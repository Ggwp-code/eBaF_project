#!/usr/bin/env python3
import argparse
import csv
import http.server
import json
import os
import random
import signal
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web" / "demo"
EXPERIMENT_CSV = ROOT / "experiments" / "latest.csv"
PACKET_PROOF = ROOT / "experiments" / "packet-proof.json"
EXPERIMENTS_DIR = ROOT / "experiments"
KEY = "000102030405060708090a0b0c0d0e0f"
UDP_PORT = 7777


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, text=True, **kwargs)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def hex_preview(data, limit=96):
    return " ".join(f"{b:02x}" for b in data[:limit])


def spaced_hex(hex_text, limit=96):
    compact = "".join(str(hex_text or "").split())[:limit * 2]
    return " ".join(compact[i:i + 2] for i in range(0, len(compact), 2))


def ascii_from_hex(hex_text):
    compact = "".join(str(hex_text or "").split())
    chars = []
    for i in range(0, len(compact), 2):
        try:
            b = int(compact[i:i + 2], 16)
        except ValueError:
            break
        chars.append(chr(b) if 32 <= b <= 126 else ".")
    return "".join(chars)


def load_json_files(pattern):
    items = []
    for path in sorted(EXPERIMENTS_DIR.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        data["_file"] = str(path.relative_to(ROOT))
        items.append(data)
    return items


def make_payload(body, seq):
    iv = bytes(((seq + i) & 0xFF) for i in range(16))
    return b"EBAF" + bytes([1, 1]) + len(body).to_bytes(2, "big") + iv + body


class DemoState:
    def __init__(self, duration):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.started = time.time()
        self.duration = duration
        self.stats = {"seen": 0, "passed": 0, "crypto_ok": 0, "crypto_fail": 0, "malformed": 0}
        self.last_stats = dict(self.stats)
        self.last_stats_at = self.started
        self.pps = 0
        self.crypto_ok_rate = 0
        self.packets = []
        self.samples = []
        self.sent_by_seq = {}
        self.sender_count = 0
        self.event_count = 0
        self.server_count = 0
        self.app_lines = []
        self.status = "starting"
        self.error = ""
        self.iface = ""
        self.app_pid = None
        self.traffic_source = ""
        self.media_file = ""

    def snapshot(self):
        with self.lock:
            return {
                "status": self.status,
                "error": self.error,
                "iface": self.iface,
                "mode": "encrypt",
                "algo": "cbc-aes",
                "port": UDP_PORT,
                "uptime_sec": int(time.time() - self.started),
                "stats": dict(self.stats),
                "pps": self.pps,
                "crypto_ok_rate": self.crypto_ok_rate,
                "packets": list(self.packets),
                "samples": list(self.samples),
                "sender_count": self.sender_count,
                "capture_count": self.event_count,
                "event_count": self.event_count,
                "server_count": self.server_count,
                "app_pid": self.app_pid,
                "traffic_source": self.traffic_source,
                "media_file": self.media_file,
                "app_lines": list(self.app_lines[-12:]),
            }

    def capabilities(self):
        with self.lock:
            return {
                "iface": self.iface,
                "port": UDP_PORT,
                "mode": "tc-transparent",
                "algo": "cbc-aes",
                "endpoints": ["/api/snapshot", "/api/events", "/api/capabilities", "/api/stop"],
                "filters": [
                    {"label": "UDP/EBAF", "value": "udp.port == 7777 && ebaf.crypto"},
                    {"label": "Encrypt", "value": "action == encrypt"},
                    {"label": "Client source", "value": "ip.src == 10.66.0.1"},
                    {"label": "Peer destination", "value": "ip.dst == 10.66.0.2"},
                    {"label": "CBC AES", "value": "algo == cbc-aes"},
                    {"label": "All packets", "value": ""},
                ],
            }

    def artifacts(self):
        rows = []
        proof = {}
        if EXPERIMENT_CSV.exists():
            with EXPERIMENT_CSV.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        if PACKET_PROOF.exists():
            proof = json.loads(PACKET_PROOF.read_text(encoding="utf-8"))
        return {
            "experiments": rows,
            "packet_proof": proof,
            "physical_profiles": load_json_files("physical-profile-*.json"),
            "physical_tc_demos": load_json_files("physical-tc-demo-*.json"),
        }

    def update_stats_from_line(self, line):
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                event = {}
            if event.get("type") == "packet":
                self.add_event(event)
                return
        with self.lock:
            self.app_lines.append(stripped)
            self.app_lines = self.app_lines[-40:]
        parts = {}
        for token in stripped.split():
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            if value.isdigit():
                parts[key] = int(value)
        if "seen" not in parts:
            return
        now = time.time()
        with self.lock:
            elapsed = max(now - self.last_stats_at, 0.001)
            self.pps = int((parts.get("seen", 0) - self.last_stats.get("seen", 0)) / elapsed)
            self.crypto_ok_rate = int((parts.get("crypto_ok", 0) - self.last_stats.get("crypto_ok", 0)) / elapsed)
            self.stats.update(parts)
            self.last_stats = dict(self.stats)
            self.last_stats_at = now

    def add_packet(self, packet):
        with self.lock:
            self.packets.insert(0, packet)
            self.packets = self.packets[:80]
            if packet.get("cipher_hex"):
                self.samples.insert(0, packet)
                self.samples = self.samples[:8]

    def add_event(self, event):
        sample = event.get("sample", "")
        metadata = {}
        with self.lock:
            seq = self.event_count
            metadata = dict(self.sent_by_seq.get(seq, {}))
        packet = {
            "time": time.strftime("%H:%M:%S"),
            "seq": seq,
            "kind": "tc",
            "src": event.get("src", "10.66.0.1"),
            "dst": event.get("dst", "10.66.0.2"),
            "src_port": event.get("src_port", 0),
            "dst_port": event.get("dst_port", UDP_PORT),
            "action": event.get("action", "encrypt"),
            "algo": event.get("algo", "cbc-aes"),
            "plain_ascii": metadata.get("summary", self._fallback_summary(event)),
            "plain_hex": "",
            "cipher_hex": spaced_hex(sample),
            "cipher_ascii": ascii_from_hex(sample),
            "length": event.get("data_len", 0),
            "payload_len": event.get("payload_len", 0),
            "ts_ns": event.get("ts_ns", 0),
            "state": "xdp_event",
            "app": metadata.get("app", ""),
            "method": metadata.get("method", ""),
            "path": metadata.get("path", ""),
            "trace_id": metadata.get("trace_id", ""),
        }
        with self.lock:
            self.event_count += 1
        self.add_packet(packet)

    def _fallback_summary(self, event):
        action = event.get("action", "encrypt")
        payload_len = event.get("payload_len", 0)
        data_len = event.get("data_len", 0)
        source = self.traffic_source or "media"
        return f"{source} UDP {action} payload={payload_len}B cipher_body={data_len}B"


class Demo:
    def __init__(self, args):
        self.args = args
        self.state = DemoState(args.duration)
        self.ns = f"ebafdash{os.getpid()}"
        self.host_if = f"ebafdh{os.getpid()}"
        self.ns_if = f"ebafdp{os.getpid()}"
        self.app = None
        self.decrypt_app = None
        self.sender_proc = None
        self.receiver_proc = None
        self.host_mac = b""
        self.ns_mac = b""
        self.state.traffic_source = args.traffic
        self.state.media_file = str(args.media_file or "")

    def setup(self):
        if os.geteuid() != 0:
            raise SystemExit("run with sudo")
        run(["make"], cwd=ROOT)
        run(["ip", "netns", "add", self.ns])
        run(["ip", "link", "add", self.host_if, "type", "veth", "peer", "name", self.ns_if])
        run(["ip", "link", "set", self.ns_if, "netns", self.ns])
        run(["ip", "addr", "add", "10.66.0.1/24", "dev", self.host_if])
        run(["ip", "link", "set", self.host_if, "up"])
        run(["ip", "netns", "exec", self.ns, "ip", "addr", "add", "10.66.0.2/24", "dev", self.ns_if])
        run(["ip", "netns", "exec", self.ns, "ip", "link", "set", "lo", "up"])
        run(["ip", "netns", "exec", self.ns, "ip", "link", "set", self.ns_if, "up"])
        self.host_mac = bytes.fromhex(Path(f"/sys/class/net/{self.host_if}/address").read_text().strip().replace(":", ""))
        ns_mac_text = subprocess.check_output(["ip", "netns", "exec", self.ns, "cat",
                                               f"/sys/class/net/{self.ns_if}/address"], text=True).strip()
        self.ns_mac = bytes.fromhex(ns_mac_text.replace(":", ""))
        self.state.iface = self.host_if

    def start_crypto(self):
        bin_path = str(ROOT / "build" / "ebaf-crypto")
        cmd = [bin_path, "--iface", self.host_if, "--mode", "encrypt",
               "--hook", "tc", "--transparent", "--key", KEY, "--port", str(UDP_PORT),
               "--stats-interval", "1", "--jsonl"]
        dec_cmd = ["ip", "netns", "exec", self.ns, bin_path, "--iface", self.ns_if,
                   "--mode", "decrypt", "--hook", "tc", "--transparent", "--key", KEY,
                   "--port", str(UDP_PORT), "--stats-interval", "1", "--jsonl"]
        self.app = subprocess.Popen(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
        self.decrypt_app = subprocess.Popen(dec_cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT)
        self.state.app_pid = self.app.pid
        threading.Thread(target=self._read_app, args=(self.app, "encrypt"), daemon=True).start()
        threading.Thread(target=self._read_app, args=(self.decrypt_app, "decrypt"), daemon=True).start()
        time.sleep(2)
        if self.app.poll() is not None:
            raise RuntimeError("encrypt ebaf-crypto exited before demo started")
        if self.decrypt_app.poll() is not None:
            raise RuntimeError("decrypt ebaf-crypto exited before demo started")

    def _read_app(self, proc, label):
        assert proc and proc.stdout
        for line in proc.stdout:
            if line.lstrip().startswith("{"):
                self.state.update_stats_from_line(line)
            else:
                self.state.update_stats_from_line(f"{label}: {line}")

    def start_threads(self):
        self.state.status = "running"
        self._start_receiver()
        if self.args.traffic == "synthetic":
            threading.Thread(target=self._send_loop, daemon=True).start()
        else:
            self._start_ffmpeg()
        if self.args.duration:
            threading.Thread(target=self._duration_loop, daemon=True).start()

    def _duration_loop(self):
        time.sleep(self.args.duration)
        self.state.stop.set()

    def _start_receiver(self):
        receiver = (
            "import socket,sys;"
            "port=int(sys.argv[1]);"
            "sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            "sock.bind(('10.66.0.2',port));"
            "sock.settimeout(1.0);"
            "count=0;"
            "\nwhile True:\n"
            "    try:\n"
            "        data,_=sock.recvfrom(65535)\n"
            "    except socket.timeout:\n"
            "        continue\n"
            "    count += 1\n"
            "    print(f'received={count} bytes={len(data)}', flush=True)\n"
        )
        self.receiver_proc = subprocess.Popen(
            ["ip", "netns", "exec", self.ns, "python3", "-u", "-c", receiver, str(UDP_PORT)],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threading.Thread(target=self._read_receiver, daemon=True).start()
        time.sleep(0.2)
        if self.receiver_proc.poll() is not None:
            raise RuntimeError("UDP media receiver exited before demo started")

    def _read_receiver(self):
        assert self.receiver_proc and self.receiver_proc.stdout
        for line in self.receiver_proc.stdout:
            with self.state.lock:
                self.state.app_lines.append(f"receiver: {line.strip()}")
                self.state.app_lines = self.state.app_lines[-40:]
                if line.startswith("received="):
                    self.state.server_count += 1

    def _start_ffmpeg(self):
        if not shutil.which("ffmpeg"):
            raise RuntimeError("ffmpeg missing; install ffmpeg or use --traffic synthetic")
        media = Path(self.args.media_file).expanduser() if self.args.media_file else None
        if media:
            if not media.exists():
                raise RuntimeError(f"media file not found: {media}")
            input_args = ["-stream_loop", "-1", "-re", "-i", str(media)]
            self.state.traffic_source = "ffmpeg-file"
            self.state.media_file = str(media)
        else:
            input_args = ["-re", "-f", "lavfi", "-i",
                          f"testsrc2=size={self.args.ffmpeg_size}:rate={self.args.ffmpeg_fps}"]
            self.state.traffic_source = "ffmpeg-testsrc"
        cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "warning", *input_args,
            "-an", "-c:v", "mpeg2video", "-b:v", self.args.ffmpeg_bitrate,
            "-f", "mpegts", f"udp://10.66.0.2:{UDP_PORT}?pkt_size=1316",
        ]
        self.sender_proc = subprocess.Popen(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT)
        threading.Thread(target=self._read_sender, daemon=True).start()

    def _read_sender(self):
        assert self.sender_proc and self.sender_proc.stdout
        for line in self.sender_proc.stdout:
            with self.state.lock:
                self.state.app_lines.append(f"ffmpeg: {line.strip()}")
                self.state.app_lines = self.state.app_lines[-40:]

    def _send_loop(self):
        seq = 0
        sender = (
            "import socket,sys,time;"
            "dst=sys.argv[1];port=int(sys.argv[2]);payloads=sys.argv[3:];"
            "base=int(sys.argv[3]);payloads=sys.argv[4:];"
            "socks=[];"
            "[socks.append(socket.socket(socket.AF_INET,socket.SOCK_DGRAM)) for _ in range(4)];"
            "[s.setsockopt(socket.SOL_SOCKET, 11, 1) for s in socks];"
            "[(socks[(base+i)%len(socks)].sendto(bytes.fromhex(p),(dst,port)), time.sleep(0.018 + ((base+i)%7)*0.006)) for i,p in enumerate(payloads)];"
            "[s.close() for s in socks]"
        )
        messages = [
            ("auth", "POST", "/login", "user=miku role=admin token=demo"),
            ("metrics", "GET", "/metrics", "cpu=07 mem=42 xdp=active"),
            ("chat", "MSG", "/room/main", "client says hello from live cipher demo"),
            ("billing", "PAY", "/orders/1042", "amount=19.99 currency=USD"),
            ("health", "PING", "/health", "service=edge-gateway status=green"),
            ("search", "GET", "/api/search", "q=ebpf+xdp+crypto"),
            ("video", "RTP", "/stream/camera-a", "frame=delta quality=720p"),
            ("dns", "QUERY", "/resolve", "name=demo.internal type=A"),
        ]
        random.seed(os.getpid())
        while not self.state.stop.is_set():
            payloads = []
            for _ in range(16):
                app, method, path, detail = messages[seq % len(messages)]
                trace_id = f"{seq:06x}{random.randrange(0, 0xffff):04x}"
                extra = " ".join(f"k{i}={random.randrange(10, 9999)}" for i in range(seq % 5))
                text = f"{method} {path} app={app} trace={trace_id} {detail} {extra} seq={seq:06d}".strip()
                size = [31, 47, 63, 79, 111, 143, 191, 239][seq % 8]
                body = text.encode("ascii")
                if len(body) < size:
                    body = body + b" " + bytes(
                        65 + ((seq + i) % 26) for i in range(size - len(body) - 1)
                    )
                body = body[:size]
                pad_len = (-len(body)) % 16
                if pad_len == 0:
                    pad_len = 16
                padded_len = len(body) + pad_len
                payloads.append(body.hex())
                with self.state.lock:
                    self.state.sender_count += 1
                    self.state.sent_by_seq[seq] = {
                        "app": app,
                        "method": method,
                        "path": path,
                        "trace_id": trace_id,
                        "summary": f"{method} {path} app={app} body={len(body)}B padded={padded_len}B trace={trace_id}",
                    }
                    if len(self.state.sent_by_seq) > 512:
                        for old_seq in list(self.state.sent_by_seq)[:128]:
                            self.state.sent_by_seq.pop(old_seq, None)
                seq += 1
            subprocess.run(["python3", "-c", sender,
                            "10.66.0.2", str(UDP_PORT), str(seq - len(payloads)), *payloads],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _server_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("10.66.0.1", UDP_PORT))
        sock.settimeout(0.5)
        while not self.state.stop.is_set():
            try:
                payload, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            parsed = self._parse_payload(payload)
            if parsed:
                with self.state.lock:
                    self.state.server_count += 1
        sock.close()

    def _parse_payload(self, payload):
        if len(payload) < 24 or payload[:4] != b"EBAF":
            return None
        body_len = struct.unpack("!H", payload[6:8])[0]
        body = payload[24:24 + body_len]
        return {"cipher_hex": hex_preview(body), "length": len(body)}

    def cleanup(self):
        self.state.stop.set()
        self.state.status = "stopping"
        for proc in (self.sender_proc, self.receiver_proc, self.app, self.decrypt_app):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        subprocess.run(["ip", "netns", "del", self.ns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "del", self.host_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.state.status = "stopped"


def make_handler(demo):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def translate_path(self, path):
            clean_path = urlparse(path).path
            if clean_path == "/":
                return str(WEB_DIR / "index.html")
            return str(WEB_DIR / clean_path.lstrip("/"))

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def send_json(self, obj):
            data = json.dumps(obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/api/snapshot" or self.path == "/api/events":
                self.send_json(demo.state.snapshot())
                return
            if self.path == "/api/capabilities":
                self.send_json(demo.state.capabilities())
                return
            if self.path == "/api/artifacts":
                self.send_json(demo.state.artifacts())
                return
            return super().do_GET()

        def do_POST(self):
            if self.path == "/api/stop":
                demo.state.stop.set()
                self.send_json({"ok": True})
                return
            self.send_error(404)

        def log_message(self, fmt, *args):
            return

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Live eBPF TC transparent UDP media dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--duration", type=int, default=0)
    parser.add_argument("--traffic", choices=("ffmpeg", "synthetic"), default="ffmpeg")
    parser.add_argument("--media-file", default="")
    parser.add_argument("--ffmpeg-size", default="640x360")
    parser.add_argument("--ffmpeg-fps", type=int, default=30)
    parser.add_argument("--ffmpeg-bitrate", default="1M")
    args = parser.parse_args()

    demo = Demo(args)

    def stop_handler(_sig, _frame):
        demo.state.stop.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    try:
        demo.setup()
        demo.start_crypto()
        demo.start_threads()
        server = http.server.ThreadingHTTPServer((args.host, args.port), make_handler(demo))
        server.timeout = 0.5
        print(f"dashboard http://{args.host}:{args.port}", flush=True)
        while not demo.state.stop.is_set():
            server.handle_request()
    finally:
        demo.cleanup()


if __name__ == "__main__":
    main()
