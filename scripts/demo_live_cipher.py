#!/usr/bin/env python3
import argparse
import http.server
import json
import os
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web" / "demo"
KEY = "000102030405060708090a0b0c0d0e0f"
UDP_PORT = 7777
ETH_P_IP = 0x0800
IPPROTO_UDP = 17


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, text=True, **kwargs)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ascii_preview(data):
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def hex_preview(data, limit=96):
    return " ".join(f"{b:02x}" for b in data[:limit])


def make_frame(src_mac, dst_mac, body, seq):
    iv = bytes(((seq + i) & 0xFF) for i in range(16))
    payload = b"EBAF" + bytes([1, 1]) + len(body).to_bytes(2, "big") + iv + body
    src_ip = socket.inet_aton("10.66.0.2")
    dst_ip = socket.inet_aton("10.66.0.1")
    udp = struct.pack("!HHHH", 4242, UDP_PORT, 8 + len(payload), 0)
    total_len = 20 + len(udp) + len(payload)
    ip0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, seq & 0xFFFF, 0, 64,
                      IPPROTO_UDP, 0, src_ip, dst_ip)
    ip = ip0[:10] + struct.pack("!H", checksum(ip0)) + ip0[12:]
    return dst_mac + src_mac + struct.pack("!H", ETH_P_IP) + ip + udp + payload


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
        self.sender_count = 0
        self.capture_count = 0
        self.app_lines = []
        self.status = "starting"
        self.error = ""
        self.iface = ""
        self.app_pid = None

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
                "capture_count": self.capture_count,
                "app_pid": self.app_pid,
                "app_lines": list(self.app_lines[-12:]),
            }

    def update_stats_from_line(self, line):
        with self.lock:
            self.app_lines.append(line.strip())
            self.app_lines = self.app_lines[-40:]
        parts = {}
        for token in line.strip().split():
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


class Demo:
    def __init__(self, args):
        self.args = args
        self.state = DemoState(args.duration)
        self.ns = f"ebafdash{os.getpid()}"
        self.host_if = f"ebafdh{os.getpid()}"
        self.ns_if = f"ebafdp{os.getpid()}"
        self.app = None
        self.host_mac = b""
        self.ns_mac = b""

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
        cmd = [str(ROOT / "build" / "ebaf-crypto"), "--iface", self.host_if, "--mode", "encrypt",
               "--key", KEY, "--port", str(UDP_PORT), "--stats-interval", "1"]
        self.app = subprocess.Popen(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
        self.state.app_pid = self.app.pid
        threading.Thread(target=self._read_app, daemon=True).start()
        time.sleep(2)
        if self.app.poll() is not None:
            raise RuntimeError("ebaf-crypto exited before demo started")

    def _read_app(self):
        assert self.app and self.app.stdout
        for line in self.app.stdout:
            self.state.update_stats_from_line(line)

    def start_threads(self):
        self.state.status = "running"
        threading.Thread(target=self._capture_loop, daemon=True).start()
        threading.Thread(target=self._send_loop, daemon=True).start()
        if self.args.duration:
            threading.Thread(target=self._duration_loop, daemon=True).start()

    def _duration_loop(self):
        time.sleep(self.args.duration)
        self.state.stop.set()

    def _send_loop(self):
        seq = 0
        sender = (
            "import socket,sys,time;"
            "iface=sys.argv[1];frames=sys.argv[2:];"
            "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((iface,0));"
            "[(s.send(bytes.fromhex(f)), time.sleep(0.05)) for f in frames];s.close()"
        )
        while not self.state.stop.is_set():
            frames = []
            for _ in range(16):
                text = f"server->client live cipher packet {seq:06d} 0123456789ABCDEF"
                body = text.encode("ascii")[:48].ljust(48, b" ")
                frame = make_frame(self.ns_mac, self.host_mac, body, seq)
                frames.append(frame.hex())
                self.state.add_packet({
                    "time": time.strftime("%H:%M:%S"),
                    "seq": seq,
                    "plain_ascii": ascii_preview(body),
                    "plain_hex": hex_preview(body),
                    "cipher_hex": "",
                    "length": len(body),
                    "state": "sent",
                })
                with self.state.lock:
                    self.state.sender_count += 1
                seq += 1
            subprocess.run(["ip", "netns", "exec", self.ns, "python3", "-c", sender, self.ns_if, *frames],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _capture_loop(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        sock.bind((self.host_if, 0))
        sock.settimeout(0.5)
        while not self.state.stop.is_set():
            try:
                packet = sock.recv(65535)
            except socket.timeout:
                continue
            parsed = self._parse_packet(packet)
            if parsed:
                with self.state.lock:
                    self.state.capture_count += 1
                self.state.add_packet(parsed)
        sock.close()

    def _parse_packet(self, packet):
        if len(packet) < 14 + 20 + 8 + 24 or packet[12:14] != b"\x08\x00":
            return None
        if packet[23] != IPPROTO_UDP:
            return None
        ihl = (packet[14] & 0x0F) * 4
        udp_off = 14 + ihl
        if len(packet) < udp_off + 8:
            return None
        if struct.unpack("!H", packet[udp_off + 2:udp_off + 4])[0] != UDP_PORT:
            return None
        payload = packet[udp_off + 8:]
        if len(payload) < 24 or payload[:4] != b"EBAF":
            return None
        body_len = struct.unpack("!H", payload[6:8])[0]
        body = payload[24:24 + body_len]
        return {
            "time": time.strftime("%H:%M:%S"),
            "seq": None,
            "plain_ascii": "",
            "plain_hex": "",
            "cipher_hex": hex_preview(body),
            "length": len(body),
            "state": "captured",
        }

    def cleanup(self):
        self.state.stop.set()
        self.state.status = "stopping"
        if self.app and self.app.poll() is None:
            self.app.terminate()
            try:
                self.app.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.app.kill()
        subprocess.run(["ip", "netns", "del", self.ns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "del", self.host_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.state.status = "stopped"


def make_handler(demo):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def translate_path(self, path):
            if path == "/":
                return str(WEB_DIR / "index.html")
            return str(WEB_DIR / path.lstrip("/"))

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
    parser = argparse.ArgumentParser(description="Live eBPF/XDP cipher dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--duration", type=int, default=0)
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
