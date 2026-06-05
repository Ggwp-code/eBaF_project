#!/usr/bin/env python3
"""Send EBAF-shim UDP chat packets."""

import argparse
import os
import socket
import struct
import time


EBAF_CRYPTO_MAGIC = 0x45424146
EBAF_CRYPTO_VERSION = 1
EBAF_ACTION_ENCRYPT = 1
EBAF_CRYPTO_IV_BYTES = 16
EBAF_CRYPTO_BLOCK_BYTES = 16
UDP_MAX_PAYLOAD = 65507
HEADER = struct.Struct("!IBBH16s")


def pad_body(body: bytes) -> bytes:
    pad_len = (-len(body)) % EBAF_CRYPTO_BLOCK_BYTES
    if pad_len == 0:
        pad_len = EBAF_CRYPTO_BLOCK_BYTES
    return body + bytes([pad_len]) * pad_len


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send EBAF-shim UDP chat packets.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=7777)
    parser.add_argument("--message", required=True)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--interval", type=float, default=0.1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.count < 1:
        raise SystemExit("--count must be >= 1")
    if args.interval < 0:
        raise SystemExit("--interval must be >= 0")

    body = pad_body(args.message.encode("utf-8"))
    if len(body) > 0xFFFF or HEADER.size + len(body) > UDP_MAX_PAYLOAD:
        raise SystemExit("padded message too large for UDP EBAF packet")

    destination = (args.host, args.port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for sequence in range(1, args.count + 1):
            iv = os.urandom(EBAF_CRYPTO_IV_BYTES)
            header = HEADER.pack(
                EBAF_CRYPTO_MAGIC,
                EBAF_CRYPTO_VERSION,
                EBAF_ACTION_ENCRYPT,
                len(body),
                iv,
            )
            packet = header + body
            sent = sock.sendto(packet, destination)
            print(f"sent {args.host}:{args.port} seq={sequence} bytes={sent}")
            if sequence != args.count and args.interval:
                time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
