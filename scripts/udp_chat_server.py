#!/usr/bin/env python3
"""Receive EBAF-shim UDP chat packets."""

import argparse
import socket
import struct
import time


EBAF_CRYPTO_MAGIC = 0x45424146
EBAF_CRYPTO_VERSION = 1
EBAF_ACTION_ENCRYPT = 1
EBAF_CRYPTO_BLOCK_BYTES = 16
HEADER = struct.Struct("!IBBH16s")


def unpad_body(body: bytes) -> bytes:
    pad_len = body[-1]
    if pad_len < 1 or pad_len > EBAF_CRYPTO_BLOCK_BYTES:
        raise ValueError(f"bad padding length: {pad_len}")
    if len(body) < pad_len or body[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad padding bytes")
    return body[:-pad_len]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Receive EBAF-shim UDP chat packets.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7777)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=5)
    return parser.parse_args()


def malformed(addr: tuple[str, int], reason: str, size: int) -> None:
    host, port = addr
    print(f"malformed {host}:{port} bytes={size} reason={reason}")


def parse_packet(data: bytes) -> tuple[int, bytes]:
    if len(data) < HEADER.size:
        raise ValueError(f"short packet: need >= {HEADER.size}")

    magic, version, action, payload_len, iv = HEADER.unpack_from(data)
    if magic != EBAF_CRYPTO_MAGIC:
        raise ValueError(f"bad magic: 0x{magic:08x}")
    if version != EBAF_CRYPTO_VERSION:
        raise ValueError(f"bad version: {version}")
    if action != EBAF_ACTION_ENCRYPT:
        raise ValueError(f"bad action: {action}")

    body = data[HEADER.size:]
    if payload_len != len(body):
        raise ValueError(f"bad payload_len: {payload_len} != {len(body)}")
    if payload_len == 0:
        raise ValueError("empty payload")
    if payload_len % EBAF_CRYPTO_BLOCK_BYTES != 0:
        raise ValueError(f"bad alignment: {payload_len}")

    # Touch IV after unpack, making header layout use explicit.
    if len(iv) != 16:
        raise ValueError("bad iv length")
    return payload_len, body


def main() -> int:
    args = parse_args()
    if args.count < 1:
        raise SystemExit("--count must be >= 1")
    if args.timeout < 0:
        raise SystemExit("--timeout must be >= 0")

    valid = 0
    deadline = time.monotonic() + args.timeout
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.host, args.port))
        while valid < args.count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break

            try:
                _, body = parse_packet(data)
            except ValueError as exc:
                malformed(addr, str(exc), len(data))
                continue

            try:
                body = unpad_body(body)
            except ValueError as exc:
                malformed(addr, str(exc), len(data))
                continue

            text = body.decode("utf-8", errors="replace")
            print(text)
            valid += 1
    if valid != args.count:
        print(f"timeout valid={valid} expected={args.count}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
