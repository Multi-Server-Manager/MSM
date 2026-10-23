#!/usr/bin/env python3
"""Raw frame probe for the MSM pairing listener.

Used by scripts/e2e.sh to prove the node refuses malformed frames. It speaks the
protocol by hand so it can violate it, which the real client never does.

    probe.py <oversize|empty|unknown> <host> <port>

Prints one of:
    type <t>            a well-formed reply
    error <code>        an error reply
    closed              the peer closed without replying
    unparseable         a reply that is not JSON
"""

import json
import socket
import ssl
import struct
import sys


def read_frame(sock):
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    length = struct.unpack(">I", header)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def describe(payload):
    if payload is None:
        return "closed"
    try:
        message = json.loads(payload)
    except Exception:
        return "unparseable"
    if not isinstance(message, dict):
        return "unparseable"
    if message.get("t") == "error":
        return "error " + str(message.get("code"))
    return "type " + str(message.get("t"))


def main():
    if len(sys.argv) != 4:
        print("usage: probe.py <mode> <host> <port>")
        return 2

    mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw) as tls:
            if mode == "oversize":
                # Announce a payload beyond the cap. A conforming peer rejects
                # this from the header alone and never allocates the buffer.
                tls.sendall(struct.pack(">I", 2 * 1024 * 1024))
            elif mode == "empty":
                tls.sendall(struct.pack(">I", 0))
            elif mode == "unknown":
                payload = json.dumps({"t": "pair.renegotiate", "v": 1}).encode()
                tls.sendall(struct.pack(">I", len(payload)) + payload)
            else:
                print("bad-mode")
                return 2

            print(describe(read_frame(tls)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
