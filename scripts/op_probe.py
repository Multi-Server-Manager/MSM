#!/usr/bin/env python3
"""Send one raw frame to a node's operational channel and print its reply.

The console CLI can only send well-formed commands, so this probe exists for the
refusals that sit *before* a command is dispatched: an unknown message type and a
request from an identity the node never paired.

The console identity is reused as-is: the store keeps the Ed25519 key as PKCS#8
DER, which `openssl` turns back into a PEM key and a self-signed certificate with
the same SPKI the node pinned. `--fresh` instead generates a new identity, which
is exactly what an unpaired console looks like to the node.

Usage:
    op_probe.py --addr 127.0.0.1:7333 --identity /root/.msm/identity.json \
        --json '{"t":"pkg.nuke","v":1,"id":"probe-1"}'
    op_probe.py --addr 127.0.0.1:7333 --fresh \
        --json '{"t":"metrics.sample","v":1,"id":"probe-2"}'
"""

import argparse
import base64
import json
import os
import ssl
import struct
import subprocess
import sys
import tempfile

MAX_FRAME = 1 << 20


def build_identity(identity_path: str, fresh: bool, workdir: str) -> tuple[str, str]:
    """Return (cert_path, key_path) for the identity to present."""
    key_pem = os.path.join(workdir, "key.pem")
    cert_pem = os.path.join(workdir, "cert.pem")

    if fresh:
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", key_pem],
            check=True,
            capture_output=True,
        )
    else:
        with open(identity_path, "r", encoding="utf-8") as handle:
            stored = json.load(handle)
        key_der = base64.b64decode(stored["key"])
        der_path = os.path.join(workdir, "key.der")
        with open(der_path, "wb") as handle:
            handle.write(key_der)
        subprocess.run(
            ["openssl", "pkey", "-inform", "DER", "-in", der_path, "-out", key_pem],
            check=True,
            capture_output=True,
        )

    subprocess.run(
        [
            "openssl", "req", "-x509", "-new", "-key", key_pem,
            "-subj", "/CN=msm-probe", "-days", "1", "-out", cert_pem,
        ],
        check=True,
        capture_output=True,
    )
    return cert_pem, key_pem


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--addr", required=True, help="host:port of the node")
    parser.add_argument("--json", required=True, dest="payload", help="frame payload")
    parser.add_argument("--identity", help="console identity.json to reuse")
    parser.add_argument("--fresh", action="store_true", help="generate an unpaired identity")
    args = parser.parse_args()

    if args.fresh == bool(args.identity):
        parser.error("give exactly one of --identity or --fresh")

    host, _, port = args.addr.rpartition(":")
    payload = args.payload.encode("utf-8")

    with tempfile.TemporaryDirectory() as workdir:
        cert_pem, key_pem = build_identity(args.identity or "", args.fresh, workdir)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert_pem, key_pem)

        import socket

        with socket.create_connection((host, int(port)), timeout=10) as raw:
            with context.wrap_socket(raw) as tls:
                tls.sendall(struct.pack(">I", len(payload)) + payload)

                header = recv_exact(tls, 4)
                if header is None:
                    print("no reply (connection closed)")
                    return 1
                (length,) = struct.unpack(">I", header)
                if length == 0 or length > MAX_FRAME:
                    print(f"bad reply length {length}")
                    return 1
                body = recv_exact(tls, length)
                if body is None:
                    print("truncated reply")
                    return 1

    print(body.decode("utf-8", "replace"))
    return 0


def recv_exact(sock, count: int):
    chunks = []
    while count:
        chunk = sock.recv(count)
        if not chunk:
            return None
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


if __name__ == "__main__":
    sys.exit(main())
