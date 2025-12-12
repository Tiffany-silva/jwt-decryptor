#!/usr/bin/env python3
import argparse
import base64
import json
from typing import Optional
from jwskate import JweCompact, Jwk


def load_private_key(path: str, password: Optional[str] = None) -> Jwk:
    """Load an RSA private key from PEM into a Jwk."""
    with open(path, "rb") as f:
        pem_data = f.read()
    return Jwk.from_pem(pem_data, password=password.encode() if password else None)


def print_header(token: str) -> None:
    """Decode and print the JWE header."""
    header_b64 = token.split(".")[0]
    padding = "=" * (-len(header_b64) % 4)
    raw = base64.urlsafe_b64decode(header_b64 + padding).decode("utf-8")
    try:
        hdr = json.loads(raw)
    except Exception:
        hdr = raw
    print(f"[info] JWE header: {hdr}")


def decrypt_jwe(compact_jwe: str, key: Jwk) -> bytes:
    """Decrypt a compact JWE with the given key."""
    jwe = JweCompact(compact_jwe)
    print(f"[info] alg={jwe.alg}, enc={jwe.enc}")
    return jwe.decrypt(key)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decrypt a JWE token using an RSA private key (jwskate)."
    )
    parser.add_argument("--token", required=True, help="Compact JWE string")
    parser.add_argument("--key-file", required=True, help="Private key PEM path")
    parser.add_argument("--key-pass", default=None, help="Private key password")
    parser.add_argument("--show-header", action="store_true", help="Show JWE header")
    parser.add_argument("--decode", action="store_true", help="Decode UTF8 payload")

    args = parser.parse_args()

    token = args.token.strip()

    if args.show_header:
        print_header(token)

    key = load_private_key(args.key_file, args.key_pass)

    try:
        plaintext = decrypt_jwe(token, key)
    except Exception as e:
        raise SystemExit(f"Decryption failed: {e}")

    if args.decode:
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print("[warn] Non UTF8 payload, hex output:")
            print(plaintext.hex())
    else:
        print(plaintext.hex())


if __name__ == "__main__":
    main()