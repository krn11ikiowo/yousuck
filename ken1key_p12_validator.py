#!/usr/bin/env python3
import argparse
import subprocess
import tempfile
import os
import sys

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--p12", required=True, help="Path to P12 file")
    p.add_argument("--password", required=True, help="P12 password")
    args = p.parse_args()

    p12_path = args.p12
    pwd = args.password

    print(f"[info] Validating P12: {p12_path}")

    # 1) Check that P12 opens and contains something
    try:
        out = run([
            "openssl", "pkcs12",
            "-info",
            "-in", p12_path,
            "-nokeys",
            "-password", f"pass:{pwd}",
        ])
        print("[ok] P12 password is correct and certificate is present")
    except RuntimeError as e:
        print(f"[error] Failed to open P12 or wrong password: {e}")
        sys.exit(1)

    # 2) Check that P12 contains a private key
    try:
        out = run([
            "openssl", "pkcs12",
            "-info",
            "-in", p12_path,
            "-nodes",
            "-password", f"pass:{pwd}",
        ])
        if "PRIVATE KEY" not in out:
            print("[error] No private key found in P12")
            sys.exit(1)
        print("[ok] Private key found in P12")
    except RuntimeError as e:
        print(f"[error] Failed to read private key from P12: {e}")
        sys.exit(1)

    # 3) Check that macOS sees a codesigning identity
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    keychain = tmp.name + ".keychain-db"

    try:
        run(["security", "create-keychain", "-p", "testpass", keychain])
        run(["security", "unlock-keychain", "-p", "testpass", keychain])
        run([
            "security", "import", p12_path,
            "-k", keychain,
            "-P", pwd,
            "-T", "/usr/bin/codesign",
            "-A",
        ])
        run(["security", "list-keychains", "-s", keychain])
        identities = run(["security", "find-identity", "-v", "-p", "codesigning", keychain])

        if "valid identities found" in identities or ")" in identities:
            print("[ok] macOS sees at least one codesigning identity in this P12")
            print(identities)
            print("✓ P12 is usable for signing")
            sys.exit(0)
        else:
            print("[error] No codesigning identities found in this P12")
            print(identities)
            sys.exit(1)
    except RuntimeError as e:
        print(f"[error] Keychain/identity check failed: {e}")
        sys.exit(1)
    finally:
        try:
            run(["security", "delete-keychain", keychain])
        except Exception:
            pass

if __name__ == "__main__":
    main()
