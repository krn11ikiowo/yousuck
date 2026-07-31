#!/usr/bin/env python3
import base64
import hashlib
import argparse
import subprocess
import os
from datetime import datetime, timedelta

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout

def ensure_der(cert_path):
    if cert_path.lower().endswith(".der"):
        return cert_path
    der_path = cert_path + ".der"
    run(["openssl", "x509", "-in", cert_path, "-outform", "der", "-out", der_path])
    return der_path

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--team-id", required=True)
    p.add_argument("--bundle-id", required=True)
    p.add_argument("--app-name", default="ken1key")
    p.add_argument("--crt", required=True)
    p.add_argument("--p12", required=True)
    p.add_argument("--out", default="ken1key.mobileprovision")
    args = p.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    der_path = ensure_der(args.crt)
    with open(der_path, "rb") as f:
        der = f.read()
    der_b64 = base64.b64encode(der).decode("ascii")
    sha1 = hashlib.sha1(der).hexdigest().upper()

    with open(args.p12, "rb") as f:
        p12 = f.read()
    p12_b64 = base64.b64encode(p12).decode("ascii")

    now = datetime.utcnow()
    exp = now + timedelta(days=365)
    team = args.team_id
    app_id = f"{team}.{args.bundle_id}"

    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>

    <key>AppIDName</key>
    <string>{args.app_name}</string>

    <key>ApplicationIdentifierPrefix</key>
    <array>
        <string>{team}</string>
    </array>

    <key>TeamIdentifier</key>
    <array>
        <string>{team}</string>
    </array>

    <key>DeveloperCertificates</key>
    <array>
        <data>{der_b64}</data>
    </array>

    <key>DeveloperCertificateHashes</key>
    <array>
        <string>{sha1}</string>
    </array>

    <key>EmbeddedP12</key>
    <data>{p12_b64}</data>

    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>{app_id}</string>

        <key>get-task-allow</key>
        <true/>

        <key>keychain-access-groups</key>
        <array>
            <string>{app_id}</string>
        </array>
    </dict>

    <key>ExpirationDate</key>
    <date>{exp.isoformat()}Z</date>

    <key>Name</key>
    <string>{args.app_name} Provisioning Profile</string>

    <key>UUID</key>
    <string>{args.app_name.upper()}-{team}-UUID</string>

    <key>Version</key>
    <integer>1</integer>

</dict>
</plist>
"""

    with open(args.out, "w") as f:
        f.write(plist)

    print(f"✓ Final mobileprovision written to {args.out}")

if __name__ == "__main__":
    main()
