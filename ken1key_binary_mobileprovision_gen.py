#!/usr/bin/env python3
import base64
import hashlib
import argparse
import subprocess
import tempfile
import os
from datetime import datetime, timedelta

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout

def plist_date(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--team-id", required=True)
    p.add_argument("--bundle-id", required=True)
    p.add_argument("--app-name", default="ken1key")
    p.add_argument("--crt", required=True)
    p.add_argument("--p12", required=True)
    p.add_argument("--p12-password", required=True)
    p.add_argument("--out", default="ken1key.mobileprovision")
    args = p.parse_args()

    # Convert cert to DER
    der_path = args.crt + ".der"
    run(["openssl", "x509", "-in", args.crt, "-outform", "der", "-out", der_path])
    der = open(der_path, "rb").read()
    der_b64 = base64.b64encode(der).decode()
    sha1 = hashlib.sha1(der).hexdigest().upper()

    # Load P12
    p12 = open(args.p12, "rb").read()
    p12_b64 = base64.b64encode(p12).decode()

    now = plist_date(datetime.utcnow())
    exp = plist_date(datetime.utcnow() + timedelta(days=365))

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

    <key>CreationDate</key>
    <date>{now}</date>

    <key>ExpirationDate</key>
    <date>{exp}</date>

    <key>Name</key>
    <string>{args.app_name} Provisioning Profile</string>

    <key>UUID</key>
    <string>{args.app_name.upper()}-{team}-UUID</string>

    <key>Version</key>
    <integer>1</integer>

</dict>
</plist>
"""

    # Write plist to temp file
    tmp_plist = tempfile.NamedTemporaryFile(delete=False)
    tmp_plist.write(plist.encode())
    tmp_plist.close()

    # Wrap plist in CMS (binary mobileprovision)
    run([
        "openssl", "smime",
        "-sign",
        "-signer", args.crt,
        "-inkey", args.crt.replace(".crt", ".key"),
        "-in", tmp_plist.name,
        "-out", args.out,
        "-outform", "der",
        "-nodetach"
    ])

    print(f"✓ Binary CMS mobileprovision written to {args.out}")

if __name__ == "__main__":
    main()
