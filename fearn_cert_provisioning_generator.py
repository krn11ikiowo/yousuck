#!/usr/bin/env python3
"""
ken1key Certificate + Provisioning Profile Generator
Generates matching self‑signed certificates and provisioning profiles.
"""

import argparse
import os
import subprocess
from datetime import datetime, timedelta

def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout

def generate_private_key(path):
    run(["openssl", "genrsa", "-out", path, "2048"])

def generate_certificate(key_path, cert_path, common_name):
    run([
        "openssl", "req",
        "-new", "-x509",
        "-key", key_path,
        "-out", cert_path,
        "-days", "365",
        "-subj", f"/C=US/ST=None/L=None/O=ken1key/CN={common_name}"
    ])

def generate_p12(key_path, cert_path, p12_path, name, password):
    run([
        "openssl", "pkcs12",
        "-export",
        "-in", cert_path,
        "-inkey", key_path,
        "-out", p12_path,
        "-name", name,
        "-password", f"pass:{password}"
    ])

def generate_mobileprovision(bundle_id, team_id, name):
    os.makedirs("certs", exist_ok=True)

    app_identifier = f"{team_id}.{bundle_id}"

    profile = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AppIDName</key>
    <string>{name}</string>

    <key>AppIdentifierPrefix</key>
    <array><string>{team_id}</string></array>

    <key>ApplicationIdentifierPrefix</key>
    <array><string>{team_id}</string></array>

    <key>CreationDate</key>
    <date>{datetime.now().isoformat()}</date>

    <key>Platform</key>
    <array><string>iOS</string></array>

    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>{app_identifier}</string>

        <key>get-task-allow</key>
        <true/>

        <key>keychain-access-groups</key>
        <array><string>{app_identifier}</string></array>
    </dict>

    <key>ExpirationDate</key>
    <date>{(datetime.now() + timedelta(days=365)).isoformat()}</date>

    <key>Name</key>
    <string>{name} Provisioning Profile</string>

    <key>TeamIdentifier</key>
    <array><string>{team_id}</string></array>

    <key>TimeToLive</key>
    <integer>365</integer>

    <key>UUID</key>
    <string>KEN1KEY-{team_id}-UUID</string>

    <key>Version</key>
    <integer>1</integer>
</dict>
</plist>
"""

    with open("certs/ken1key.mobileprovision", "w") as f:
        f.write(profile)

def main():
    parser = argparse.ArgumentParser(description="Generate matching cert + mobileprovision")
    parser.add_argument("--bundle-id", default="com.kenen.ikiowk")
    parser.add_argument("--team-id", default="LOCALTEAMID")
    parser.add_argument("--name", default="ken1key")
    parser.add_argument("--password", default="ken1pass")
    args = parser.parse_args()

    os.makedirs("certs", exist_ok=True)

    key_path = "certs/ken1key.key"
    cert_path = "certs/ken1key.crt"
    p12_path = "certs/ken1key.p12"

    # Certificate CN MUST match bundle ID
    common_name = args.bundle_id

    generate_private_key(key_path)
    generate_certificate(key_path, cert_path, common_name)
    generate_p12(key_path, cert_path, p12_path, args.bundle_id, args.password)
    generate_mobileprovision(args.bundle_id, args.team_id, args.name)

    print("✓ Matching cert + provisioning profile generated")
    print(f"  - Private key: {key_path}")
    print(f"  - Certificate: {cert_path}")
    print(f"  - P12: {p12_path}")
    print("  - Mobileprovision: certs/ken1key.mobileprovision")

if __name__ == "__main__":
    main()
