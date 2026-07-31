#!/usr/bin/env python3
"""
ken1key IPA Signer

Feature-rich IPA signer:
- Loads P12 + mobileprovision (plain plist OR CMS-wrapped)
- Extracts entitlements
- Resigns IPA with new bundle ID
- Supports debug mode
"""

import argparse
import os
import shutil
import subprocess
import tempfile
import zipfile
import plistlib
import sys

def run(cmd, verbose=False):
    if verbose:
        print("[run]", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    return result.stdout

def unzip_ipa(ipa_path, work_dir, verbose=False):
    if verbose:
        print(f"[info] Unzipping IPA: {ipa_path}")
    with zipfile.ZipFile(ipa_path, "r") as z:
        z.extractall(work_dir)

def zip_ipa(payload_dir, out_path, verbose=False):
    if verbose:
        print(f"[info] Creating signed IPA: {out_path}")
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        root = os.path.dirname(payload_dir)
        for base, _, files in os.walk(root):
            for f in files:
                full = os.path.join(base, f)
                rel = os.path.relpath(full, root)
                z.write(full, rel)

def find_app_bundle(payload_dir):
    payload = os.path.join(payload_dir, "Payload")
    for item in os.listdir(payload):
        if item.endswith(".app"):
            return os.path.join(payload, item)
    raise RuntimeError("No .app bundle found in Payload")

# ⭐ FIXED: Supports both plain plist and CMS-wrapped profiles
def load_mobileprovision(mobileprovision_path, verbose=False):
    if verbose:
        print(f"[info] Loading mobileprovision: {mobileprovision_path}")

    with open(mobileprovision_path, "rb") as f:
        data = f.read()

    # Try plain plist first (your generated profiles)
    try:
        return plistlib.loads(data)
    except Exception:
        if verbose:
            print("[info] Plain plist parse failed, trying CMS decode")

    # Fallback: CMS-wrapped Apple provisioning profile
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(data)
    tmp.close()

    out = run(["security", "cms", "-D", "-i", tmp.name], verbose=verbose)
    os.unlink(tmp.name)

    return plistlib.loads(out.encode("utf-8"))

def extract_entitlements_from_profile(profile_plist, verbose=False):
    ents = profile_plist.get("Entitlements", {})
    if verbose:
        print("[info] Entitlements from profile:", ents)
    return ents

def write_entitlements_plist(entitlements, path, verbose=False):
    if verbose:
        print(f"[info] Writing entitlements to {path}")
    with open(path, "wb") as f:
        plistlib.dump(entitlements, f)

def import_p12(p12_path, password, keychain, verbose=False):
    if verbose:
        print(f"[info] Importing P12: {p12_path} into keychain {keychain}")
    run([
        "security", "import", p12_path,
        "-k", keychain,
        "-P", password,
        "-T", "/usr/bin/codesign",
        "-A",  # allow all apps to access, makes identity visible
    ], verbose=verbose)


def get_identity_from_keychain(keychain, verbose=False):
    out = run(["security", "find-identity", "-v", "-p", "codesigning", keychain], verbose=verbose)
    for line in out.splitlines():
        if '"' in line:
            return line.split('"')[1]
    raise RuntimeError("No signing identity found in keychain")

def patch_info_plist(app_path, new_bundle_id, verbose=False):
    info_path = os.path.join(app_path, "Info.plist")
    if verbose:
        print(f"[info] Patching Info.plist at {info_path}")
    with open(info_path, "rb") as f:
        info = plistlib.load(f)
    info["CFBundleIdentifier"] = new_bundle_id
    with open(info_path, "wb") as f:
        plistlib.dump(info, f)

def resign_app(app_path, identity, entitlements_path, verbose=False):
    if verbose:
        print(f"[info] Resigning app with identity: {identity}")

    sig_dir = os.path.join(app_path, "_CodeSignature")
    if os.path.isdir(sig_dir):
        shutil.rmtree(sig_dir)

    for root, dirs, files in os.walk(app_path):
        for f in files:
            if f == "CodeResources":
                os.remove(os.path.join(root, f))

    for root, dirs, files in os.walk(app_path):
        for f in files:
            full = os.path.join(root, f)
            if os.access(full, os.X_OK) and not f.endswith(".plist"):
                run([
                    "codesign",
                    "--force",
                    "--sign", identity,
                    "--entitlements", entitlements_path,
                    "--timestamp=none",
                    full
                ], verbose=verbose)
def create_temp_keychain(verbose=False):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    keychain = tmp.name + ".keychain-db"
    run(["security", "create-keychain", "-p", "ken1keypass", keychain], verbose=verbose)
    run(["security", "set-keychain-settings", keychain], verbose=verbose)
    run(["security", "unlock-keychain", "-p", "ken1keypass", keychain], verbose=verbose)
    # make sure this keychain is in the search list
    run(["security", "list-keychains", "-s", keychain], verbose=verbose)
    return keychain

def delete_temp_keychain(keychain, verbose=False):
    run(["security", "delete-keychain", keychain], verbose=verbose)

def main():
    parser = argparse.ArgumentParser(description="ken1key IPA signer")
    parser.add_argument("--ipa", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--p12", required=True)
    parser.add_argument("--p12-password", required=True)
    parser.add_argument("--mobileprovision", required=True)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    work_dir = tempfile.mkdtemp(prefix="ken1key_ipa_")

    try:
        unzip_ipa(args.ipa, work_dir, verbose=args.verbose)
        app_path = find_app_bundle(work_dir)

        profile_plist = load_mobileprovision(args.mobileprovision, verbose=args.verbose)
        entitlements = extract_entitlements_from_profile(profile_plist, verbose=args.verbose)

        team_ids = profile_plist.get("TeamIdentifier", [])
        if not team_ids:
            raise RuntimeError("No TeamIdentifier in mobileprovision")

        team_id = team_ids[0]
        app_identifier = f"{team_id}.{args.bundle_id}"

        entitlements["application-identifier"] = app_identifier
        entitlements["keychain-access-groups"] = [app_identifier]
        entitlements["get-task-allow"] = args.debug

        ent_path = os.path.join(work_dir, "entitlements.plist")
        write_entitlements_plist(entitlements, ent_path, verbose=args.verbose)

        patch_info_plist(app_path, args.bundle_id, verbose=args.verbose)

        if args.dry_run:
            print("[info] Dry run complete.")
            print("[info] Working directory:", work_dir)
            return 0

        keychain = create_temp_keychain(verbose=args.verbose)
        try:
            import_p12(args.p12, args.p12_password, keychain, verbose=args.verbose)
            identity = get_identity_from_keychain(keychain, verbose=args.verbose)
            resign_app(app_path, identity, ent_path, verbose=args.verbose)
        finally:
            delete_temp_keychain(keychain, verbose=args.verbose)

        zip_ipa(os.path.join(work_dir, "Payload"), args.out, verbose=args.verbose)
        print(f"[success] Signed IPA written to: {args.out}")

    except Exception as e:
        print("[error]", e)
        return 1
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    return 0

if __name__ == "__main__":
    sys.exit(main())
