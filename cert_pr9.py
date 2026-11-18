"""Опыты C0-C3 с OpenSSL 3. Закрытый ключ только вне репозитория."""
import argparse
import os
import subprocess
import time
from pathlib import Path


def execute(args):
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    directory = args.directory.resolve()
    if directory == root or root in directory.parents:
        parser.error("Certificate directory must be outside Git")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert = directory / "lab-cert.pem"
    tls_key = directory / "lab-tls-key.pem"
    if cert.exists() or tls_key.exists():
        parser.error("Use a new certificate directory")
    old_umask = os.umask(0o077)
    try:
        version = execute(["openssl", "version"])
        print(version.stdout.strip())
        if version.returncode or not version.stdout.startswith("OpenSSL 3."):
            raise RuntimeError("OpenSSL 3 is required")
        created = execute(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-sha256", "-days", "2", "-noenc", "-subj",
            "/CN=PR9 local certificate", "-addext", "subjectAltName=DNS:app.lab.test",
            "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=serverAuth", "-keyout", str(tls_key), "-out", str(cert)])
        if created.returncode:
            raise RuntimeError("Certificate creation failed: " + created.stderr.strip())
    finally:
        os.umask(old_umask)
    meta = execute(["openssl", "x509", "-in", str(cert), "-noout", "-subject", "-issuer", "-dates",
                   "-sha256", "-fingerprint", "-ext", "subjectAltName"])
    if meta.returncode:
        raise RuntimeError(meta.stderr.strip())
    print(meta.stdout.strip())
    trusted = ["-no-CApath", "-no-CAstore", "-CAfile", str(cert)]
    verify = ["openssl", "verify"]
    suffix = ["-purpose", "sslserver", "-verify_hostname"]
    after = str(int(time.time()) + 3 * 86400)
    cases = (
        ("C0", trusted + suffix + ["app.lab.test"], None),
        ("C1", trusted + suffix + ["other.lab.test"], "hostname mismatch"),
        ("C2", ["-no-CAfile", "-no-CApath", "-no-CAstore"] + suffix + ["app.lab.test"], "self-signed certificate"),
        ("C3", trusted + suffix + ["app.lab.test", "-attime", after], "certificate has expired"),
    )
    all_ok = True
    for code, options, diagnostic in cases:
        result = execute(verify + options + [str(cert)])
        combined = (result.stdout + result.stderr).replace(str(cert), "lab-cert.pem").strip()
        print(f"\n{code} | exit={result.returncode}")
        print(combined)
        ok = (result.returncode == 0 and "OK" in combined) if diagnostic is None else (result.returncode != 0 and diagnostic in combined.lower())
        all_ok &= ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
