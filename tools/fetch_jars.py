#!/usr/bin/env python3
"""Download the V2 jars from Maven Central and check them against the pinned sha256 (and Central's .sha1)."""
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "validators"))
import run as R  # noqa: E402

GAV = {
    "pdfbox-2.0.27.jar": "org/apache/pdfbox/pdfbox/2.0.27",
    "fontbox-2.0.27.jar": "org/apache/pdfbox/fontbox/2.0.27",
    "commons-logging-1.2.jar": "commons-logging/commons-logging/1.2",
    "bcpkix-jdk15on-1.70.jar": "org/bouncycastle/bcpkix-jdk15on/1.70",
    "bcprov-jdk15on-1.70.jar": "org/bouncycastle/bcprov-jdk15on/1.70",
    "bcutil-jdk15on-1.70.jar": "org/bouncycastle/bcutil-jdk15on/1.70",
}
R.JARS_DIR.mkdir(parents=True, exist_ok=True)
rc = 0
for name, path in GAV.items():
    url = f"https://repo1.maven.org/maven2/{path}/{name}"
    data = urllib.request.urlopen(url).read()
    sha1 = urllib.request.urlopen(url + ".sha1").read().decode().split()[0]
    ok1 = hashlib.sha1(data).hexdigest() == sha1
    ok256 = hashlib.sha256(data).hexdigest() == R.JARS[name]
    print(f"{name}: sha1 {'OK' if ok1 else 'MISMATCH'}, sha256 {'OK' if ok256 else 'MISMATCH'}")
    if ok1 and ok256:
        (R.JARS_DIR / name).write_bytes(data)
    else:
        rc = 1
print("jars in", R.JARS_DIR)
sys.exit(rc)
