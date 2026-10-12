"""Fetch wintun.dll for the TUN backend.

wintun is a standalone DLL that ships as a release asset of the
wireguard-nt "wintun" sub-project. It is not bundled with this repo; run
this script once before building:

    python dl_wintun.py

It writes assets/wintun.dll and prints the URL it came from.
"""

import io
import os
import sys
import urllib.request
import zipfile

CANDIDATES = [
    "https://download.wireguard.com/windows-client/wintun.zip",
    "https://www.mullvad.net/media/wintun.zip",
    "https://wintun.net/wintun.zip",
    "https://github.com/WireGuard/wintun/releases/download/1.0/wintun.zip",
    "https://github.com/WireGuard/wintun/releases/download/0.12.1/wintun.zip",
    "https://github.com/WireGuard/wintun/releases/download/0.12.0/wintun.zip",
    "https://github.com/WireGuard/wintun/releases/download/0.11.0/wintun.zip",
    "https://github.com/WireGuard/wintun/releases/download/0.10.0/wintun.zip",
    "https://github.com/WireGuard/wintun/releases/download/0.9.0/wintun.zip",
]


def _try(url):
    req = urllib.request.Request(url, headers={"User-Agent": "letuc/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def main():
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "wintun.dll")

    last_err = None
    for url in CANDIDATES:
        try:
            data = _try(url)
        except Exception as e:
            last_err = e
            print("FAIL", url, e)
            continue
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            last_err = e
            print("FAIL not a zip", url, e)
            continue
        names = [n for n in z.namelist() if n.lower().endswith("wintun.dll")]
        if not names:
            last_err = RuntimeError("no wintun.dll in %s" % url)
            print("FAIL no dll", url)
            continue
        with open(out, "wb") as f:
            f.write(z.read(names[0]))
        print("saved", out, "from", url, len(z.read(names[0])), "bytes")
        return 0

    print("could not fetch wintun.dll:", last_err, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())