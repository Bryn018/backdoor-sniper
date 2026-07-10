import type { DetectionRule, ScanContext, RawMatch } from "./types";

/**
 * Helper: run a regex against every line and collect matches.
 * The regex should NOT use the global flag; we test line-by-line.
 */
function scanLines(
  ctx: ScanContext,
  pattern: RegExp,
  opts?: { minConfidence?: number; extra?: string }
): RawMatch[] {
  const out: RawMatch[] = [];
  const min = opts?.minConfidence ?? 0.85;
  for (let i = 0; i < ctx.lines.length; i++) {
    const raw = ctx.lines[i];
    // strip comments for matching accuracy but keep snippet original
    const code = stripLineComment(raw);
    const m = pattern.exec(code);
    if (m) {
      out.push({
        line: i + 1,
        snippet: raw.trim(),
        confidence: min,
        extra: opts?.extra ? m[0] : undefined,
      });
    }
  }
  return out;
}

/** Strip a trailing # comment (naive, ignores strings — acceptable for heuristics). */
function stripLineComment(line: string): string {
  // remove simple # comments not inside quotes (best-effort)
  let inS = false;
  let inD = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) inD = !inD;
    else if (c === "#" && !inS && !inD) return line.slice(0, i);
  }
  return line;
}

const has = (ctx: ScanContext, ...names: string[]) =>
  names.some((n) => ctx.imports.has(n) || ctx.fromImports.has(n));

// ---------------------------------------------------------------------------
// 1. CODE EXECUTION
// ---------------------------------------------------------------------------

const evalRule: DetectionRule = {
  id: "PY-EXEC-001",
  title: "Use of eval() with dynamic input",
  severity: "critical",
  category: "code-execution",
  description:
    "eval() executes an arbitrary string as Python code. When the string is built from user input, environment variables, network data or decoded blobs, an attacker can inject and run arbitrary Python — full RCE. eval is one of the most common primitives in Python web shells and backdoors.",
  remediation:
    "Avoid eval entirely. If you must evaluate expressions, use ast.literal_eval() for literals, or parse with a proper grammar. Never pass attacker-controlled data to eval().",
  references: ["CWE-95", "OWASP A03:2021"],
  match: (ctx) => scanLines(ctx, /\beval\s*\(/, { minConfidence: 0.9 }),
};

const execRule: DetectionRule = {
  id: "PY-EXEC-002",
  title: "Use of exec() to execute arbitrary code",
  severity: "critical",
  category: "code-execution",
  description:
    "exec() compiles and runs a string as Python code. Backdoors commonly use exec() to run decoded/decrypted payloads at runtime, hiding the real malicious code from static review.",
  remediation:
    "Remove exec(). If you need dynamic behavior, refactor into real functions/modules. If loading trusted code, import it as a module instead.",
  references: ["CWE-95"],
  match: (ctx) => scanLines(ctx, /\bexec\s*\(/, { minConfidence: 0.9 }),
};

const compileRule: DetectionRule = {
  id: "PY-EXEC-003",
  title: "compile() used to build executable code objects",
  severity: "high",
  category: "code-execution",
  description:
    "compile() turns source/AST strings into code objects that can later be exec'd. This is a classic two-stage evasion: the payload is compiled at runtime then executed, hiding it from simple string scans.",
  remediation:
    "Avoid compile() with dynamic strings. If used for legitimate templating, ensure the source string is fully trusted and constant.",
  match: (ctx) => scanLines(ctx, /\bcompile\s*\(/, { minConfidence: 0.8 }),
};

const dunderImportRule: DetectionRule = {
  id: "PY-EXEC-004",
  title: "Dynamic import via __import__() / importlib",
  severity: "high",
  category: "code-execution",
  description:
    "__import__() and importlib.import_module() load modules by name at runtime. Backdoors use this to load modules (e.g. ctypes, socket) indirectly so static greps for `import socket` miss them.",
  remediation:
    "Use a normal top-level `import` statement. If dynamic loading is required, validate the module name against an allow-list.",
  match: (ctx) =>
    scanLines(ctx, /__import__\s*\(|importlib\.import_module\s*\(/, {
      minConfidence: 0.85,
    }),
};

// ---------------------------------------------------------------------------
// 2. OS COMMAND EXECUTION
// ---------------------------------------------------------------------------

const osSystemRule: DetectionRule = {
  id: "PY-CMD-001",
  title: "os.system() shell command execution",
  severity: "high",
  category: "command-execution",
  description:
    "os.system() runs a command through the system shell (/bin/sh or cmd.exe). It is frequently abused by backdoors to download second-stage payloads, kill AV, or spawn reverse shells via bash -i.",
  remediation:
    "Use subprocess.run([...], shell=False) with explicit argument lists. Never interpolate user data into a shell command.",
  references: ["CWE-78"],
  match: (ctx) => scanLines(ctx, /\bos\.(system|popen)\s*\(/, { minConfidence: 0.9 }),
};

const subprocessShellRule: DetectionRule = {
  id: "PY-CMD-002",
  title: "subprocess with shell=True",
  severity: "high",
  category: "command-execution",
  description:
    "Passing shell=True to subprocess causes the command to be interpreted by the shell, enabling command injection if any part comes from user input. Backdoors use this to run obfuscated one-liners.",
  remediation:
    "Use shell=False and pass a list of arguments. If a shell is truly required, sanitize every interpolated value with shlex.quote().",
  references: ["CWE-78"],
  match: (ctx) =>
    scanLines(ctx, /shell\s*=\s*True/, { minConfidence: 0.8 }),
};

const osExecFamilyRule: DetectionRule = {
  id: "PY-CMD-003",
  title: "Low-level process execution (os.exec*/spawn*)",
  severity: "medium",
  category: "command-execution",
  description:
    "os.exec* and os.spawn* replace or create processes. Less common in benign code; used by malware to launch dropped binaries or re-exec themselves for persistence.",
  remediation:
    "Prefer subprocess.run(). Audit the command path and arguments — they must be constants or sanitized.",
  match: (ctx) =>
    scanLines(ctx, /\bos\.(exec\w*|spawn\w*|fork|kill|setsid)\s*\(/, {
      minConfidence: 0.75,
    }),
};

const ptySpawnRule: DetectionRule = {
  id: "PY-CMD-004",
  title: "pty.spawn() used to attach a shell to a tty",
  severity: "critical",
  category: "reverse-shell",
  description:
    "pty.spawn() forks a process attached to a pseudo-terminal. This is the canonical building block of Python reverse shells: combined with a socket it gives the attacker an interactive shell with full job control.",
  remediation:
    "Remove this call. If you legitimately need a PTY (e.g. a terminal emulator), audit the surrounding socket/dup2 logic carefully.",
  references: ["CWE-912"],
  match: (ctx) => scanLines(ctx, /\bpty\.spawn\s*\(/, { minConfidence: 0.95 }),
};

// ---------------------------------------------------------------------------
// 3. REVERSE SHELLS / NETWORK
// ---------------------------------------------------------------------------

const socketDup2Rule: DetectionRule = {
  id: "PY-NET-001",
  title: "Classic reverse-shell pattern: socket + dup2/fileno",
  severity: "critical",
  category: "reverse-shell",
  description:
    "Redirecting stdin/stdout/stderr (file descriptors 0/1/2) onto a network socket via os.dup2 is the textbook Python reverse shell. After this, every input/output of the process flows to the attacker — an interactive remote shell.",
  remediation:
    "This combination has almost no legitimate use. Delete it. If you need remote access, use SSH or an authenticated API.",
  references: ["CWE-912"],
  match: (ctx) =>
    scanLines(ctx, /\b(os\.dup2|dup2)\s*\([^,]*,\s*(0|1|2)\b|dup2\s*\([^,]*,\s*sys\.std(in|out|err)|dup2\s*\([^,]*,\s*(STDIN|STDOUT|STDERR)/i, {
      minConfidence: 0.95,
    }),
};

const socketConnectRule: DetectionRule = {
  id: "PY-NET-002",
  title: "Outbound socket connection (potential C2 callback)",
  severity: "high",
  category: "network",
  description:
    "A raw socket.socket() with connect() to an external host is how most implants phone home. Combined with send/recv loops it forms a C2 channel. Hardcoded IPs/domains are strong indicators of compromise.",
  remediation:
    "Use a high-level HTTP client (requests/httpx) over TLS to a known endpoint. Never connect to a hardcoded IP address in application code.",
  match: (ctx) =>
    scanLines(ctx, /\b(socket\.socket|s\.connect|\.connect\s*\(\s*\()/, {
      minConfidence: 0.7,
    }),
};

const bindShellRule: DetectionRule = {
  id: "PY-NET-003",
  title: "Listening socket (potential bind shell)",
  severity: "high",
  category: "reverse-shell",
  description:
    "socket.bind() + listen() + accept() opens a port waiting for inbound connections. When the accepted connection is wired to a shell (exec/pty), this is a bind shell — an open backdoor on the host.",
  remediation:
    "Do not open raw listening sockets in application code. Use a real web server framework with authentication.",
  match: (ctx) =>
    scanLines(ctx, /\b(\.bind\s*\(|\.listen\s*\(|\.accept\s*\(\s*\))/, {
      minConfidence: 0.6,
    }),
};

const telnetlibRule: DetectionRule = {
  id: "PY-NET-004",
  title: "telnetlib used for unencrypted remote access",
  severity: "medium",
  category: "network",
  description:
    "telnetlib sends credentials and data in cleartext and is a common reverse-shell transport in older Python implants (e.g. SocGholish-style droppers). Deprecated since Python 3.11.",
  remediation:
    "Remove telnetlib. Use paramiko/asyncssh over SSH or an HTTPS API.",
  match: (ctx) => scanLines(ctx, /\btelnetlib\b/, { minConfidence: 0.8 }),
};

const urllibSuspiciousRule: DetectionRule = {
  id: "PY-NET-005",
  title: "Remote payload download via urllib/request",
  severity: "medium",
  category: "network",
  description:
    "urllib.request.urlopen / urllib2.urlopen fetching a URL is a common stage-1 dropper behavior: download a script then exec it. The danger rises sharply when combined with exec/eval on the response.",
  remediation:
    "Pin URLs to HTTPS endpoints you control. Never exec() the body of an HTTP response.",
  match: (ctx) =>
    scanLines(ctx, /urllib\w*\.request\.urlopen|urllib2\.urlopen|requests\.get\s*\(/, {
      minConfidence: 0.6,
    }),
};

// ---------------------------------------------------------------------------
// 4. OBFUSCATION / ENCODING
// ---------------------------------------------------------------------------

const base64DecodeExecRule: DetectionRule = {
  id: "PY-OBF-001",
  title: "base64-decoded payload (likely obfuscated code)",
  severity: "high",
  category: "obfuscation",
  description:
    "base64.b64decode() of a large string is the single most common obfuscation trick in Python malware: the real payload (often another Python script, shellcode, or a PE) is hidden inside an innocuous-looking blob and decoded at runtime.",
  remediation:
    "Decode base64 only for legitimate binary data (images, tokens). If the decoded result is executed (exec/eval/PyExecJS), treat the whole file as malicious.",
  match: (ctx) =>
    scanLines(ctx, /base64\.(b64decode|b32decode|b16decode|urlsafe_b64decode|decodebytes)\s*\(/, {
      minConfidence: 0.8,
    }),
};

const longBase64BlobRule: DetectionRule = {
  id: "PY-OBF-002",
  title: "Long base64/hex string literal (embedded payload)",
  severity: "medium",
  category: "obfuscation",
  description:
    "A string literal of >60 base64 or hex characters is suspicious — it usually decodes to executable code, shellcode, or a binary blob that gets written to disk and run.",
  remediation:
    "Inspect what consumes this string. Move any real assets out of source into a versioned binary file.",
  match: (ctx) =>
    scanLines(ctx, /['"][A-Za-z0-9+/=]{60,}['"]/, { minConfidence: 0.6 }),
};

const codecsDecodeRule: DetectionRule = {
  id: "PY-OBF-003",
  title: "codecs.decode / rot13 / hex codec obfuscation",
  severity: "medium",
  category: "obfuscation",
  description:
    "codecs.decode(s, 'rot_13') or 'hex'/'zip' codecs are used to hide strings (commands, URLs) from simple grep. Combined with eval this becomes a fully obfuscated payload.",
  remediation:
    "Do not obfuscate strings. Store secrets in a vault, not behind a codec.",
  match: (ctx) =>
    scanLines(ctx, /codecs\.decode\s*\(|['"][^'"]*['"]\.decode\s*\(\s*['"](rot_?13|hex|zip|base64|utf_7)/, {
      minConfidence: 0.75,
    }),
};

const chrChainRule: DetectionRule = {
  id: "PY-OBF-004",
  title: "chr() concatenation chain (string reconstruction)",
  severity: "medium",
  category: "obfuscation",
  description:
    "Building strings from chr(N)+chr(N)+... is a classic evasion to hide payloads, URLs and commands from signature-based scanners. Three or more chr() on one line is a strong obfuscation signal.",
  remediation:
    "Replace with a plain string literal. If the value is a secret, load it from the environment.",
  match: (ctx) =>
    scanLines(ctx, /(chr\s*\(\s*\d+\s*\)[\s+]+){2,}chr\s*\(/, {
      minConfidence: 0.7,
    }),
};

const zlibExecRule: DetectionRule = {
  id: "PY-OBF-005",
  title: "zlib.decompress paired with exec (packed payload)",
  severity: "high",
  category: "obfuscation",
  description:
    "Compressing a payload with zlib then decompress+exec at runtime shrinks the on-disk footprint and breaks signatures. Seen in many PyInstaller-packed stealers.",
  remediation:
    "Decompress only trusted data. Remove any exec/eval of the decompressed result.",
  match: (ctx) =>
    scanLines(ctx, /zlib\.(decompress|decompressobj)/, { minConfidence: 0.7 }),
};

const marshalLoadRule: DetectionRule = {
  id: "PY-OBF-006",
  title: "marshal.loads of code objects",
  severity: "critical",
  category: "obfuscation",
  description:
    "marshal can serialize Python code objects. Malware authors pre-compile a payload, marshal it, then unmarshal+exec at runtime — completely hiding the source. This is almost never legitimate.",
  remediation:
    "Do not unmarshal code objects. Delete this code path.",
  references: ["CWE-502"],
  match: (ctx) =>
    scanLines(ctx, /marshal\.(loads|load)\s*\(/, { minConfidence: 0.9 }),
};

// ---------------------------------------------------------------------------
// 5. DESERIALIZATION
// ---------------------------------------------------------------------------

const pickleLoadRule: DetectionRule = {
  id: "PY-DESER-001",
  title: "pickle / cPickle / shelve deserialization",
  severity: "critical",
  category: "deserialization",
  description:
    "pickle.loads() can execute arbitrary code via the __reduce__ method. A malicious pickle file = instant RCE on load. Backdoors frequently hide inside 'saved game state' or 'config cache' pickles.",
  remediation:
    "Use JSON or a schema-validated format. If pickle is unavoidable, only load data you produced yourself, never from network/disk input.",
  references: ["CWE-502"],
  match: (ctx) =>
    scanLines(ctx, /(pickle|cPickle|shelve)\.(loads?|load)/, { minConfidence: 0.9 }),
};

const yamlLoadRule: DetectionRule = {
  id: "PY-DESER-002",
  title: "yaml.load without SafeLoader",
  severity: "high",
  category: "deserialization",
  description:
    "yaml.load() (without SafeLoader) can instantiate arbitrary Python objects from YAML tags — RCE on parse. A common supply-chain attack vector.",
  remediation:
    "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
  references: ["CWE-502"],
  match: (ctx) =>
    scanLines(ctx, /yaml\.load\s*\((?!\s*[^,]*Loader\s*=\s*yaml\.SafeLoader)/, {
      minConfidence: 0.75,
    }),
};

// ---------------------------------------------------------------------------
// 6. DANGEROUS IMPORTS
// ---------------------------------------------------------------------------

const ctypesRule: DetectionRule = {
  id: "PY-IMP-001",
  title: "ctypes — foreign function interface to libc",
  severity: "high",
  category: "dangerous-import",
  description:
    "ctypes lets Python call arbitrary C functions from shared libraries, including libc's system(), mmap() for shellcode, and Win32 API. Used heavily by cross-platform Python malware and shellcode loaders.",
  remediation:
    "Avoid ctypes in application code. If you need a native binding, write a proper C extension or use cffi with a fixed set of declarations.",
  match: (ctx) =>
    scanLines(ctx, /\bctypes\b/, { minConfidence: 0.7 }),
};

const win32ApiRule: DetectionRule = {
  id: "PY-IMP-002",
  title: "Win32 API access (pywin32 / winreg / wmi)",
  severity: "medium",
  category: "dangerous-import",
  description:
    "Direct Win32 API access is used for persistence (registry Run keys, services, scheduled tasks), process injection, and credential theft (LSASS). Rare in cross-platform apps.",
  remediation:
    "Use a high-level library. Audit every registry/service call against an allow-list of keys.",
  match: (ctx) =>
    scanLines(ctx, /\b(win32api|win32con|win32process|win32service|winreg|wmi|pywintypes)\b/, {
      minConfidence: 0.7,
    }),
};

const keyboardKeyloggerRule: DetectionRule = {
  id: "PY-IMP-003",
  title: "Keyboard hook library (potential keylogger)",
  severity: "high",
  category: "credential-theft",
  description:
    "The 'keyboard' / 'pynput' / 'win32console' libraries can capture every keystroke system-wide. Outside accessibility tooling this is almost always a keylogger harvesting credentials.",
  remediation:
    "Remove the library. If you need global hotkeys, scope the listener to your own app window only.",
  match: (ctx) =>
    scanLines(ctx, /\b(keyboard|pynput|GlobalHotKeys|Listener\s*\(\s*on_press)\b/, {
      minConfidence: 0.7,
    }),
};

// ---------------------------------------------------------------------------
// 7. PERSISTENCE
// ---------------------------------------------------------------------------

const cronPersistenceRule: DetectionRule = {
  id: "PY-PERS-001",
  title: "Cron / crontab manipulation (Linux persistence)",
  severity: "high",
  category: "persistence",
  description:
    "Writing to /etc/cron.*, /var/spool/cron or invoking crontab -e from a script is a classic Linux persistence technique: the malware re-executes itself on a schedule as root.",
  remediation:
    "Do not modify cron from application code. Use a systemd unit installed via a package manager.",
  match: (ctx) =>
    scanLines(ctx, /(\/etc\/cron|\/var\/spool\/cron|crontab|atrm|\bat\s+-)/, {
      minConfidence: 0.75,
    }),
};

const registryPersistenceRule: DetectionRule = {
  id: "PY-PERS-002",
  title: "Windows registry Run/RunOnce persistence",
  severity: "high",
  category: "persistence",
  description:
    "Writing to HKCU/HKLM ...\\CurrentVersion\\Run makes the payload execute at every login. This is the #1 Windows persistence mechanism used by Python RATs.",
  remediation:
    "Never write to Run/RunOnce from application code. Register your app properly via the Start Menu or Task Scheduler GUI.",
  match: (ctx) =>
    scanLines(ctx, /(CurrentVersion\\\\Run|Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|RunOnce|StartupApproved)/i, {
      minConfidence: 0.85,
    }),
};

const startupFolderRule: DetectionRule = {
  id: "PY-PERS-003",
  title: "Write to Startup / autostart folder",
  severity: "high",
  category: "persistence",
  description:
    "Dropping a .bat/.vbs/.py into the Windows Startup folder or ~/.config/autostart makes the payload run on every login/session — a trivial persistence primitive.",
  remediation:
    "Do not write files into startup directories. Use the platform's service manager.",
  match: (ctx) =>
    scanLines(ctx, /(Startup|Start Menu\\\\Programs\\\\Startup|\.config\/autostart|\.bashrc|\.bash_profile|\.profile|\.zshrc)/i, {
      minConfidence: 0.7,
    }),
};

const systemdPersistenceRule: DetectionRule = {
  id: "PY-PERS-004",
  title: "systemd service / timer creation",
  severity: "medium",
  category: "persistence",
  description:
    "Writing a .service or .timer into /etc/systemd or ~/.config/systemd/user grants reboot-surviving persistence with root privileges. Used by cryptominers and IoT botnets.",
  remediation:
    "Ship systemd units via a proper package; do not generate them at runtime.",
  match: (ctx) =>
    scanLines(ctx, /(\/etc\/systemd|\.config\/systemd|\.service|\.timer|systemctl\s+(enable|start))/, {
      minConfidence: 0.65,
    }),
};

// ---------------------------------------------------------------------------
// 8. CREDENTIAL THEFT
// ---------------------------------------------------------------------------

const browserCredentialRule: DetectionRule = {
  id: "PY-CRED-001",
  title: "Browser credential/cookie store access",
  severity: "high",
  category: "credential-theft",
  description:
    "Reading 'Login Data', 'Cookies', 'Local State' from Chrome/Edge/Firefox profile paths is the signature of a credential stealer (RedLine, Vidar, Raccoon-style). The DBs are decrypted with DPAPI / the 'Local State' key.",
  remediation:
    "Never read browser profile data. If you need SSO, use the official browser API or OAuth.",
  match: (ctx) =>
    scanLines(ctx, /(Login Data|Cookies|Local State|Web Data|chrome|edgy|firefox|AppData\\\\Local\\\\Google\\\\Chrome|Library\/Application Support\/Google\/Chrome)/i, {
      minConfidence: 0.7,
    }),
};

const discordTokenRule: DetectionRule = {
  id: "PY-CRED-002",
  title: "Discord token theft",
  severity: "high",
  category: "credential-theft",
  description:
    "Reading 'leveldb' or 'Local Storage' under the Discord app folder to extract tokens is the defining behavior of a Discord token grabber. Stolen tokens give full account access without 2FA.",
  remediation:
    "Remove this code. There is no legitimate reason for an app to read Discord's local storage.",
  match: (ctx) =>
    scanLines(ctx, /(discord|leveldb|Local Storage|discordptb|Discord\\\\Local Storage)/i, {
      minConfidence: 0.65,
    }),
};

const sshKeyRule: DetectionRule = {
  id: "PY-CRED-003",
  title: "SSH / GPG / AWS key file access",
  severity: "medium",
  category: "credential-theft",
  description:
    "Reading ~/.ssh/, ~/.aws/credentials, .gnupg/ or .kube/config from application code is suspicious — these are high-value secrets an attacker exfiltrates for lateral movement.",
  remediation:
    "Use an explicit credential provider (env vars, IAM role, secret manager). Never glob the user's home for keys.",
  match: (ctx) =>
    scanLines(ctx, /(\.ssh\/|\.aws\/credentials|\.gnupg|\.kube\/config|id_rsa|id_ed25519|\.docker\/config\.json)/, {
      minConfidence: 0.7 }),
};

// ---------------------------------------------------------------------------
// 9. PRIVILEGE ESCALATION
// ---------------------------------------------------------------------------

const setuidRule: DetectionRule = {
  id: "PY-PRIV-001",
  title: "uid/gid manipulation (setuid/setgid/seteuid)",
  severity: "medium",
  category: "privilege-escalation",
  description:
    "os.setuid/setgid/seteuid change the process identity. Used by rootkits to drop privileges after binding a privileged port, or to escalate by abusing a suid binary.",
  remediation:
    "Privilege changes belong in a small, audited entrypoint — not scattered through app code.",
  match: (ctx) =>
    scanLines(ctx, /os\.(setuid|setgid|seteuid|setegid|setreuid|setregid)\s*\(/, {
      minConfidence: 0.75,
    }),
};

const sudoRule: DetectionRule = {
  id: "PY-PRIV-002",
  title: "sudo / su invocation",
  severity: "medium",
  category: "privilege-escalation",
  description:
    "Invoking sudo/su from a script can be abused to trick users into entering their password for an attacker, or to chain a sudo misconfiguration into root.",
  remediation:
    "Require the user to run the whole program with sudo instead of shelling out to it.",
  match: (ctx) =>
    scanLines(ctx, /\b(sudo|su\s+-|\bdoas\b)\s+/, { minConfidence: 0.6 }),
};

// ---------------------------------------------------------------------------
// 10. EXFILTRATION
// ---------------------------------------------------------------------------

const exfilPostRule: DetectionRule = {
  id: "PY-EXF-001",
  title: "HTTP POST of collected data (exfiltration)",
  severity: "medium",
  category: "exfiltration",
  description:
    "requests.post with a data/files/json argument is how most stealers ship loot to a C2 server. The risk rises when the URL is hardcoded and the payload includes keyfiles or tokens.",
  remediation:
    "Send data only to your own authenticated API over HTTPS. Avoid hardcoded URLs.",
  match: (ctx) =>
    scanLines(ctx, /requests\.(post|put|patch)\s*\(/, { minConfidence: 0.55 }),
};

const webhookExfilRule: DetectionRule = {
  id: "PY-EXF-002",
  title: "Discord / Telegram webhook exfiltration",
  severity: "high",
  category: "exfiltration",
  description:
    "Discord webhooks and Telegram bot APIs are free, anonymous, TLS-encrypted C2 channels. Modern Python grabbers post stolen tokens/passwords straight to a webhook URL — no server needed.",
  remediation:
    "Remove the webhook. There is no legitimate reason for application code to POST to a Discord/Telegram webhook.",
  match: (ctx) =>
    scanLines(ctx, /(discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|discord\.com\/api\/webhooks)/i, {
      minConfidence: 0.85,
    }),
};

const dnsExfilRule: DetectionRule = {
  id: "PY-EXF-003",
  title: "DNS exfiltration pattern",
  severity: "high",
  category: "exfiltration",
  description:
    "Encoding stolen data into subdomain labels and resolving them via DNS is a stealthy exfiltration technique that bypasses many firewalls. Look for base32/hex labels concatenated to a domain and queried.",
  remediation:
    "Remove the DNS resolver calls. Use an authenticated HTTPS channel for any telemetry.",
  match: (ctx) =>
    scanLines(ctx, /(dns\.resolver|gethostbyname|socket\.getaddrinfo)/, {
      minConfidence: 0.55,
    }),
};

// ---------------------------------------------------------------------------
// 11. ANTI-ANALYSIS / EVASION
// ---------------------------------------------------------------------------

const vmDetectRule: DetectionRule = {
  id: "PY-ANTI-001",
  title: "VM / sandbox detection",
  severity: "medium",
  category: "anti-analysis",
  description:
    "Checking for VM-specific MACs (00:0c:29 VMware, 08:00:27 VirtualBox), /proc/cpuinfo hypervisor flag, or sandbox DLLs (sbiedll, dbghelp) is evasion: the malware stays dormant when analyzed.",
  remediation:
    "Remove environment fingerprinting. It has no legitimate role in application code.",
  match: (ctx) =>
    scanLines(ctx, /(VMware|VirtualBox|QEMU|vmware|vbox|sandboxie|sbiedll|hypervisor|\/proc\/cpuinfo|SbieDll)/i, {
      minConfidence: 0.7,
    }),
};

const debuggerRule: DetectionRule = {
  id: "PY-ANTI-002",
  title: "Debugger / tracer detection",
  severity: "medium",
  category: "anti-analysis",
  description:
    "Checking sys.gettrace(), ptrace, or IsDebuggerPresent to detect an attached debugger is anti-analysis. Malware aborts or behaves benignly when a debugger is present.",
  remediation:
    "Remove debugger detection. Rely on your test suite, not runtime evasion.",
  match: (ctx) =>
    scanLines(ctx, /(sys\.gettrace|IsDebuggerPresent|ptrace|CheckRemoteDebuggerPresent|being_debugged)/i, {
      minConfidence: 0.75,
    }),
};

const sleepEvasionRule: DetectionRule = {
  id: "PY-ANTI-003",
  title: "Long sleep (sandbox evasion)",
  severity: "low",
  category: "anti-analysis",
  description:
    "A long time.sleep() (commonly 30s+) at startup makes automated sandboxes time out before the payload runs. Combined with other anti-analysis flags this is a strong indicator.",
  remediation:
    "Remove artificial delays. If a delay is required (retry backoff), keep it short and bounded.",
  match: (ctx) =>
    scanLines(ctx, /time\.sleep\s*\(\s*(\d{5,}|[0-9]+\s*\*\s*60|[0-9]+\s*\*\s*3600)/, {
      minConfidence: 0.6,
    }),
};

// ---------------------------------------------------------------------------
// 12. FILESYSTEM
// ---------------------------------------------------------------------------

const chmodExecRule: DetectionRule = {
  id: "PY-FS-001",
  title: "os.chmod to make a file executable",
  severity: "medium",
  category: "filesystem",
  description:
    "Setting the executable bit (0o755 / 0o111) on a freshly written file is how droppers prepare a downloaded binary or script to be executed. Benign apps rarely need this.",
  remediation:
    "Use the platform package manager to install executables. Avoid chmod 0o755 from Python.",
  match: (ctx) =>
    scanLines(ctx, /os\.chmod\s*\([^)]*0o?755|os\.chmod\s*\([^)]*0o?111|os\.chmod\s*\([^)]*0o?777/, {
      minConfidence: 0.7,
    }),
};

const hiddenFileRule: DetectionRule = {
  id: "PY-FS-002",
  title: "Creation of hidden / dotfile",
  severity: "low",
  category: "filesystem",
  description:
    "Writing to a dot-prefixed file or directory (e.g. ~/.cache/...) hides the artifact from a casual `ls`. Common for staging downloaded payloads or config persistence.",
  remediation:
    "Use a clear, named data directory. Avoid dotfiles for executable content.",
  match: (ctx) =>
    scanLines(ctx, /open\s*\(\s*['"][\.\/~][^'"]*\/\.[A-Za-z0-9_]+/, {
      minConfidence: 0.5,
    }),
};

const tmpPayloadRule: DetectionRule = {
  id: "PY-FS-003",
  title: "Writing executable payload to /tmp",
  severity: "medium",
  category: "filesystem",
  description:
    "Dropping .so/.dll/.exe/.py files into /tmp or %TEMP% and then executing them is the canonical dropper pattern. /tmp is world-writable and rarely audited.",
  remediation:
    "Do not write executables to /tmp. Use a private app data directory and verify signatures before running.",
  match: (ctx) =>
    scanLines(ctx, /(\/tmp\/|%TEMP%|%APPDATA%|tempfile\.mkstemp|NamedTemporaryFile)/, {
      minConfidence: 0.55,
    }),
};

// ---------------------------------------------------------------------------
// 13. HARDCODED SECRETS
// ---------------------------------------------------------------------------

const telegramBotTokenRule: DetectionRule = {
  id: "PY-SEC-001",
  title: "Hardcoded Telegram bot token",
  severity: "high",
  category: "hardcoded-secret",
  description:
    "A Telegram bot token (digits:alphanum) is both a secret AND, in Python malware, a C2 channel. Anyone with the token can read messages sent to the bot — full command-and-control.",
  remediation:
    "Revoke the token immediately in BotFather. Load it from an environment variable if still needed.",
  match: (ctx) =>
    scanLines(ctx, /\d{8,12}:[A-Za-z0-9_-]{30,}/, { minConfidence: 0.9 }),
};

const discordWebhookRule: DetectionRule = {
  id: "PY-SEC-002",
  title: "Hardcoded Discord webhook URL",
  severity: "high",
  category: "hardcoded-secret",
  description:
    "A Discord webhook URL lets anyone POST messages to a channel. In malware it doubles as an exfil endpoint. Committing one to source is both a leak and an IoC.",
  remediation:
    "Rotate the webhook (Discord → Edit Channel → Integrations → Delete). Never hardcode webhook URLs.",
  match: (ctx) =>
    scanLines(ctx, /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+/i, {
      minConfidence: 0.9,
    }),
};

const hardcodedPasswordRule: DetectionRule = {
  id: "PY-SEC-003",
  title: "Hardcoded password / API key",
  severity: "medium",
  category: "hardcoded-secret",
  description:
    "String literals assigned to variables named password/passwd/secret/api_key/token are leaked credentials. Even if benign, they should never live in source.",
  remediation:
    "Move secrets to environment variables or a secret manager. Rotate any value already committed.",
  match: (ctx) =>
    scanLines(ctx, /\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token)\b\s*=\s*['"][^'"]{6,}['"]/i, {
      minConfidence: 0.7 }),
};

const ipv4AddressRule: DetectionRule = {
  id: "PY-SEC-004",
  title: "Hardcoded IPv4 address (possible C2)",
  severity: "low",
  category: "suspicious-pattern",
  description:
    "A raw IPv4 address literal in source is suspicious — application code should use DNS names. Hardcoded IPs are a common C2 indicator and break under infrastructure rotation.",
  remediation:
    "Replace with a DNS name you control. Allow-list any IP that must remain (e.g. a metadata endpoint).",
  match: (ctx) => {
    const out: RawMatch[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      const code = stripLineComment(ctx.lines[i]);
      for (const m of code.matchAll(/\b(\d{1,3}\.){3}\d{1,3}\b/g)) {
        const ip = m[0];
        // Skip localhost, loopback, and private ranges
        if (
          ip.startsWith("127.") || // loopback
          ip.startsWith("0.") || // reserved
          ip.startsWith("10.") || // private
          ip.startsWith("192.168.") || // private
          ip.match(/^172\.(1[6-9]|2\d|3[01])\./) || // private
          ip === "255.255.255.255" || // broadcast
          ip === "0.0.0.0" // all interfaces
        )
          continue;
        out.push({
          line: i + 1,
          snippet: ctx.lines[i].trim(),
          confidence: 0.45,
        });
        break; // one match per line is enough
      }
    }
    return out;
  },
};

// ---------------------------------------------------------------------------
// 14. SUSPICIOUS PATTERNS
// ---------------------------------------------------------------------------

const envInjectionRule: DetectionRule = {
  id: "PY-SUS-001",
  title: "os.environ / getenv fed into exec/eval/subprocess",
  severity: "high",
  category: "code-execution",
  description:
    "Reading an environment variable and passing it to exec/eval/subprocess lets an attacker control execution by setting a single env var — a stealthy backdoor trigger that looks innocent in code review.",
  remediation:
    "Never execute env vars. Treat env values as untrusted data; validate against an allow-list.",
  match: (ctx) =>
    scanLines(ctx, /(exec|eval|os\.system|subprocess\.\w+)\s*\([^)]*(os\.environ|os\.getenv|getenv)/, {
      minConfidence: 0.85,
    }),
};

const inputExecRule: DetectionRule = {
  id: "PY-SUS-002",
  title: "input() piped into eval/exec (Python 2 eval)",
  severity: "critical",
  category: "code-execution",
  description:
    "In Python 2, input() == eval(raw_input()). Passing user input through it (or modern input() into eval) is an instant RCE. This is the simplest possible backdoor.",
  remediation:
    "Use raw_input (py2) or input (py3) and validate the value. Never feed it to eval/exec.",
  match: (ctx) =>
    scanLines(ctx, /(eval|exec)\s*\(\s*input\s*\(/, { minConfidence: 0.95 }),
};

const requestExecRule: DetectionRule = {
  id: "PY-SUS-003",
  title: "exec() of HTTP response body (fileless backdoor)",
  severity: "critical",
  category: "code-execution",
  description:
    "Fetching a URL and exec()'ing the response text is a fileless backdoor: the malicious code never touches disk and can be changed server-side at will. Extremely common in droppers.",
  remediation:
    "Never exec remote content. Fetch signed packages and verify their signature before import.",
  match: (ctx) =>
    scanLines(ctx, /(exec|eval)\s*\(\s*(requests|urllib|urlopen|httpx)/, {
      minConfidence: 0.95,
    }),
};

const evalFormatStringRule: DetectionRule = {
  id: "PY-SUS-004",
  title: "eval of f-string / format (dynamic code construction)",
  severity: "high",
  category: "code-execution",
  description:
    "Building the argument to eval/exec with f-strings, .format, % or concatenation means the executed code is computed at runtime — defeating static review and hiding intent.",
  remediation:
    "Do not construct code strings dynamically. Refactor to real functions.",
  match: (ctx) =>
    scanLines(ctx, /(eval|exec)\s*\(\s*[fF]['"]/, { minConfidence: 0.85 }),
};

const shellInjectionConcatRule: DetectionRule = {
  id: "PY-SUS-005",
  title: "String concatenation in shell command (injection risk)",
  severity: "medium",
  category: "command-execution",
  description:
    "Building a shell command with + or f-strings before passing it to os.system/subprocess(shell=True) enables command injection if any operand is user-controlled.",
  remediation:
    "Pass a list of arguments to subprocess with shell=False. Use shlex.quote() if a shell is unavoidable.",
  match: (ctx) =>
    scanLines(ctx, /(os\.system|subprocess\.\w+)\s*\([^)]*[\+fF]['"]/, {
      minConfidence: 0.7,
    }),
};

const processInjectionRule: DetectionRule = {
  id: "PY-SUS-006",
  title: "Process hollowing / injection primitives (Windows)",
  severity: "high",
  category: "code-execution",
  description:
    "Calls to CreateProcess, WriteProcessMemory, VirtualAllocEx, NtUnmapViewOfSection (often via ctypes) are process injection primitives. No legitimate Python app needs them.",
  remediation:
    "Remove the calls. If you need to launch a process, use subprocess normally.",
  match: (ctx) =>
    scanLines(ctx, /(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|NtUnmapViewOfSection|CreateProcess|QueueUserAPC|SetWindowsHookEx|GetProcAddress)/, {
      minConfidence: 0.85,
    }),
};

const mmapShellcodeRule: DetectionRule = {
  id: "PY-SUS-007",
  title: "mmap with executable protection (shellcode runner)",
  severity: "critical",
  category: "code-execution",
  description:
    "Allocating memory with PROT_EXEC (0x4) and writing bytes into it is shellcode execution. Combined with ctypes to call the buffer as a function, this runs native payload in-process.",
  remediation:
    "Remove this code. There is no legitimate reason to mark Python memory executable.",
  match: (ctx) =>
    scanLines(ctx, /(PROT_EXEC|0x4|0x7|mmap\s*\([^)]*exec|VirtualProtect[^)]*0x40|PAGE_EXECUTE)/, {
      minConfidence: 0.85,
    }),
};

const ncBashReverseShellRule: DetectionRule = {
  id: "PY-SUS-008",
  title: "Embedded bash reverse shell one-liner",
  severity: "critical",
  category: "reverse-shell",
  description:
    "A string containing 'bash -i >& /dev/tcp/...' or 'nc -e /bin/sh' is a reverse shell one-liner being passed to the OS shell. Even as a string it indicates hostile intent.",
  remediation:
    "Delete the string. There is no legitimate use for these one-liners in application code.",
  match: (ctx) =>
    scanLines(ctx, /(bash\s+-i\s+>&|\/dev\/tcp\/|nc\s+-e\s+\/bin\/?sh|mkfifo|\/dev\/udp\/)/, {
      minConfidence: 0.95,
    }),
};

const pastebinRule: DetectionRule = {
  id: "PY-SUS-009",
  title: "Pastebin / hastebin / paste.rs URL (stage payload)",
  severity: "medium",
  category: "network",
  description:
    "Fetching code from pastebin.com / raw.githubusercontent / hastebin is a common way to host mutable stage-2 payloads. The C2 can change the payload without touching the dropper.",
  remediation:
    "Fetch resources only from domains you control. Pin and verify the content hash.",
  match: (ctx) =>
    scanLines(ctx, /(pastebin\.com|raw\.githubusercontent|hastebin|paste\.rs|ghostbin|rentry\.co|ix\.io)/i, {
      minConfidence: 0.7,
    }),
};

const ngrokRule: DetectionRule = {
  id: "PY-SUS-010",
  title: "ngrok / dynamic DNS C2 domain",
  severity: "medium",
  category: "network",
  description:
    "ngrok.io, serveo, localhost.run, no-ip domains are free tunneling services attackers use to expose a local C2 without buying infrastructure. Common in off-the-shelf Python RATs.",
  remediation:
    "Do not connect to ephemeral tunneling domains. Use a fixed, owned domain over TLS.",
  match: (ctx) =>
    scanLines(ctx, /(ngrok\.io|serveo\.net|localhost\.run|\.ngrok\.app|\.ddns\.net|no-ip\.com|hopto\.org|sytes\.net)/i, {
      minConfidence: 0.75,
    }),
};

const overlongLineRule: DetectionRule = {
  id: "PY-SUS-011",
  title: "Extremely long line (minified/obfuscated code)",
  severity: "low",
  category: "obfuscation",
  description:
    "A single source line over 500 characters usually means minified or packed code. Legitimate Python is rarely written this way; it is a strong signal of obfuscation.",
  remediation:
    "Reformat the code. If the line is a data blob, move it to a separate file.",
  match: (ctx) => {
    const out: RawMatch[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      if (ctx.lines[i].length > 500) {
        out.push({
          line: i + 1,
          snippet: ctx.lines[i].slice(0, 120) + "…",
          confidence: 0.55,
        });
      }
    }
    return out;
  },
};

const base32ExfilRule: DetectionRule = {
  id: "PY-SUS-012",
  title: "base32 encoding (DNS exfil indicator)",
  severity: "low",
  category: "exfiltration",
  description:
    "base32 produces the [A-Z2-7=] charset which is DNS-label safe — it's the go-to encoding for DNS exfiltration. Standalone use is suspicious.",
  remediation:
    "Use base64 for binary data. If base32 is required, document why.",
  match: (ctx) =>
    scanLines(ctx, /base64\.b32encode|base32/, { minConfidence: 0.55 }),
};

// ---------------------------------------------------------------------------
// 15. ADDITIONAL RULES
// ---------------------------------------------------------------------------

const reduceMethodRule: DetectionRule = {
  id: "PY-DESER-003",
  title: "__reduce__ method (malicious pickle primitive)",
  severity: "high",
  category: "deserialization",
  description:
    "A __reduce__ method inside a class defines how pickle serializes the object. Malware uses it to return (callable, args) so that pickle.loads() executes arbitrary code on deserialization. This is the core primitive behind all pickle RCE exploits.",
  remediation:
    "Remove __reduce__ unless you are implementing a legitimate custom pickle protocol. Use __getstate__/__setstate__ for safe serialization, or switch to JSON.",
  references: ["CWE-502"],
  match: (ctx) =>
    scanLines(ctx, /def\s+__reduce__\s*\(/, { minConfidence: 0.85 }),
};

const systemInReduceRule: DetectionRule = {
  id: "PY-DESER-004",
  title: "os.system / subprocess in __reduce__ return (pickle RCE)",
  severity: "critical",
  category: "deserialization",
  description:
    "Returning (os.system, (cmd,)) or (subprocess.call, [...]) from __reduce__ means pickle.loads() will execute that command. This is a direct, weaponized pickle backdoor.",
  remediation:
    "Delete this code immediately. Use json or a schema-validated format instead of pickle.",
  references: ["CWE-502"],
  match: (ctx) =>
    scanLines(ctx, /return\s+\(\s*(os\.system|os\.popen|subprocess\.\w+)/, {
      minConfidence: 0.95,
    }),
};

const insecureTempFileRule: DetectionRule = {
  id: "PY-FS-004",
  title: "Insecure temporary file creation",
  severity: "medium",
  category: "filesystem",
  description:
    "tempfile.mktemp() is deprecated and insecure — it creates a predictable filename that an attacker can race to replace (TOCTOU). Malware exploits this for privilege escalation by symlinking the predicted path.",
  remediation:
    "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile(delete=False) with proper permissions.",
  references: ["CWE-377"],
  match: (ctx) =>
    scanLines(ctx, /tempfile\.mktemp\s*\(/, { minConfidence: 0.85 }),
};

const assertSideEffectRule: DetectionRule = {
  id: "PY-SUS-013",
  title: "assert used for security checks (bypassable with -O)",
  severity: "medium",
  category: "suspicious-pattern",
  description:
    "Using assert for authentication or access checks means running Python with -O (optimize) strips them out entirely, bypassing all security. Attackers who control the launch command can silently disable protections.",
  remediation:
    "Use explicit if/raise for security-critical checks. Never rely on assert for auth, access control, or input validation.",
  references: ["CWE-617"],
  match: (ctx) =>
    scanLines(ctx, /assert\s+.*(password|token|auth|permission|access|admin|secret|login)/i, {
      minConfidence: 0.7,
    }),
};

const sqlInjectionRule: DetectionRule = {
  id: "PY-SUS-014",
  title: "String formatting in SQL query (SQL injection)",
  severity: "medium",
  category: "suspicious-pattern",
  description:
    "Using f-strings, .format(), or % in SQL queries allows an attacker to inject arbitrary SQL — a classic injection vector. In a backdoor context this can be used to extract or modify data from the application's database.",
  remediation:
    "Use parameterized queries (cursor.execute('SELECT ... WHERE id=?', (id,))). Never interpolate user input into SQL.",
  references: ["CWE-89"],
  match: (ctx) =>
    scanLines(ctx, /execute\s*\(\s*[fF]['"]|execute\s*\([^)]*\.format\(|execute\s*\([^)]*%[sd]/, {
      minConfidence: 0.75,
    }),
};

const importlibReloadRule: DetectionRule = {
  id: "PY-SUS-015",
  title: "importlib.reload used to re-execute module code",
  severity: "low",
  category: "suspicious-pattern",
  description:
    "importlib.reload() re-executes a module's top-level code. If the module was modified on disk (e.g. by an attacker), reload runs the tampered code — a form of code injection via the filesystem.",
  remediation:
    "Avoid reload in production. If dynamic updates are needed, use a proper hot-reload framework that validates code signatures.",
  match: (ctx) =>
    scanLines(ctx, /importlib\.reload\s*\(/, { minConfidence: 0.6 }),
};

// ---------------------------------------------------------------------------
// 16. EXTRA RULES
// ---------------------------------------------------------------------------

const randomSeedFrozenRule: DetectionRule = {
  id: "PY-SUS-016",
  title: "Frozen random seed (deterministic — weak crypto)",
  severity: "low",
  category: "suspicious-pattern",
  description:
    "random.seed(0) or seeding with a constant makes output predictable. In security contexts (token generation, session IDs, password reset codes) this defeats the randomness entirely — attackers can replay/forge tokens.",
  remediation:
    "Use secrets module for security-sensitive randomness. Never seed random with a constant for crypto-adjacent operations.",
  references: ["CWE-335"],
  match: (ctx) =>
    scanLines(ctx, /random\.seed\s*\(\s*\d+\s*\)/, { minConfidence: 0.75 }),
};

const jwtNoneAlgRule: DetectionRule = {
  id: "PY-SUS-017",
  title: "JWT with 'none' algorithm or verify=False",
  severity: "high",
  category: "suspicious-pattern",
  description:
    "Setting JWT algorithm to 'none' or passing verify_signature=False disables signature verification entirely. An attacker can forge any token with arbitrary claims — full authentication bypass.",
  remediation:
    "Always verify signatures with a strong algorithm (HS256/RS256). Never accept 'none' algorithm. Never disable signature verification.",
  references: ["CWE-345"],
  match: (ctx) =>
    scanLines(
      ctx,
      /algorithms\s*=\s*\[?\s*['"]none['"]|verify_signature\s*=\s*False|verify\s*=\s*False/,
      { minConfidence: 0.9 }
    ),
};

const sslVerifyFalseRule: DetectionRule = {
  id: "PY-SUS-018",
  title: "SSL verification disabled",
  severity: "high",
  category: "network",
  description:
    "Setting verify=False in requests/httpx or SSLContext.check_hostname=False disables TLS certificate validation, enabling man-in-the-middle attacks. An attacker on the network can intercept/modify all HTTPS traffic.",
  remediation:
    "Always verify=True (the default). If internal CAs are used, configure the CA bundle rather than disabling verification.",
  references: ["CWE-295"],
  match: (ctx) =>
    scanLines(ctx, /verify\s*=\s*False|check_hostname\s*=\s*False|CERT_NONE|ssl\._create_unverified_context/, {
      minConfidence: 0.85,
    }),
};

const xmlExternalEntityRule: DetectionRule = {
  id: "PY-SUS-019",
  title: "XML parser without XXE protection",
  severity: "high",
  category: "suspicious-pattern",
  description:
    "Parsing XML with defusedxml missing or with resolve_entities=True enables XXE attacks. An attacker can read arbitrary files, perform SSRF, or cause denial-of-service via billion-laughs.",
  remediation:
    "Use defusedxml instead of xml.etree/ElementTree/lxml for untrusted XML. If lxml is required, set resolve_entities=False and no_network=True.",
  references: ["CWE-611"],
  match: (ctx) => {
    // only flag if defusedxml not imported
    const hasDefused = ctx.imports.has("defusedxml");
    if (hasDefused) return [];
    return scanLines(
      ctx,
      /xml\.etree\.ElementTree\.parse|fromstring|lxml\.etree\.(parse|fromstring)|xml\.dom\.(minidom|parse)/,
      { minConfidence: 0.6 }
    );
  },
};

const devModeInProdRule: DetectionRule = {
  id: "PY-SUS-020",
  title: "Debug mode enabled (exposes execution)",
  severity: "medium",
  category: "suspicious-pattern",
  description:
    "app.run(debug=True) or Django DEBUG=True exposes the Werkzeug/Django debugger, which allows arbitrary Python execution via the interactive console if an exception is triggered. A common RCE vector in staging/prod leaks.",
  remediation:
    "Set debug=False in production. Drive debug mode from an environment variable that defaults to off.",
  references: ["CWE-489"],
  match: (ctx) =>
    scanLines(ctx, /debug\s*=\s*True|DEBUG\s*=\s*True/, { minConfidence: 0.65 }),
};

const evalGetattrRule: DetectionRule = {
  id: "PY-SUS-021",
  title: "getattr() with dynamic name (reflection abuse)",
  severity: "medium",
  category: "code-execution",
  description:
    "getattr(obj, user_input) dynamically resolves attributes by name. Combined with builtins or imported modules, an attacker can reach dangerous functions (e.g. getattr(os, 'system')) even when they aren't directly referenced in code.",
  remediation:
    "Validate the attribute name against an allow-list before getattr. Avoid reflecting on user-supplied names against builtins or os/subprocess.",
  match: (ctx) =>
    scanLines(ctx, /getattr\s*\([^,]*,\s*(input|request\.|sys\.argv|os\.environ|getenv)/, {
      minConfidence: 0.8,
    }),
};

// ---------------------------------------------------------------------------
// ADDITIONAL RULES — Round 4
// ---------------------------------------------------------------------------

const subprocessWithoutCaptureRule: DetectionRule = {
  id: "PY-CMD-005",
  title: "Subprocess call without output capture (potential shell injection)",
  severity: "low",
  category: "command-execution",
  description:
    "subprocess.call/Popen without capture_output or stdout/stderr redirection may allow output to leak to the attacker, and combined with shell=True is a common injection vector.",
  remediation:
    "Use subprocess.run() with capture_output=True and shell=False. Avoid shell=True with user input.",
  references: ["CWE-78"],
  match: (ctx) =>
    scanLines(ctx, /subprocess\.(call|Popen|run)\s*\([^)]*(?!capture_output|stdout)[^)]*\)/, {
      minConfidence: 0.5,
    }),
};

const globalVariableRule: DetectionRule = {
  id: "PY-SUS-022",
  title: "Global variable modification (potential persistence)",
  severity: "low",
  category: "persistence",
  description:
    "Using the 'global' keyword to modify module-level variables can indicate a persistence mechanism where a backdoor injects state that persists across function calls. Combined with import hooks, this is a stealthy way to maintain access.",
  remediation:
    "Avoid modifying global state from functions. Use class instances or closures for mutable state. Audit all 'global' declarations for necessity.",
  references: ["CWE-589"],
  match: (ctx) =>
    scanLines(ctx, /\bglobal\s+\w+/, { minConfidence: 0.35 }),
};

const socketServerRule: DetectionRule = {
  id: "PY-NET-006",
  title: "Socket server / bind (potential C2 listener)",
  severity: "high",
  category: "network",
  description:
    "Creating a socket server (bind + listen) can indicate a command-and-control listener or a bind shell. The attacker can connect to this port to execute commands remotely.",
  remediation:
    "If this is a legitimate server, ensure it binds to localhost only and requires authentication. Audit for bind shells in production code.",
  references: ["CWE-200"],
  match: (ctx) => {
    const hasBind = ctx.lines.some((l) => /\.bind\s*\(/.test(stripLineComment(l)));
    const hasListen = ctx.lines.some((l) => /\.listen\s*\(/.test(stripLineComment(l)));
    if (hasBind || hasListen) {
      return scanLines(ctx, /\.bind\s*\(|\.listen\s*\(/, { minConfidence: 0.75 });
    }
    return [];
  },
};

const importHijackRule: DetectionRule = {
  id: "PY-SUS-023",
  title: "Import hook injection (sys.meta_path / importlib hack)",
  severity: "high",
  category: "persistence",
  description:
    "Manipulating sys.meta_path, sys.path_hooks, or importlib.machinery allows an attacker to intercept all future imports. This is a stealthy persistence mechanism — malicious code runs whenever any module is imported, even after a reboot.",
  remediation:
    "Never modify sys.meta_path or sys.path_hooks in application code. If needed for testing, reset them after use. Audit any code that touches the import system.",
  references: ["CWE-506"],
  match: (ctx) =>
    scanLines(ctx, /sys\.meta_path|sys\.path_hooks|importlib\.machinery/, {
      minConfidence: 0.85,
    }),
};

const dangerousYakRule: DetectionRule = {
  id: "PY-OBF-008",
  title: "eval + zlib / decompress chain (deep obfuscation)",
  severity: "critical",
  category: "obfuscation",
  description:
    "Combining eval/exec with zlib.decompress (or other decompression) is a hallmark of heavily obfuscated malware. The actual payload is compressed to evade static analysis, then decompressed and executed at runtime.",
  remediation:
    "Never eval/exec decompressed content. If dynamic loading is needed, use a sandboxed environment and audit all decompressed content before execution.",
  references: ["CWE-94"],
  match: (ctx) => {
    const hasEvalExec = ctx.lines.some(
      (l) => /\b(eval|exec)\s*\(/.test(stripLineComment(l))
    );
    const hasDecompress = ctx.lines.some(
      (l) => /zlib\.decompress|decompress\s*\(/.test(stripLineComment(l))
    );
    if (hasEvalExec && hasDecompress) {
      return scanLines(ctx, /\b(eval|exec)\s*\(/, { minConfidence: 0.92 });
    }
    return [];
  },
};

const tempfileRaceRule: DetectionRule = {
  id: "PY-FS-005",
  title: "Insecure temp file creation (race condition)",
  severity: "medium",
  category: "filesystem",
  description:
    "Using open() on paths from tempfile.mktemp() or hardcoded /tmp/ paths creates a TOCTOU race condition. An attacker can replace the file between creation and use (symlink attack).",
  remediation:
    "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile(delete=False) which create files atomically with proper permissions.",
  references: ["CWE-377"],
  match: (ctx) =>
    scanLines(ctx, /open\s*\(\s*['"]\/tmp\/|tempfile\.mktemp/, {
      minConfidence: 0.75,
    }),
};

const itertoolsSteganographyRule: DetectionRule = {
  id: "PY-OBF-009",
  title: "Steganographic data extraction (hidden payload)",
  severity: "high",
  category: "obfuscation",
  description:
    "Extracting data from images (PIL/Pillow pixel reads) or audio files and then eval/exec-ing the result is a steganographic backdoor technique. The malicious code is hidden inside media files and extracted at runtime.",
  remediation:
    "Never execute data extracted from media files. If image processing is needed, validate that pixel data is used only for display/analysis, never as code.",
  references: ["CWE-94"],
  match: (ctx) => {
    const hasPixelRead = ctx.lines.some(
      (l) => /getpixel|getdata|tobytes|\.load\s*\(\s*\)/.test(stripLineComment(l))
    );
    const hasEvalExec = ctx.lines.some(
      (l) => /\b(eval|exec)\s*\(/.test(stripLineComment(l))
    );
    if (hasPixelRead && hasEvalExec) {
      return scanLines(ctx, /\b(eval|exec)\s*\(/, { minConfidence: 0.85 });
    }
    return [];
  },
};

const platformInfoRule: DetectionRule = {
  id: "PY-SUS-024",
  title: "Excessive system fingerprinting (reconnaissance)",
  severity: "medium",
  category: "anti-analysis",
  description:
    "Collecting extensive system information (platform, hostname, username, CPU count, memory, etc.) is common in reconnaissance stages of malware. This data helps attackers target their exploit and avoid sandboxes.",
  remediation:
    "If system info is needed for legitimate purposes (e.g., logging), minimize the data collected. Avoid collecting username, hostname, and environment variables together.",
  references: ["CWE-200"],
  match: (ctx) => {
    const signals = [
      ctx.imports.has("platform"),
      ctx.imports.has("socket"),
      ctx.lines.some((l) => /os\.environ|getenv/.test(stripLineComment(l))),
      ctx.lines.some((l) => /platform\.(node|system|processor|release|machine)/.test(stripLineComment(l))),
      ctx.lines.some((l) => /os\.getlogin|getpass\.getuser/.test(stripLineComment(l))),
    ];
    const count = signals.filter(Boolean).length;
    if (count >= 3) {
      return scanLines(ctx, /platform\.|os\.getlogin|getpass\.getuser|os\.environ/, {
        minConfidence: 0.6,
      });
    }
    return [];
  },
};

const strToBytesRule: DetectionRule = {
  id: "PY-OBF-010",
  title: "Manual bytes construction (shellcode builder)",
  severity: "high",
  category: "obfuscation",
  description:
    "Building bytes objects manually from hex strings, integer arrays, or character codes is commonly used to construct shellcode that will be executed via ctypes or mmap. This evades string-based detection.",
  remediation:
    "Avoid constructing raw byte sequences from hex/int arrays unless absolutely necessary for legitimate binary protocol handling. Audit any bytes that are passed to ctypes or mmap.",
  references: ["CWE-506"],
  match: (ctx) => {
    const hasBytesBuilder = ctx.lines.some(
      (l) => /bytes\s*\(\s*\[|bytes\.fromhex|bytearray\s*\(\s*\[/.test(stripLineComment(l))
    );
    const hasCtypesOrMmap = ctx.imports.has("ctypes") || ctx.imports.has("mmap");
    if (hasBytesBuilder && hasCtypesOrMmap) {
      return scanLines(ctx, /bytes\s*\(\s*\[|bytes\.fromhex|bytearray\s*\(\s*\[/, {
        minConfidence: 0.88,
      });
    }
    return [];
  },
};

// ---------------------------------------------------------------------------
// RULE REGISTRY
// ---------------------------------------------------------------------------

export const RULES: DetectionRule[] = [
  // code execution
  evalRule,
  execRule,
  compileRule,
  dunderImportRule,
  // command execution
  osSystemRule,
  subprocessShellRule,
  osExecFamilyRule,
  ptySpawnRule,
  // network / reverse shell
  socketDup2Rule,
  socketConnectRule,
  bindShellRule,
  telnetlibRule,
  urllibSuspiciousRule,
  // obfuscation
  base64DecodeExecRule,
  longBase64BlobRule,
  codecsDecodeRule,
  chrChainRule,
  zlibExecRule,
  marshalLoadRule,
  // deserialization
  pickleLoadRule,
  yamlLoadRule,
  // dangerous imports
  ctypesRule,
  win32ApiRule,
  keyboardKeyloggerRule,
  // persistence
  cronPersistenceRule,
  registryPersistenceRule,
  startupFolderRule,
  systemdPersistenceRule,
  // credential theft
  browserCredentialRule,
  discordTokenRule,
  sshKeyRule,
  // priv esc
  setuidRule,
  sudoRule,
  // exfiltration
  exfilPostRule,
  webhookExfilRule,
  dnsExfilRule,
  // anti-analysis
  vmDetectRule,
  debuggerRule,
  sleepEvasionRule,
  // filesystem
  chmodExecRule,
  hiddenFileRule,
  tmpPayloadRule,
  // secrets
  telegramBotTokenRule,
  discordWebhookRule,
  hardcodedPasswordRule,
  ipv4AddressRule,
  // suspicious
  envInjectionRule,
  inputExecRule,
  requestExecRule,
  evalFormatStringRule,
  shellInjectionConcatRule,
  processInjectionRule,
  mmapShellcodeRule,
  ncBashReverseShellRule,
  pastebinRule,
  ngrokRule,
  overlongLineRule,
  base32ExfilRule,
  // additional
  reduceMethodRule,
  systemInReduceRule,
  insecureTempFileRule,
  assertSideEffectRule,
  sqlInjectionRule,
  importlibReloadRule,
  // extra
  randomSeedFrozenRule,
  jwtNoneAlgRule,
  sslVerifyFalseRule,
  xmlExternalEntityRule,
  devModeInProdRule,
  evalGetattrRule,
  // round 4
  subprocessWithoutCaptureRule,
  globalVariableRule,
  socketServerRule,
  importHijackRule,
  dangerousYakRule,
  tempfileRaceRule,
  itertoolsSteganographyRule,
  platformInfoRule,
  strToBytesRule,
];

export const RULE_COUNT = RULES.length;
