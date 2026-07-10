import type { DetectionRule, ScanContext, RawMatch } from "./types";

/**
 * Enterprise hardening rules — sophisticated real-world backdoor techniques
 * that evade naive regex scanners. These cover:
 *  - DNS / ICMP / WebSocket covert C2 channels
 *  - In-memory / reflective code loading (marshal, code objects, mmap)
 *  - Polymorphic & staged payloads (AES + base64 droppers)
 *  - Environment / time / VM-aware activation triggers
 *  - Process injection primitives (ctypes VirtualAllocEx, WriteProcessMemory)
 *  - Living-off-the-land binaries (certutil, bitsadmin, msiexec)
 *  - Steganographic payload extraction (PIL pixel reads)
 *  - Windows registry / scheduled-task persistence
 *  - Covert stdin/stdout channel hijack
 *  - Hardcoded IP C2 (no DNS, harder to block)
 *
 * All patterns are matched line-by-line against the source. They are inert
 * detection signatures — they do not execute anything.
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
    let inS = false;
    let inD = false;
    let code = raw;
    for (let j = 0; j < raw.length; j++) {
      const c = raw[j];
      if (c === "'" && !inD) inS = !inS;
      else if (c === '"' && !inS) inD = !inD;
      else if (c === "#" && !inS && !inD) {
        code = raw.slice(0, j);
        break;
      }
    }
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

const has = (ctx: ScanContext, ...names: string[]) =>
  names.some((n) => ctx.imports.has(n) || ctx.fromImports.has(n));

// ---------------------------------------------------------------------------
// ENT-001: marshal.loads() of bytecode — classic obfuscated payload dropper
// ---------------------------------------------------------------------------
const marshalLoadRule: DetectionRule = {
  id: "PY-ENT-001",
  title: "marshal.loads() of serialized bytecode (obfuscated payload)",
  severity: "critical",
  category: "obfuscation",
  description:
    "marshal.loads() deserializes Python code objects from a binary blob. Attackers base64/decode a marshalled code object at runtime and exec it, hiding the real payload from static string greps. This is one of the most common techniques in Python web shells and droppers because the malicious code never appears as plaintext source.",
  remediation:
    "Do not load marshal'd code from untrusted or embedded data. If legitimate (e.g. cached bytecode), ensure the source is integrity-protected with a signature and the key is not co-located with the payload.",
  references: ["CWE-912", "CWE-502", "OWASP A08:2021"],
  match: (ctx) => scanLines(ctx, /\bmarshal\.loads?\s*\(/, { minConfidence: 0.88 }),
};

// ---------------------------------------------------------------------------
// ENT-002: types.CodeType() construction — hand-built code objects
// ---------------------------------------------------------------------------
const codeTypeRule: DetectionRule = {
  id: "PY-ENT-002",
  title: "Manual construction of types.CodeType (code object forgery)",
  severity: "critical",
  category: "obfuscation",
  description:
    "Building a code object directly via types.CodeType(...) bypasses the normal compile pipeline and lets an attacker assemble executable bytecode from numeric constants — completely invisible to source-level review. Used in advanced packers and reflective loaders.",
  remediation:
    "Remove the code object construction. If this is a legitimate JIT/interpreter, isolate it in a sandbox and audit the bytecode source.",
  references: ["CWE-912", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(ctx, /types\.CodeType\s*\(|CodeType\s*\(/, { minConfidence: 0.82 }),
};

// ---------------------------------------------------------------------------
// ENT-003: ctypes process injection primitives (Windows)
// ---------------------------------------------------------------------------
const ctypesInjectionRule: DetectionRule = {
  id: "PY-ENT-003",
  title: "ctypes process-injection API (VirtualAllocEx / WriteProcessMemory / CreateRemoteThread)",
  severity: "critical",
  category: "code-execution",
  description:
    "These Win32 APIs are the canonical process-injection triad: allocate memory in another process, write shellcode into it, then force that process to execute it via CreateRemoteThread. Any Python script calling them is almost certainly a shellcode loader or process hollowing tool.",
  remediation:
    "Remove the injection code. If you genuinely need cross-process memory access for debugging, use a supported debugger API and restrict it to dev tooling.",
  references: ["CWE-912", "CWE-1235", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|QueueUserAPC|SetThreadContext)\b/,
      { minConfidence: 0.92 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-004: DNS exfiltration channel (dnspython / dnslib)
// ---------------------------------------------------------------------------
const dnsExfilRule: DetectionRule = {
  id: "PY-ENT-004",
  title: "DNS tunneling / exfiltration primitive",
  severity: "high",
  category: "exfiltration",
  description:
    "Encoding stolen data into DNS query subdomains (e.g. <data>.exfil.evil.com) is a common covert exfiltration channel because DNS is rarely blocked and blends with normal traffic. dnslib / dnspython are abused to craft raw DNS packets or to encode chunked data into query names.",
  remediation:
    "Do not embed arbitrary data into DNS query names. If you need DNS resolution, use socket.getaddrinfo() for individual hostnames and never loop over data-chunked subdomains.",
  references: ["CWE-200", "OWASP A05:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /\bdnslib\b|\bdnspython\b|\bdns\.resolver\b|\bdns\.message\.make_query\b|\.resolver\.resolve\s*\([^)]*['\"][a-z0-9+/%]{16,}/,
      { minConfidence: 0.8 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-005: AES + base64 staged payload (encrypted dropper)
// ---------------------------------------------------------------------------
const aesDropperRule: DetectionRule = {
  id: "PY-ENT-005",
  title: "Encrypted + base64 staged payload (AES dropper)",
  severity: "critical",
  category: "obfuscation",
  description:
    "Decrypting a base64 blob with AES (often a hardcoded key) then exec'ing the result is the textbook staged-payload pattern. The real malicious code is invisible to static review — only the decryptor + ciphertext are visible. Combined with exec/eval/compile this is a near-certain backdoor.",
  remediation:
    "Remove the staged decrypt-and-exec pattern. If you ship encrypted code, decrypt it at build/install time, not at runtime, and never exec decrypted strings.",
  references: ["CWE-912", "OWASP A08:2021"],
  match: (ctx) => {
    if (!(has(ctx, "Crypto") || has(ctx, "Cryptodome") || has(ctx, "cryptography"))) {
      // still flag if AES/Cipher appears inline
    }
    return scanLines(
      ctx,
      /\.decrypt\s*\([^)]*\)\s*\)\s*$|AES\.new|Fernet\(|Cipher\(|\.decrypt\s*\(.*\)\s*\.\s*decode/,
      { minConfidence: 0.82 }
    );
  },
};

// ---------------------------------------------------------------------------
// ENT-006: Environment-aware activation trigger (hostname/username/env key)
// ---------------------------------------------------------------------------
const envTriggerRule: DetectionRule = {
  id: "PY-ENT-006",
  title: "Environment-keyed backdoor activation trigger",
  severity: "high",
  category: "suspicious-pattern",
  description:
    "Checking a specific hostname, username, or environment variable before arming the payload is a classic dormancy trigger — the backdoor stays inert on analyst machines and only fires on the intended victim. Common triggers: os.environ.get('SECRET'), platform.node() == '...', getpass.getuser() in [...].",
  remediation:
    "Remove the environment-gated branch. Legitimate feature flags should use a documented configuration system, not opaque environment checks paired with exec/network/subprocess calls.",
  references: ["CWE-912", "CWE-1019", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /platform\.node\(\)\s*==|getpass\.getuser\(\)\s*(==|in)\s*|os\.environ\.get\(\s*['\"](?:SECRET|DEBUG|BACKDOOR|ARM|PAYLOAD|TRIGGER|ENABLE)/i,
      { minConfidence: 0.78 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-007: Time-based evasion (day-of-week / hour gating)
// ---------------------------------------------------------------------------
const timeEvasionRule: DetectionRule = {
  id: "PY-ENT-007",
  title: "Time-based activation gate (evasion)",
  severity: "medium",
  category: "anti-analysis",
  description:
    "Gating malicious behavior on datetime.now().hour or weekday() is a sandbox-evasion technique: the payload only runs during business hours or on a specific day, defeating automated detonation in sandboxes that snapshot a fixed time.",
  remediation:
    "Remove the time gate. If this is legitimate scheduling, use a proper cron/scheduler library, not an inline if-statement around datetime.now().",
  references: ["CWE-912", "CWE-1019"],
  match: (ctx) =>
    scanLines(
      ctx,
      /datetime\.(now|utcnow)\(\)\.(hour|weekday|minute|second)\s*(==|<|>|<=|>=|in)\s*\d/,
      { minConfidence: 0.72 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-008: VM / sandbox detection
// ---------------------------------------------------------------------------
const vmDetectRule: DetectionRule = {
  id: "PY-ENT-008",
  title: "Virtual machine / sandbox fingerprinting",
  severity: "high",
  category: "anti-analysis",
  description:
    "Checking CPU count, RAM size, MAC address OUI, or registry keys for VMware/VirtualBox/QEMU signatures is the hallmark of sandbox-aware malware. The payload exits or behaves benignly when an analyst's VM is detected.",
  remediation:
    "Remove the fingerprinting logic. Production code should never need to detect whether it runs in a VM.",
  references: ["CWE-912", "CWE-1019", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /os\.cpu_count\(\)\s*[<>=]|psutil\.virtual_memory|08:00:27:|00:0C:29:|00:50:56:|VMware|VirtualBox|vbox|sandboxie|SxS.dll.*IsDebuggerPresent/i,
      { minConfidence: 0.8 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-009: Debugger detection (sys.gettrace)
// ---------------------------------------------------------------------------
const debuggerRule: DetectionRule = {
  id: "PY-ENT-009",
  title: "Debugger presence detection",
  severity: "medium",
  category: "anti-analysis",
  description:
    "sys.gettrace() returns the global debug trace function; if it is non-None a debugger (pdb, coverage tools, some sandboxes) is attached. Backdoors use this to skip the malicious branch when being analysed. Checking threading.settrace alongside raises the suspicion further.",
  remediation:
    "Remove the debugger check. Legitimate code never needs to detect whether it is being debugged.",
  references: ["CWE-912", "CWE-1019"],
  match: (ctx) =>
    scanLines(ctx, /sys\.gettrace\(\)|threading\.settrace|sys\._current_frames\(\)/, {
      minConfidence: 0.78,
    }),
};

// ---------------------------------------------------------------------------
// ENT-010: Living-off-the-land binaries (certutil, bitsadmin, msiexec)
// ---------------------------------------------------------------------------
const lolbinRule: DetectionRule = {
  id: "PY-ENT-010",
  title: "Living-off-the-land (LotL) binary invocation",
  severity: "high",
  category: "command-execution",
  description:
    "certutil.exe -decode, bitsadmin /transfer, msiexec /i http..., and regsvr32 /s /u /i:http are signed Windows binaries routinely abused to download, decode, or execute payloads without dropping custom tooling. Their presence in a Python script is a strong indicator of a dropper.",
  remediation:
    "Use the native Python equivalents (urllib, requests) for downloads and standard installers for MSI packages. Never shell out to certutil/bitsadmin for arbitrary URLs.",
  references: ["CWE-78", "CWE-912", "OWASP A03:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /\bcertutil\b|\bbitsadmin\b|\bmsiexec\b\b|\bregsvr32\b|\bmshta\b|\bwscript\b|\bcscript\b|\bpowercfg\b/i,
      { minConfidence: 0.85 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-011: Steganographic payload extraction (PIL pixel reads)
// ---------------------------------------------------------------------------
const stegoRule: DetectionRule = {
  id: "PY-ENT-011",
  title: "Steganographic payload extraction from image pixels",
  severity: "high",
  category: "obfuscation",
  description:
    "Reading LSBs (least significant bits) from PIL pixel data and reassembling them into a byte string is a classic steganographic payload-extraction technique. The malicious code is hidden inside a benign-looking image file, evading content-based inspection.",
  remediation:
    "Do not extract executable payloads from image pixels. If this is a legitimate steganography tool, it should not feed the extracted bytes into exec/eval/compile.",
  references: ["CWE-912", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /\.getpixel\s*\(|\.load\(\)\s*\[|Image\.open\s*\([^)]*\)\.(?:convert|load)|LSB|lsb_extract|\.tobytes\(\)\s*$/i,
      { minConfidence: 0.7 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-012: Hardcoded IP C2 (no DNS — harder to block / sinkhole)
// ---------------------------------------------------------------------------
const hardcodedIpRule: DetectionRule = {
  id: "PY-ENT-012",
  title: "Hardcoded IP address as network endpoint (C2 candidate)",
  severity: "high",
  category: "network",
  description:
    "Connecting directly to a hardcoded IP address (instead of a domain) is common in backdoors because it cannot be sinkholed via DNS or rotated via fast-flux. Look for socket.connect to a literal IP, or requests/urllib to http://<ip>/ paths.",
  remediation:
    "Use a configurable, documented hostname instead of a hardcoded IP. If an IP is required for a specific deployment, load it from an external config file.",
  references: ["CWE-912", "CWE-749", "OWASP A05:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /(?:connect|requests\.(get|post|put)|urlopen|urllib)\s*\(\s*['\"]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|['\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['\"]\s*,\s*\d{2,5}\s*\)/,
      { minConfidence: 0.8 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-013: WebSocket C2 channel
// ---------------------------------------------------------------------------
const websocketC2Rule: DetectionRule = {
  id: "PY-ENT-013",
  title: "WebSocket command-and-control channel",
  severity: "high",
  category: "network",
  description:
    "websocket / websockets libraries are increasingly used for C2 because the channel is persistent, bidirectional, and blends with legitimate web traffic. A long-lived on_message handler that exec's received data is a textbook C2 implant.",
  remediation:
    "Do not exec/eval data received over a WebSocket. If you need a command channel, define a strict JSON command schema and dispatch through an allow-list of handlers.",
  references: ["CWE-912", "CWE-94", "OWASP A03:2021"],
  match: (ctx) =>
    has(ctx, "websocket", "websockets", "websocket_client")
      ? scanLines(ctx, /websocket|on_message|ws\.recv|ws\.send|WebSocketApp|run_forever/, {
          minConfidence: 0.75,
        })
      : scanLines(ctx, /WebSocketApp|websocket\.create_connection|run_forever\s*\(\s*\)/, {
          minConfidence: 0.78,
        }),
};

// ---------------------------------------------------------------------------
// ENT-014: mmap executable code loading
// ---------------------------------------------------------------------------
const mmapExecRule: DetectionRule = {
  id: "PY-ENT-014",
  title: "mmap-backed executable memory",
  severity: "high",
  category: "code-execution",
  description:
    "Mapping a file or anonymous region with PROT_EXEC and then jumping into it (via ctypes function pointer) is the POSIX equivalent of VirtualAllocEx — it lets an attacker run shellcode directly from memory without writing it to disk.",
  remediation:
    "Remove the executable mmap. If this is a JIT compiler, it must be heavily sandboxed and the executable pages must be generated from a trusted compiler, not attacker data.",
  references: ["CWE-912", "CWE-1235", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(ctx, /mmap\.mmap\s*\(|PROT_EXEC|MAP_ANONYMOUS.*PROT_EXEC|c_char_p.*cast.*CFUNCTYPE/, {
      minConfidence: 0.82,
    }),
};

// ---------------------------------------------------------------------------
// ENT-015: Windows registry persistence (winreg Run keys / services)
// ---------------------------------------------------------------------------
const registryPersistRule: DetectionRule = {
  id: "PY-ENT-015",
  title: "Windows registry persistence (Run / RunOnce / services)",
  severity: "critical",
  category: "persistence",
  description:
    "Writing to HKCU/HKLM\\...\\Run or \\RunOnce ensures the payload re-executes on every login or boot. winreg.SetValueEx is the Python primitive. Combined with a dropped payload path this is full host persistence.",
  remediation:
    "Do not write to the Run / RunOnce / Explorer\\Run keys from application code. Use the OS's documented autostart mechanisms (Task Scheduler, services) with explicit user consent.",
  references: ["CWE-912", "CWE-1019", "OWASP A05:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /winreg\.SetValueEx|HKEY_(LOCAL_MACHINE|CURRENT_USER)\\\\?Software\\\\?(Microsoft\\\\Windows\\\\CurrentVersion\\\\)?Run|CreateKeyEx?\s*\([^)]*Run/i,
      { minConfidence: 0.88 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-016: Covert stdin/stdout channel hijack for reverse shells
// ---------------------------------------------------------------------------
const stdioHijackRule: DetectionRule = {
  id: "PY-ENT-016",
  title: "stdin/stdout/stderr dup2 to socket (reverse shell)",
  severity: "critical",
  category: "reverse-shell",
  description:
    "Redirecting file descriptors 0/1/2 to a socket via os.dup2 is the canonical Python reverse shell. After the dup2 calls, subprocess.call(['sh']) or os.system('sh') gives the remote attacker an interactive shell over the socket.",
  remediation:
    "Remove the dup2-to-socket redirection. If you need remote shell access for administration, use SSH with key-based auth, not a hand-rolled socket shell.",
  references: ["CWE-912", "CWE-78", "OWASP A03:2021"],
  match: (ctx) =>
    scanLines(ctx, /os\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*[012]\s*\)|dup2\s*\(\s*\w+\s*,\s*[012]\s*\)/, {
      minConfidence: 0.9,
    }),
};

// ---------------------------------------------------------------------------
// ENT-017: ICMP tunneling
// ---------------------------------------------------------------------------
const icmpTunnelRule: DetectionRule = {
  id: "PY-ENT-017",
  title: "Raw ICMP socket (tunneling / covert channel)",
  severity: "high",
  category: "network",
  description:
    "Opening a raw socket with socket.IPPROTO_ICMP and crafting ping packets by hand is the basis of ICMP tunneling — exfiltrating data inside echo-request payloads, which most firewalls allow outbound.",
  remediation:
    "Do not craft raw ICMP packets. If you need ping functionality, use subprocess to call the system ping binary, or a vetted library.",
  references: ["CWE-912", "CWE-200", "OWASP A05:2021"],
  match: (ctx) =>
    scanLines(ctx, /IPPROTO_ICMP|socket\.AF_PACKET|ICMP_ECHO_REQUEST|socket\.IPPROTO_RAW/, {
      minConfidence: 0.85,
    }),
};

// ---------------------------------------------------------------------------
// ENT-018: Multi-layer encoding chains (base64 + rot13 + hex)
// ---------------------------------------------------------------------------
const multiLayerEncodingRule: DetectionRule = {
  id: "PY-ENT-018",
  title: "Multi-layer encoding chain (obfuscation)",
  severity: "high",
  category: "obfuscation",
  description:
    "Chaining codecs (base64 → rot13 → hex → zlib → ...) before exec is a layering technique to defeat static signatures. Each layer peels off one encoding; the innermost is the real payload. The presence of codecs.decode(..., 'rot_13') or bytes.fromhex inside a chain feeding exec is a strong backdoor signal.",
  remediation:
    "Flatten the encoding. Ship the real source as a module and import it. If you need transport obfuscation, do it at the network layer (TLS), not by layering codecs in source.",
  references: ["CWE-912", "CWE-1019", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /codecs\.decode\s*\([^)]*,\s*['\"]rot_?13['\"]|bytes\.fromhex\s*\([^)]*\)\.decode|\.decode\(['\"]hex['\"]\)|codecs\.decode\(.*,\s*['\"]unicode_escape['\"]\)/,
      { minConfidence: 0.8 }
    ),
};

// ---------------------------------------------------------------------------
// ENT-019: Reading /proc/self/mem or ptrace (memory introspection)
// ---------------------------------------------------------------------------
const procMemRule: DetectionRule = {
  id: "PY-ENT-019",
  title: "Reading /proc/self/mem or ptrace (memory introspection)",
  severity: "medium",
  category: "anti-analysis",
  description:
    "Opening /proc/self/mem or calling ptrace is used by packers to modify their own in-memory image at runtime — overwriting strings, unpacking code, or detecting debuggers (ptrace returns EAGAIN if a debugger is already attached on Linux).",
  remediation:
    "Remove the /proc/self/mem access and ptrace calls. These are not used by normal application code.",
  references: ["CWE-912", "CWE-1019"],
  match: (ctx) =>
    scanLines(ctx, /\/proc\/self\/mem|ptrace|PTRACE_TRACEME|\/proc\/self\/maps/, {
      minConfidence: 0.82,
    }),
};

// ---------------------------------------------------------------------------
// ENT-020: Executing a fetched-then-evaluated HTTP payload (fileless)
// ---------------------------------------------------------------------------
const filelessRule: DetectionRule = {
  id: "PY-ENT-020",
  title: "Fileless execution of a fetched HTTP payload",
  severity: "critical",
  category: "code-execution",
  description:
    "urllib.request.urlopen(...).read() piped into exec() is the fileless-dropper signature: the payload is never written to disk, so disk-based AV never sees it. The URL is often a paste site, a compromised web server, or a CDN-fronted C2.",
  remediation:
    "Never exec remote-fetched code. If you need plugin loading, download to a temp file, verify a signature, and import it as a module — do not exec a string.",
  references: ["CWE-912", "CWE-94", "OWASP A03:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /exec\s*\(\s*(?:urlopen|requests\.|urllib)\b|exec\s*\(\s*\w+\.read\(\)\s*\)|exec\s*\(\s*\w+\.text\s*\)/,
      { minConfidence: 0.88 }
    ),
};

export const RULES_ENTERPRISE: DetectionRule[] = [
  marshalLoadRule,
  codeTypeRule,
  ctypesInjectionRule,
  dnsExfilRule,
  aesDropperRule,
  envTriggerRule,
  timeEvasionRule,
  vmDetectRule,
  debuggerRule,
  lolbinRule,
  stegoRule,
  hardcodedIpRule,
  websocketC2Rule,
  mmapExecRule,
  registryPersistRule,
  stdioHijackRule,
  icmpTunnelRule,
  multiLayerEncodingRule,
  procMemRule,
  filelessRule,
];
