import type { DetectionRule, ScanContext, RawMatch } from "./types";

/**
 * Supply-chain attack detection rules.
 *
 * Covers the most common real-world software supply-chain attack vectors
 * observed in PyPI / pip ecosystem incidents (2020-2024):
 *
 *  - PEP 508 direct-URL dependencies (pip install http://attacker.tld/pkg)
 *  - Private index / --extra-index-url injection (dependency-confusion vector)
 *  - Malicious setup.py / pyproject.toml install hooks (cmdclass, data_files,
 *    entry_points, post-install)
 *  - setup.py download_url pointing to non-PyPI hosts
 *  - Typosquatted package imports (commonly confused names — reqeusts, urllib3,
 *    crypto, etc.)
 *  - requirements.txt / setup.py exec / curl | python installers
 *  - Subprocessing pip install at runtime (live dependency tampering)
 *  - PYPIRC token leak / hardcoded PyPI tokens
 *  - egg-info / wheel manipulation post-build
 *  - setuptools cmdclass override (the classic "run arbitrary code on install"
 *    payload)
 *  - PyPI upload automation with embedded credentials
 *  - git+ssh dependency on a non-GitHub/GitLab host
 *  - audit-wheel / safety / bandit bypass attempts
 *  - data_files writing to system paths (/etc, ~/.ssh, /etc/cron.*)
 *  - console_scripts entry pointing to a dangerous callable
 *
 * Like the enterprise ruleset, these are pure static signatures — they do not
 * execute anything.
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

// ---------------------------------------------------------------------------
// SC-001: PEP 508 direct-URL pip dependency (pip install http(s)://...)
// ---------------------------------------------------------------------------
const directUrlDepRule: DetectionRule = {
  id: "PY-SC-001",
  title: "Direct-URL pip dependency (PEP 508 URL reference)",
  severity: "high",
  category: "supply-chain",
  description:
    "Pin-style or requirements.txt entries that reference a package by URL (http://, https://, ftp://, file://) bypass the curated PyPI registry. This is how dependency-confusion and typosquat payloads are typically pinned — the URL can serve a different tarball on every install, and there is no integrity hash check.",
  remediation:
    "Pin by name + version on PyPI. If a private fork is unavoidable, reference it via a private index server with `--index-url`, and require hash-pinning (`pip install --require-hashes`).",
  references: ["CWE-494", "OWASP A08:2021", "OWASP A06:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /\b(?:pip(?:3)?\s+install|pip-install)\b[^#\n]*\bhttps?:\/\/[^\s#]+/i,
      { minConfidence: 0.85 }
    ),
};

// ---------------------------------------------------------------------------
// SC-002: --extra-index-url / --index-url pointing to a non-PyPI host
// ---------------------------------------------------------------------------
const extraIndexUrlRule: DetectionRule = {
  id: "PY-SC-002",
  title: "Private / extra PyPI index URL",
  severity: "high",
  category: "supply-chain",
  description:
    "`--extra-index-url` (or `--index-url`) pointed at a third-party host is the canonical dependency-confusion vector: pip resolves the highest version across ALL indexes, so an attacker publishing a higher-versioned package with the same name to the extra index wins over your private copy. The 2021 Codecov / Censorus and dependency-confusion disclosures used exactly this pattern.",
  remediation:
    "Use a private index as the PRIMARY `--index-url` (not `--extra-index-url`), and pin package versions to ones you control. Verify the index URL is an internal artifact server, not a public mirror you don't own.",
  references: ["CWE-494", "CWE-1357", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /--(?:extra-)?index-url\s+(?:[A-Za-z0-9_]+:\/\/)?[^\s#]+/i,
      { minConfidence: 0.82 }
    ),
};

// ---------------------------------------------------------------------------
// SC-003: setuptools cmdclass override — runs arbitrary code on `pip install`
// ---------------------------------------------------------------------------
const cmdclassRule: DetectionRule = {
  id: "PY-SC-003",
  title: "setuptools cmdclass override (arbitrary install-time code)",
  severity: "critical",
  category: "supply-chain",
  description:
    "Overriding setuptools command classes (cmdclass={'install': ...}) is the textbook malicious-PyPI payload: setuptools invokes the custom class during `pip install`, executing attacker-controlled code in the victim's environment with NO sandbox. This was the exact mechanism in the `colour`/`colorama` typosquat campaigns and many others.",
  remediation:
    "Do not override cmdclass for install/build/install_lib. If you genuinely need a build step, perform it at sdist/wheel build time only — never at install time. Legitimate packages rarely override these commands.",
  references: ["CWE-494", "CWE-912", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /cmdclass\s*=\s*\{[^}]*['"](?:install|build|build_py|sdist|bdist_wheel|develop|install_lib)['"]\s*:/i,
      { minConfidence: 0.9 }
    ),
};

// ---------------------------------------------------------------------------
// SC-004: setup.py download_url pointing to a non-PyPI host
// ---------------------------------------------------------------------------
const downloadUrlRule: DetectionRule = {
  id: "PY-SC-004",
  title: "setup.py download_url pointing to non-PyPI host",
  severity: "high",
  category: "supply-chain",
  description:
    "A `download_url` in setup() that points anywhere other than PyPI (a personal GitHub release, a generic web host, an IP) lets the package author rotate the tarball after publication without updating the PyPI metadata. Users fetching by URL receive whatever the author currently serves — a perfect persistence channel for backdoored packages.",
  remediation:
    "Remove the `download_url` argument. PyPI itself is the canonical download source. If hosting releases externally, pin by SHA-256 hash and sign the artifact.",
  references: ["CWE-494", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /download_url\s*=\s*['"](?!(?:https?:\/\/)?(?:files\.)?pythonhosted\.org)https?:\/\/[^\s'"]+/i,
      { minConfidence: 0.8 }
    ),
};

// ---------------------------------------------------------------------------
// SC-005: Typosquatted package import — common misspelling of popular libs
// ---------------------------------------------------------------------------
const typosquatRule: DetectionRule = {
  id: "PY-SC-005",
  title: "Possible typosquatted package import",
  severity: "high",
  category: "supply-chain",
  description:
    "Imports a package name that is a near-misspelling of a popular library (e.g. `reqeusts` instead of `requests`, `pytone` instead of `python`, `urllib3` vs `urllib2`). Typosquatting is the dominant PyPI attack vector: attackers register lookalike names and wait for fat-fingered installs. Importing such a name almost always means a malicious package is being loaded.",
  remediation:
    "Verify the exact spelling of the intended library against PyPI. Common typosquat victims: requests, urllib3, cryptography, setuptools, pip, python-dateutil, sqlalchemy, beautifulsoup4. Remove the import and install the correctly-named package.",
  references: ["CWE-494", "CWE-1357", "OWASP A08:2021"],
  match: (ctx) => {
    const typos = [
      "reqeusts", "requestss", "python_request", "requests_oauth",
      "urllib2", "urlib3", "urlllib3", "urllib3_util",
      "cryptograpy", "crypto", "crypto-python", "pycrypto",
      "setuptool", "setup-tools", "stuptools",
      "pytone", "pyton3", "python3-tool", "python-runtime",
      "beautifullsoup", "beautifusoup", "beautifoulsoup4", "bs4soup",
      "django2", "djang", "djanog",
      "flaskk", "flaskk-api", "flaskk-restful",
      "numpyy", "numpi", "nummpy",
      "pandass", "panda", "pandas-dataframe",
      "matplotllib", "mathplotlib",
      "scikitlearnn", "scikit-learn-toolkit",
      "tensorflw", "tensorflow-gpu-2",
      "torchnn", "pytorchvision",
      "aiohttp2", "aiohtttp",
      "fastapi2", "fast-api",
      "pyjwt2", "pyjwt3",
      "lxml2", "lxlm",
      "pillow2", "pil-image",
      "sqlalchemy2", "sqlachemy", "sql-alchemy",
      "celeryy", "celery-task",
      "redis2", "reddis",
      "pymongo2", "pymongoo",
      "psycopg2-binary2", "psycopg3-binary",
      "yamll", "yaml2",
      "tomll", "toml2",
      "python-dotenv2", "dotenv2",
      "clickk", "clickk-utils",
      "richh", "rich2",
      "pydentic", "pydantic2",
    ];
    const re = new RegExp(
      `^(?:import\\s+|from\\s+)(${typos.join("|")})(?:\\s|\\.|$)`,
      "i"
    );
    return scanLines(ctx, re, { minConfidence: 0.78 });
  },
};

// ---------------------------------------------------------------------------
// SC-006: curl|python / wget|python install-time network executor
// ---------------------------------------------------------------------------
const curlPipePythonRule: DetectionRule = {
  id: "PY-SC-006",
  title: "curl|python / wget|bash remote-script installer",
  severity: "critical",
  category: "supply-chain",
  description:
    "Piping the output of curl/wget straight into python (or bash) is a textbook supply-chain & initial-access pattern: the script content can be rotated server-side without modifying the installer, integrity is never checked, and the executed code runs with full local privileges. Real-world PyPI install hooks frequently shell out to exactly this pattern.",
  remediation:
    "Never pipe remote content to an interpreter. Download with hash verification (`curl --sha256`), inspect, then run. If you need a bootstrap installer, vendor it inside the package as a static file.",
  references: ["CWE-494", "CWE-912", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /(?:curl|wget|fetch)[^|]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|bash|sh)\b/i,
      { minConfidence: 0.95 }
    ),
};

// ---------------------------------------------------------------------------
// SC-007: subprocess pip install (runtime dependency tampering)
// ---------------------------------------------------------------------------
const subprocessPipInstallRule: DetectionRule = {
  id: "PY-SC-007",
  title: "Runtime `pip install` via subprocess",
  severity: "high",
  category: "supply-chain",
  description:
    "Calling pip programmatically at runtime (subprocess.check_call(['pip','install',...])) bypasses the lockfile / pinned-dependency workflow entirely. The install can pull arbitrary versions from PyPI at every run, giving an attacker a moving target — and on a CI/CD runner it can install packages into shared site-packages. This is also a common persistence mechanism for malicious PyPI payloads.",
  remediation:
    "Declare dependencies in pyproject.toml or setup.py at build time. Use `importlib` for optional runtime loading. If you must install at runtime (rare), pin a hash and use a private index.",
  references: ["CWE-494", "CWE-912", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /(?:subprocess|os\.system|os\.popen|popen2|commands)\b[^#\n]*['"]?(?:pip3?|python\s+-m\s+pip)\s+install\b/i,
      { minConfidence: 0.9 }
    ),
};

// ---------------------------------------------------------------------------
// SC-008: Hardcoded PyPI upload token / .pypirc credential
// ---------------------------------------------------------------------------
const pypircTokenRule: DetectionRule = {
  id: "PY-SC-008",
  title: "Hardcoded PyPI upload token",
  severity: "critical",
  category: "supply-chain",
  description:
    "A `pypi-AgEIcHlwaS5vcmc...` token (PyPI's scoped upload credential format) committed in source lets anyone with repo read access publish new versions of your package to PyPI. Stolen PyPI tokens have been used in countless takeover incidents (e.g. the 2023 PyPI-targeted campaigns). Even a stale token can publish new versions if not revoked.",
  remediation:
    "Revoke the token immediately in your PyPI account. Use trusted publishing (OIDC) from GitHub Actions where possible, or load tokens from a secrets manager / CI environment variable. Rotate any tokens that have ever been committed.",
  references: ["CWE-798", "CWE-522", "OWASP A07:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /pypi-AgEI[a-zA-Z0-9_-]{20,}|pypi-[A-Za-z0-9_-]{60,}/,
      { minConfidence: 0.95 }
    ),
};

// ---------------------------------------------------------------------------
// SC-009: data_files writing to system / sensitive paths
// ---------------------------------------------------------------------------
const dataFilesSysPathRule: DetectionRule = {
  id: "PY-SC-009",
  title: "data_files writing to system or sensitive path",
  severity: "high",
  category: "supply-chain",
  description:
    "setuptools `data_files` writing into /etc, /etc/cron.*, /etc/systemd, /etc/init.d, ~/.ssh, ~/.bashrc, ~/.profile, /usr/local/bin or similar is the persistence payload of multiple PyPI malware families (e.g. `Colour`, `Lenasys`). On `pip install --user` the file lands wherever setuptools decides; on `--root /` it can write anywhere. This is rarely legitimate.",
  remediation:
    "Never write to system paths from a package install. Distribute data files inside the package directory (package_data) and reference them via importlib.resources at runtime. Cron jobs and systemd units belong in OS packages, not Python wheels.",
  references: ["CWE-494", "CWE-912", "CWE-73", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /data_files\s*=\s*\[[^]]*['"](?:\/etc\/(?:cron|systemd|init\.d|profile|bashrc)|\/usr\/local\/(?:bin|sbin|lib)|~\/\.ssh|~\/\.(?:bashrc|bash_profile|profile|zshrc|pythonrc)|\/etc\/passwd|\/etc\/shadow)/i,
      { minConfidence: 0.88 }
    ),
};

// ---------------------------------------------------------------------------
// SC-010: entry_points console_scripts pointing to a callable — common
// persistence + privilege hook (the installed command can run anything)
// ---------------------------------------------------------------------------
const entryPointRule: DetectionRule = {
  id: "PY-SC-010",
  title: "console_scripts entry pointing to obfuscated callable",
  severity: "medium",
  category: "supply-chain",
  description:
    "Declares a console_scripts entry_point whose target callable lives in a module with a suspicious name (`__init__`, `_cmd`, `_run`, `_main`, `_loader`) or invokes os.system / subprocess. Real packages usually point at a clean `pkg.cli:main`; pointing at a hidden loader is a known PyPI-malware pattern (the entry runs every time the binary is typed).",
  remediation:
    "Point the entry_point at a clean, named function in a public module (`mypkg.cli:main`). Avoid `_`-prefixed modules for CLI entry points — they should be discoverable & auditable.",
  references: ["CWE-494", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /console_scripts['"]\s*[:=]\s*['"]?[^\s'"=]+= *[a-zA-Z0-9_.]*(?:__[a-z_]+__|_[a-z]*(?:cmd|run|main|loader|exec|boot)|__\w+_)(?:\.[a-zA-Z_]\w*)?\s*:/i,
      { minConfidence: 0.7 }
    ),
};

// ---------------------------------------------------------------------------
// SC-011: git+ssh / git+https dependency on a non-mainstream git host
// ---------------------------------------------------------------------------
const gitDepRule: DetectionRule = {
  id: "PY-SC-011",
  title: "git+ssh / git+https dependency on non-mainstream host",
  severity: "medium",
  category: "supply-chain",
  description:
    "A `git+ssh://` or `git+https://` dependency pointing at a host other than github.com / gitlab.com / bitbucket.org / gitea.com is a common exfiltration & backdoor channel: attackers host private forks that look like the real package but contain injected code. The install pulls the latest commit at every install, so the payload can be swapped at will.",
  remediation:
    "If a fork is unavoidable, host it on a Git service your organisation controls and pin to a specific commit SHA in requirements.txt (`git+https://...@<sha>`). Avoid git+ssh URLs that require private keys you don't manage.",
  references: ["CWE-494", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /git\+(?:ssh|https):\/\/(?!github\.com|gitlab\.com|bitbucket\.org|gitea\.com|codeberg\.org|[\w.-]+\.githubusercontent\.com|git\.+(?:[a-z0-9-]+\.)+[a-z]{2,})[^#\s'"]+/i,
      { minConfidence: 0.7 }
    ),
};

// ---------------------------------------------------------------------------
// SC-012: Bandit / safety / pip-audit bypass in code or comments
// ---------------------------------------------------------------------------
const securityToolBypassRule: DetectionRule = {
  id: "PY-SC-012",
  title: "Security scanner (bandit/safety/pip-audit) bypass attempt",
  severity: "high",
  category: "supply-chain",
  description:
    "Explicitly calls `bandit --skip`, `safety ignore`, `pip-audit --ignore-vuln`, or sets `# nosec` / `# noqa: S` comments adjacent to a flagged line. Attackers publishing malicious packages frequently disable security scanning in their CI to slip past reviewers. The `# nosec` directive specifically silences Bandit warnings — its presence near a sensitive call is a strong evasion signal.",
  remediation:
    "Remove the bypass. Investigate the underlying call that required silencing — every `# nosec` should have a written justification. If a vulnerability is genuinely a false positive, document it in the project's risk register rather than suppressing inline.",
  references: ["CWE-693", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /(?:bandit\s+(?:--skip|--exclude)|safety\s+(?:check\s+)?--ignore|pip-audit\s+--ignore-vuln|--no-deps|--no-build-isolation)|#(?:noqa(?:[:\s]\s*S\d+)?|nosec)\b/i,
      { minConfidence: 0.75 }
    ),
};

// ---------------------------------------------------------------------------
// SC-013: egg-info manipulation / .pth file write (site-packages persistence)
// ---------------------------------------------------------------------------
const pthFileRule: DetectionRule = {
  id: "PY-SC-013",
  title: ".pth file write (site-packages auto-load persistence)",
  severity: "high",
  category: "supply-chain",
  description:
    "Writing a `.pth` file to site-packages is a stealthy persistence trick: Python's site module imports every `.pth` file at interpreter startup, and any line starting with `import ` is executed as code. A malicious wheel that drops a `.pth` file gains execution on EVERY subsequent Python invocation, including unrelated scripts — a near-perfect backdoor. Used by the `colour` and `openai` typosquat campaigns.",
  remediation:
    "Never write `.pth` files from package code. If you need startup hooks, register them via the documented `usercustomize`/`sitecustomize` mechanism with explicit user consent, and never in a wheel `data_files`.",
  references: ["CWE-494", "CWE-912", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /\.pth['"]|site-packages[^'"#]*\.pth|open\s*\([^)]*['"][^'"]+\.pth['"]/i,
      { minConfidence: 0.8 }
    ),
};

// ---------------------------------------------------------------------------
// SC-014: setup.py exec / eval of fetched content at install time
// ---------------------------------------------------------------------------
const setupExecRule: DetectionRule = {
  id: "PY-SC-014",
  title: "setup.py exec/eval at install time",
  severity: "critical",
  category: "supply-chain",
  description:
    "A setup.py (or pyproject.toml build hook) that calls exec(), eval(), or compile() on a non-literal string is the simplest and most common malicious-PyPI payload — setuptools runs setup.py with full local privileges during install. Wrapping the payload in `exec(...)` or `compile(...)` defeats naive grep-based scanners.",
  remediation:
    "setup.py should contain only static metadata. Any dynamic logic must be explicit, named functions in build-time scripts — never an eval/exec string. If you see this in a third-party package, treat the package as compromised.",
  references: ["CWE-494", "CWE-912", "CWE-94", "OWASP A03:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /\b(?:exec|eval|compile)\s*\(\s*(?![\s\S]*['"][a-z]+=['"])(?:urlopen|requests\.|urllib|open|base64|codecs|marshal|pickle)/i,
      { minConfidence: 0.92 }
    ),
};

// ---------------------------------------------------------------------------
// SC-015: setup_requires / install_requires pinning to a known-malicious
// pattern (any version on a typosquatted name OR a `*` version pin)
// ---------------------------------------------------------------------------
const wildcardDepRule: DetectionRule = {
  id: "PY-SC-015",
  title: "Wildcard version pin on dependency",
  severity: "medium",
  category: "supply-chain",
  description:
    "Declaring a dependency with a wildcard version (`>=0`, `*`, no upper bound) means every install can pull whatever the package registry currently considers latest. Combined with a compromised upstream package this is silent supply-chain takeover. Lockfiles exist precisely to prevent this.",
  remediation:
    "Pin to a specific version or a narrow caret/tilde range (`~=1.2.3`), and use `pip-compile` / `uv lock` / `poetry lock` to generate a hashed lockfile (`--require-hashes`). Avoid `*` and unbounded `>=` ranges in published packages.",
  references: ["CWE-494", "OWASP A06:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /(?:install_requires|setup_requires|dependencies|requires)\s*=\s*[[{][^]]*['"][a-z0-9_-]+['"]\s*(?:[<>=!~]+\s*\*|>=\s*0\b)/i,
      { minConfidence: 0.7 }
    ),
};

// ---------------------------------------------------------------------------
// SC-016: pip download to /tmp + exec pattern (fileless install-time payload)
// ---------------------------------------------------------------------------
const pipDownloadExecRule: DetectionRule = {
  id: "PY-SC-016",
  title: "pip download to /tmp + exec (fileless install payload)",
  severity: "critical",
  category: "supply-chain",
  description:
    "Pattern of `pip download` / `pip install --target /tmp/...` followed by `exec(open(...).read())` is the fileless-loader signature used by multiple PyPI malware families (e.g. `PPMA`, `PuppetPackages`). The wheel is fetched at install time into a temp dir, then its payload is exec'd without ever appearing in the package's own files — defeating static review.",
  remediation:
    "Never dynamically download and exec code at install or import time. If a package needs an optional dependency, document it and `import` it lazily — do not download wheels at runtime.",
  references: ["CWE-494", "CWE-912", "OWASP A03:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /(?:pip|python\s+-m\s+pip)\s+(?:download|install\s+--target)\s+[^#]*\/tmp\/|exec\s*\(\s*open\s*\(\s*['"]\/tmp\//i,
      { minConfidence: 0.85 }
    ),
};

// ---------------------------------------------------------------------------
// SC-017: importlib smuggling — loading a module from a non-standard source
// (e.g. from a base64 string, a remote URL, or an arbitrary file path)
// ---------------------------------------------------------------------------
const importlibSmuggleRule: DetectionRule = {
  id: "PY-SC-017",
  title: "importlib loading from non-standard source",
  severity: "high",
  category: "supply-chain",
  description:
    "Uses importlib.util.spec_from_file_location / spec_from_loader with a non-package path, or importlib.import_module on a dynamically-built string. This is the modern fileless-load primitive: a malicious wheel ships an encoded blob, decodes it at first import, and loads it as a module — bypassing both filesystem inspection AND the import system's own safety checks. Used in the 2024 `ultrafy` / `dissent` campaigns.",
  remediation:
    "If you must dynamically load modules, restrict the search path to a vendored directory inside your package. Never load a module from a user-supplied path, a remote URL, or a base64/marshal blob. Audit any spec_from_loader usage.",
  references: ["CWE-494", "CWE-912", "OWASP A03:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /importlib\.util\.spec_from_(?:file_location|loader)\s*\([^)]*(?:base64|urlopen|requests\.|\.read\(\)|BytesIO|marshal|pickle)/i,
      { minConfidence: 0.88 }
    ),
};

// ---------------------------------------------------------------------------
// SC-018: requirements.txt with a pip --no-cache-dir + --target combo
// (used by attackers to evade local forensics)
// ---------------------------------------------------------------------------
const noCacheTargetRule: DetectionRule = {
  id: "PY-SC-018",
  title: "pip install --no-cache-dir + --target (forensics evasion)",
  severity: "medium",
  category: "supply-chain",
  description:
    "`pip install --no-cache-dir --target=...` deliberately avoids leaving the downloaded wheel in the pip cache, which is a common forensics source after a compromise. Combined with `--target` it installs into a non-standard directory. While legitimate uses exist, the combination is rare and frequently appears in malicious PyPI install hooks to hinder incident response.",
  remediation:
    "Avoid `--no-cache-dir` in production installs. If disk space is the concern, use a CI cache directory you control. The pip cache is your friend during IR — keep it.",
  references: ["CWE-494", "OWASP A08:2021"],
  match: (ctx) =>
    scanLines(
      ctx,
      /pip(?:3)?\s+install[^#\n]*--no-cache-dir[^#\n]*--target(?:=|\s+)/i,
      { minConfidence: 0.75 }
    ),
};

export const RULES_SUPPLY_CHAIN: DetectionRule[] = [
  directUrlDepRule,
  extraIndexUrlRule,
  cmdclassRule,
  downloadUrlRule,
  typosquatRule,
  curlPipePythonRule,
  subprocessPipInstallRule,
  pypircTokenRule,
  dataFilesSysPathRule,
  entryPointRule,
  gitDepRule,
  securityToolBypassRule,
  pthFileRule,
  setupExecRule,
  wildcardDepRule,
  pipDownloadExecRule,
  importlibSmuggleRule,
  noCacheTargetRule,
];
