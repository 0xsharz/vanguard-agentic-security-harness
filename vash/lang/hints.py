# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Language-specific researcher hints + specialist researcher bodies.

Each block is injected into the s4 deep-dive prompt so the researcher gets
language-appropriate "where to look" guidance instead of a generic brief.
Hints are seeds, not checklists — the researcher is told to reason past them.
"""
from __future__ import annotations
import re
from pathlib import Path, PurePosixPath


# ─────────────────────────────────────────────────────────────────────────────
# Extension → language key
# ─────────────────────────────────────────────────────────────────────────────

EXT_TO_LANG: dict[str, str] = {
    ".c": "c-cpp", ".cc": "c-cpp", ".cpp": "c-cpp", ".cxx": "c-cpp",
    ".h": "c-cpp", ".hpp": "c-cpp",
    ".rs": "rust",
    ".go": "go",
    ".py": "python",
    ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".mts": "typescript", ".cts": "typescript",
    ".php": "php",
    ".rb": "ruby",
    ".m": "objective-c", ".mm": "objective-c",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
    ".pl": "perl", ".pm": "perl",
    ".swift": "swift",
    ".scala": "scala", ".sc": "scala",
    ".cbl": "cobol", ".cob": "cobol", ".cpy": "cobol",
    ".jcl": "jcl",
    ".dart": "dart",
    ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang", ".hrl": "erlang",
    ".groovy": "groovy", ".gvy": "groovy", ".gy": "groovy", ".gsh": "groovy",
    ".lua": "lua",
    ".r": "r",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".cmd": "batch", ".bat": "batch",
    # SQL / PL-SQL (Oracle) / T-SQL (SQL Server) — stored procs, packages, dynamic SQL
    ".sql": "sql", ".ddl": "sql", ".dml": "sql", ".tsql": "sql", ".plsql": "sql",
    ".pks": "sql", ".pkb": "sql", ".pls": "sql", ".plb": "sql",
    ".prc": "sql", ".fnc": "sql", ".trg": "sql", ".vw": "sql",
    # Visual Basic / VB.NET / VBA / VBScript (enterprise/finance)
    ".vb": "vbnet", ".bas": "vbnet", ".cls": "vbnet", ".frm": "vbnet", ".vbs": "vbnet",
    # ABAP (SAP)
    ".abap": "abap", ".aba": "abap",
    # Clojure
    ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure", ".edn": "clojure",
    # Haskell
    ".hs": "haskell", ".lhs": "haskell",
    # OCaml
    ".ml": "ocaml", ".mli": "ocaml",
    # F#
    ".fs": "fsharp", ".fsi": "fsharp", ".fsx": "fsharp",
    # Julia
    ".jl": "julia",
    # Solidity (EVM smart contracts)
    ".sol": "solidity",
    # Assembly (x86/x64/ARM — GAS/NASM)
    ".asm": "assembly", ".s": "assembly",
    # Zig
    ".zig": "zig",
    # Nim
    ".nim": "nim", ".nims": "nim",
    # Crystal
    ".cr": "crystal",
    # infrastructure-as-code (specialist `iac` sweeps these — see SPECIALIST_HINTS)
    ".tf": "terraform", ".tfvars": "terraform", ".hcl": "terraform",
    ".bicep": "bicep",
    # web/server templates — XSS / SSTI surface
    ".html": "web-template", ".htm": "web-template",
    ".jsp": "web-template", ".jspx": "web-template", ".jspf": "web-template",
    ".tag": "web-template", ".tagx": "web-template",
    ".aspx": "web-template", ".ascx": "web-template", ".master": "web-template",
    ".cshtml": "web-template", ".vbhtml": "web-template",
    ".phtml": "web-template",
    ".erb": "web-template", ".rhtml": "web-template",
    ".ejs": "web-template",
    ".hbs": "web-template", ".handlebars": "web-template",
    ".mustache": "web-template",
    ".twig": "web-template",
    ".pug": "web-template", ".jade": "web-template",
    ".ftl": "web-template", ".ftlh": "web-template",
    ".vm": "web-template", ".vtl": "web-template",
    ".mako": "web-template",
    ".j2": "web-template", ".jinja": "web-template", ".jinja2": "web-template",
    ".vue": "web-template", ".svelte": "web-template",
    ".liquid": "web-template", ".njk": "web-template",
    ".slim": "web-template", ".haml": "web-template",
}

LANG_DISPLAY: dict[str, str] = {
    "c-cpp": "C/C++", "rust": "Rust", "go": "Go", "python": "Python",
    "java": "Java", "javascript": "JavaScript", "php": "PHP",
    "ruby": "Ruby", "objective-c": "Objective-C", "kotlin": "Kotlin",
    "csharp": "C#/.NET", "perl": "Perl", "swift": "Swift",
    "scala": "Scala", "cobol": "COBOL", "jcl": "JCL (z/OS)",
    "dart": "Dart/Flutter", "elixir": "Elixir", "erlang": "Erlang",
    "groovy": "Groovy", "lua": "Lua", "r": "R",
    "powershell": "PowerShell", "shell": "Shell (bash/sh)",
    "batch": "Windows Batch (.cmd/.bat)",
    "web-template": "Web Templates",
    "ansible": "Ansible",
    "terraform": "Terraform / HCL",
    "bicep": "Azure Bicep",
    "dockerfile": "Dockerfile",
    "jenkins": "Jenkinsfile",
    "github-actions": "GitHub Actions",
    "kubernetes": "Kubernetes / Helm",
    "typescript": "TypeScript",
    "sql": "SQL / PL-SQL / T-SQL",
    "vbnet": "Visual Basic / VB.NET",
    "abap": "ABAP (SAP)",
    "clojure": "Clojure",
    "haskell": "Haskell",
    "ocaml": "OCaml",
    "fsharp": "F#",
    "julia": "Julia",
    "solidity": "Solidity",
    "assembly": "Assembly",
    "zig": "Zig",
    "nim": "Nim",
    "crystal": "Crystal",
}


# ─────────────────────────────────────────────────────────────────────────────
# Path / content sniffing for files the extension map can't classify
# ─────────────────────────────────────────────────────────────────────────────

_ANSIBLE_PATH_RX = re.compile(
    r"(?:^|/)(?:ansible|playbooks?|roles|inventories|group_vars|host_vars)(?:/|$)",
    re.IGNORECASE,
)
_ANSIBLE_BODY_RX = re.compile(
    r"^\s*-?\s*(hosts|tasks|handlers|become|gather_facts|ansible\.[\w.]+)\s*:",
    re.MULTILINE,
)
_COBOL_BODY_RX = re.compile(
    r"IDENTIFICATION\s+DIVISION|PROCEDURE\s+DIVISION|WORKING-STORAGE\s+SECTION"
    r"|^.{0,7}\d{2}\s+\S+.*\bPIC(?:TURE)?\s+[X9SVA]"
    r"|^.{0,7}\d{2}\s+FILLER\b"
    r"|\bCOPY\s+\w+\s*\.",
    re.IGNORECASE | re.MULTILINE,
)
_JCL_BODY_RX = re.compile(
    r"^//\S*\s+(JOB|EXEC|DD|PROC)\b|^//\s*SYSIN\b", re.MULTILINE,
)
_MAINFRAME_PATH_RX = re.compile(
    r"(?:^|/)(?:mvs[_-]?code|jcl|cntl|proclib|cobol|copybooks?|jobs)(?:/|$)",
    re.IGNORECASE,
)

# IaC / CI / container config — filename-based detection (no I/O so safe to
# call from _is_source and gates). Shared by detect_languages, is_iac_file,
# and the `iac` specialist gate in s3.
_DOCKERFILE_NAME_RX = re.compile(
    r"(?:^|/)(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$", re.IGNORECASE,
)
_JENKINSFILE_NAME_RX = re.compile(
    r"(?:^|/)Jenkinsfile(?:\.[\w.-]+)?$", re.IGNORECASE,
)
_GHACTIONS_PATH_RX = re.compile(
    r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$",
)
_K8S_PATH_RX = re.compile(
    r"(?:^|/)(?:k8s|kubernetes|helm|charts?|manifests?|deploy(?:ments?)?)/.+\.(?:ya?ml|tpl)$",
    re.IGNORECASE,
)
_K8S_BODY_RX = re.compile(r"^apiVersion:\s+\S+", re.MULTILINE)
_IAC_PATH_RX = re.compile(
    r"(?:^|/)(?:Dockerfile|Containerfile|Jenkinsfile)(?:\.[\w.-]+)?$"
    r"|(?:^|/)(?:docker-compose(?:[\w.-]*)?|Chart|kustomization"
    r"|\.gitlab-ci|cloudbuild|azure-pipelines|buildspec|appspec|serverless"
    r")\.ya?ml$"
    r"|\.(?:tf|tfvars|hcl|bicep)$"
    r"|(?:^|/)\.github/workflows/[^/]+\.ya?ml$"
    r"|(?:^|/)(?:k8s|kubernetes|helm|charts?|manifests?|deploy(?:ments?)?"
    r"|cloudformation|cfn)/.+\.(?:ya?ml|tpl|json)$"
    r"|(?:^|/)(?:ansible|playbooks?|roles|group_vars|host_vars)/.+\.ya?ml$",
    re.IGNORECASE,
)


def is_iac_file(rel: str) -> bool:
    """Path/filename-only check for Infrastructure-as-Code, CI, and container
    config. No file I/O — safe to call per file from `_is_source` and from
    specialist gates."""
    return bool(_IAC_PATH_RX.search(rel))


def _read_head(repo_root: Path, rel: str, n: int = 4096) -> str:
    try:
        with open(repo_root / rel, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(n)
    except OSError:
        return ""


def _sniff_lang(rel: str, repo_root: Path | None) -> str | None:
    """Classify files the extension map missed (or mis-bucketed as plain
    config). Path-based first; falls back to a head-of-file content probe
    when repo_root is supplied."""
    # IaC by filename/path — Dockerfile / Jenkinsfile have no extension or
    # non-standard suffixes; GitHub Actions live under .github/workflows/.
    if _DOCKERFILE_NAME_RX.search(rel):
        return "dockerfile"
    if _JENKINSFILE_NAME_RX.search(rel):
        return "jenkins"
    if _GHACTIONS_PATH_RX.search(rel):
        return "github-actions"

    suffix = PurePosixPath(rel).suffix.lower()

    if suffix in (".yml", ".yaml"):
        if _ANSIBLE_PATH_RX.search(rel):
            return "ansible"
        if _K8S_PATH_RX.search(rel):
            return "kubernetes"
        if repo_root:
            head = _read_head(repo_root, rel)
            if _ANSIBLE_BODY_RX.search(head):
                return "ansible"
            if _K8S_BODY_RX.search(head):
                return "kubernetes"
        return None

    if suffix:
        return None

    # extension-less: mainframe sources commonly ship as PDS-member dumps
    if _MAINFRAME_PATH_RX.search(rel) and repo_root:
        head = _read_head(repo_root, rel)
        if _JCL_BODY_RX.search(head):
            return "jcl"
        if _COBOL_BODY_RX.search(head):
            return "cobol"
    elif repo_root:
        head = _read_head(repo_root, rel, 1024)
        if _JCL_BODY_RX.search(head):
            return "jcl"
        if _COBOL_BODY_RX.search(head):
            return "cobol"
    return None


def detect_languages(files: list[str],
                     repo_root: Path | str | None = None) -> list[str]:
    """Return ordered list of language keys present in `files`, most common
    first. If `repo_root` is given, extension-less and .yml/.yaml files are
    additionally content-sniffed (COBOL/JCL/Ansible)."""
    root = Path(repo_root) if repo_root else None
    counts: dict[str, int] = {}
    for f in files:
        suffix = PurePosixPath(f).suffix.lower()
        lang = EXT_TO_LANG.get(suffix)
        if lang is None or suffix in (".yml", ".yaml"):
            lang = _sniff_lang(f, root) or lang
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return [k for k, _ in sorted(counts.items(), key=lambda kv: -kv[1])]


# ─────────────────────────────────────────────────────────────────────────────
# Per-language researcher hints
# Each block opens with the shared LEAD line below.
# ─────────────────────────────────────────────────────────────────────────────

LANG_HINTS: dict[str, str] = {
    "c-cpp": """\
Where to look first (non-exhaustive — reason beyond this list):
- Allocation sites (malloc/calloc/realloc/new[]): is the byte count derived
  from external input, and can the arithmetic that produced it wrap?
- Bulk copies (memcpy/memmove/strcpy/strncpy/sprintf/snprintf): does the
  length argument come from the SOURCE data while the destination size is
  fixed elsewhere?
- Every free()/delete: walk the pointer's lifetime — who else holds it, which
  error paths also free it, is it nulled after release?
- Signedness at comparison sites: an `int` length compared against a `size_t`
  capacity, or cast just before the check.
- Any parser/decoder that reads a length/count/offset from the wire or file
  and then trusts it for indexing or copy size.

Easy to miss:
- A product of input-derived dimensions (n * elemSize, w * h * bpp) wraps
  32-bit, allocation succeeds undersized, later writes overflow.
- `len - hdr` style unsigned subtraction when `len < hdr` → huge positive
  index or copy length.
- One pointer freed on the error branch AND again in a shared cleanup label /
  caller destructor — map every route to free(), not just the happy path.
- Shallow struct copy (`a = *b`) where the struct owns heap pointers — both
  copies' destructors release the same block.
- A bounds check that exists but tests the wrong variable, the wrong
  operator (< vs <=), or compares signed against unsigned.
- A stale alias: object freed through one handle while another cached
  reference is still used afterward.
- memset/memcpy with a hard-coded byte count that no longer matches the
  field's actual size after a struct change.""",

    "rust": """\
Where to look first (non-exhaustive — reason beyond this list):
- Every `unsafe { }` block: what invariant does the surrounding safe API
  promise the compiler, and can a caller break it without writing `unsafe`
  themselves?
- Hand-written `Send`/`Sync` impls (or `#[derive]` on types holding `*mut T`
  / `Rc` / interior-mutable cells) — would sharing across threads race?
- FFI (`extern "C"`): who owns the pointer after the call, and does the Rust
  side keep a borrow alive long enough?
- `transmute`, `from_raw_parts`, `slice::from_raw_parts_mut`, `ptr::offset`:
  are length, alignment and lifetime all proven at the call site?

Easy-to-miss soundness holes:
- A safe method hands out `&T` into interior-mutable storage, then a second
  safe method reallocates/clears that storage — the first borrow now dangles.
- A type that is effectively `!Send` (raw pointer, `RefCell`, OS handle)
  gains `Send`/`Sync` via a blanket impl or derive and becomes shareable
  from safe code.""",

    "go": """\
Where to look first (non-exhaustive — reason beyond this list):
- HTML built with `text/template` instead of `html/template`, or
  `template.HTML()` casts on request-derived strings.
- Maps / slices / struct fields written from multiple goroutines without a
  mutex or channel hand-off (look at HTTP handlers sharing package-level
  state).
- `os.Stat` → `os.Open`, `Exists` → `Remove` and similar two-step file ops
  on paths another principal can swap between calls.
- `filepath.Join(base, userInput)` without `filepath.Clean` + prefix check
  back to `base` — `..` segments still escape after Join.
- `exec.Command("sh", "-c", x)` or argv elements assembled from request
  fields.
- `interface{}` asserted with `x.(T)` (no `, ok`) on values that came from
  JSON/YAML decode — wrong type panics the handler.""",

    "python": """\
Where to look first (non-exhaustive — reason beyond this list):
- Code execution: eval / exec / compile / __import__ / getattr(obj, user)()
  / functools.reduce over user data; ast.literal_eval is safe, eval is not
- Deserialization: pickle.load(s) / shelve / marshal / jsonpickle / dill /
  joblib.load / yaml.load without SafeLoader / pandas.read_pickle on
  untrusted bytes — all are RCE
- Command exec: subprocess.* with shell=True or string args, os.system,
  os.popen, commands.*; also .NET Process.Start / win32 ShellExecute /
  os.startfile in IronPython / pywin32 / pythonnet code — check the path
  argument is allow-listed (fixed dir + fixed basename), not just "a path"
- SQL: cursor.execute(f"..."), .raw(), .extra(), text() with f-strings,
  string-built queries; ORM bypasses
- Template / HTML: mark_safe, |safe, Markup(), autoescape off — AND
  hand-rolled HTML via f"<td>{x}</td>" / "".join / += where x is external
  and not passed through html.escape()
- XXE: lxml.etree.parse / fromstring without resolve_entities=False or
  no_network=True; xml.sax / xml.dom.pulldom with external-general-entities
- XPath injection (CWE-643): lxml / ElementTree .xpath() / .find() or a
  string-built XPath expression where a request value is concatenated in
- SSRF: requests.* / httpx.* / urllib.request.urlopen where the URL host is
  user-influenced; check redirects aren't followed to internal hosts
- Path traversal: open / shutil.* / send_file / os.remove / rmtree on
  os.path.join(base, user) without os.path.realpath + startswith(base) check
- Archive extraction: tarfile.extractall / zipfile.extractall on untrusted
  archives (zip-slip — member names containing ../ or absolute paths)
- CSV / formula injection (CWE-1236): csv.writer / pandas.to_csv / f-string
  rows where cell values originate from parsed input and are written without
  stripping leading = + - @ TAB (Excel evaluates these as formulas on open)
- Windows forced-auth (CWE-73): externally-supplied paths passed to open(),
  shutil.*, os.startfile, Process.Start, SetValue on a native file-dialog,
  or any Win32 API WITHOUT rejecting UNC prefixes (\\\\host\\..., //host/...).
  Resolving a UNC triggers SMB → leaks the runner's NTLMv2 hash.

Easy-to-miss logic faults:
- Module-level mutable globals: one function sets `global X; X = ...` but a
  sibling function that ALSO changes the same conceptual state forgets the
  assignment — downstream readers of X act on stale state (cross-tenant /
  cross-workspace file ops, wrong-record updates)
- TOCTOU via filesystem metadata: `max(glob(...), key=os.path.getmtime)` or
  `sorted(..., key=getctime)[-1]` to pick "the latest" output — any local
  writer can plant a future-dated entry and win the selection. Same for
  os.path.exists → open, or stat → use, on shared/world-writable dirs
- Destructive ops on derived paths: os.remove / shutil.rmtree / os.rename
  where the target path is built from a global or external value without
  re-validating it belongs to the current run/tenant""",

    "java": """\
Where to look first (non-exhaustive — reason beyond this list):
- Deserialization: ObjectInputStream.readObject without an ObjectInputFilter;
  Jackson enableDefaultTyping / @JsonTypeInfo(Id.CLASS); XStream.fromXML;
  XMLDecoder; SnakeYAML new Yaml() (not SafeConstructor); Kryo/Hessian/FST
- XXE: DocumentBuilderFactory / SAXParserFactory / XMLInputFactory / SAXReader /
  TransformerFactory without FEATURE_SECURE_PROCESSING + disallow-doctype-decl
- XPath injection (CWE-643): XPath.compile / evaluate, XPathExpression, or
  Document.selectNodes built by concatenating a request value into the expr
- JNDI: new InitialContext().lookup(x) / LdapCtx / RMI where x is user-derived
- Command exec: Runtime.exec / ProcessBuilder with user-influenced argv;
  String[] is safe only if argv[0] is fixed
- Path traversal: new File(base, user) / Paths.get / getResourceAsStream
  without getCanonicalPath().startsWith(base) check
- Zip-slip: ZipInputStream / TarArchiveInputStream / ZipFile.entries() where
  entry.getName() is used in new File(dest, name) without canonicalize+prefix
- SSRF: new URL(user).openConnection / HttpURLConnection / Apache HttpClient /
  OkHttp / ImageIO.read(URL) where host is user-controlled
- TLS bypass: X509TrustManager with empty checkServerTrusted, HostnameVerifier
  returning true, SSLContext.init with all-trusting managers
- Reflection: Class.forName(user) / Method.invoke / ScriptEngine.eval /
  URLClassLoader on user-supplied class names or URLs
- Open redirect / CRLF: response.sendRedirect(param), setHeader("Location",
  param), addHeader with unfiltered \\r\\n""",

    "javascript": """\
Where to look first (non-exhaustive — reason beyond this list):
- Property writes through a request-controlled key (`obj[k] = v`, lodash
  `merge`/`set`, recursive assign) — `__proto__`/`constructor` keys pollute
  the prototype chain.
- Regexes evaluated against request bodies/headers: nested or overlapping
  quantifiers (`(a+)+`, `(.*?,)*`) on unbounded input → CPU exhaustion.
- DOM/SSR sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `dangerouslySetInnerHTML`, server-side template literals that splice
  request fields into markup without an encoder.
- `child_process.exec` / `execSync` (string form) or `spawn` with
  `shell: true` taking request-derived arguments.
- File-serving / download routes: `path.join(root, req.params.file)` or
  `res.sendFile(userPath)` without resolving + asserting the result stays
  under `root`.
- `eval`, `new Function`, `vm.runInThisContext` on request data; `require()`
  of a path that includes a request field.""",

    "php": """\
Where to look first (non-exhaustive — reason beyond this list):
- `unserialize()` on cookies, POST bodies or anything request-derived (POP
  gadget chains → RCE); `phar://` reached via file functions on a user path
  triggers the same.
- `include`/`require`/`include_once` where any part of the path comes from
  the request (LFI; with `allow_url_include` → RFI).
- SQL strings assembled with `.` concat or double-quoted interpolation from
  `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` instead of PDO bound params.
- `exec`/`system`/`shell_exec`/`passthru`/`popen`/`proc_open`/backticks
  where the command string or argv embeds request data.
- Outbound fetches (`file_get_contents`, `fopen`, `curl_*`, Guzzle) where
  the host/scheme is request-controlled.
- `preg_replace` with the deprecated `/e` modifier, `assert($str)`,
  `create_function`, or `call_user_func($_GET[...])`.""",

    "ruby": """\
Where to look first (non-exhaustive — reason beyond this list):
- `YAML.load`, `Marshal.load`, `Oj.load` (non-strict) on request or uploaded
  bytes — the safe forms are `YAML.safe_load` / `Marshal` never on untrusted
  data.
- Views emitting unescaped content: `raw`, `.html_safe`, `<%== %>`, Haml
  `!=`, Slim `==` on request-derived values.
- `params.permit!` / blanket `permit(...)` that whitelists role/admin/owner
  fields, or `update(params[:model])` straight onto the record.
- Dynamic dispatch with a request-supplied symbol: `send(params[:m])`,
  `public_send`, `constantize`/`safe_constantize` on user strings.
- `system`/`exec`/`` `cmd` ``/`%x{}`/`Open3.*` where any fragment is request
  data; same for `Kernel.open(user)` (leading `|` runs a process).""",

    "objective-c": """\
Where to look first (non-exhaustive — reason beyond this list):
- Format-string sinks (`NSLog`, `-[NSString stringWithFormat:]`,
  `CFStringCreateWithFormat`) where the FORMAT argument itself is external
  data rather than a literal.
- Raw C buffers under the ObjC layer: `strcpy`/`sprintf`/`memcpy` on
  `[nsstr UTF8String]` or socket bytes without a bound.
- Custom URL-scheme / universal-link handlers: query items reaching
  `NSURL`, `openURL:`, file paths, or WebView loads unvalidated.
- Secrets or session tokens persisted to `NSUserDefaults`, plists, or
  unencrypted SQLite instead of Keychain.""",

    "kotlin": """\
Where to look first (non-exhaustive — reason beyond this list):
- JVM deserialization surfaces inherited from Java: `ObjectInputStream`,
  Jackson polymorphic typing, SnakeYAML `Yaml()` on request bytes.
- Queries built with `$var` string templates in Exposed / JDBC / Room raw
  SQL rather than bound `?` parameters.
- (Android) exported `Activity`/`Service`/`Receiver`/`Provider` consuming
  `Intent` extras without validating origin or contents — intent redirection
  / extra-driven file/URL loads.
- `File(base, userInput)` / `Paths.get(user)` without canonicalising and
  asserting the result stays under the intended root.
- `Runtime.exec`/`ProcessBuilder` with string-template argv.""",

    "csharp": """\
Where to look first (non-exhaustive — reason beyond this list):
- `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`,
  `LosFormatter`, `ObjectStateFormatter`, or `JavaScriptSerializer` with a
  custom type resolver, fed from request/viewstate/queue data.
- `SqlCommand`/`OracleCommand`/`NpgsqlCommand` whose `CommandText` is built
  with `+` or `$"... {x} ..."` instead of `Parameters.Add`.
- `Path.Combine(root, user)` / `File.*` / `Directory.*` on request input
  without `Path.GetFullPath` + `StartsWith(root)` containment.
- `XmlDocument.Load`/`XDocument.Load`/`XmlReader.Create` without
  `DtdProcessing = Prohibit` and a null `XmlResolver`.
- `Process.Start` (or `UseShellExecute = true`) with arguments or filename
  derived from the request.
- Newtonsoft `TypeNameHandling != None` on attacker-reachable JSON.""",

    "perl": """\
Where to look first (non-exhaustive — reason beyond this list):
- Command injection via open()/system()/backticks/qx — ONLY when the argument
  crosses a trust boundary (CGI param, network input, file content from an
  untrusted source). $ARGV[n] / @ARGV on a locally-run operator CLI tool is
  TRUSTED input — the operator already has a shell, so do NOT report it.
- Two-arg open(): only a finding when (a) the filename is untrusted AND
  (b) no explicit mode prefix (`<`, `>`) is hard-coded. `open(F, "<$x")`
  cannot reach pipe/command mode — do NOT flag it.
- Regex injection / ReDoS where the PATTERN itself is untrusted input
- Taint propagation through eval STRING, `do $file`, `require $var`
- CSV / formula injection (CWE-1236): print/printf emitting parsed fields
  into a .csv WITHOUT prefixing a single-quote or stripping leading
  = + - @ TAB. Double-quoting ("$x") does NOT neutralise — Excel strips
  RFC-4180 quotes before evaluating the cell.
- Hardcoded credentials / secrets in source (these ARE findings regardless
  of execution reachability)""",

    "swift": """\
Where to look first (non-exhaustive — reason beyond this list):
- `application(_:open:options:)` / `onOpenURL` / universal-link handlers
  where URL components feed file paths, WebView loads, or auth state.
- `String(format: x, ...)` / `NSString.init(format:)` where `x` itself is
  external (bridged ObjC varargs format-string risk).
- Secrets in `UserDefaults`, plist, or app-group containers instead of
  Keychain; Keychain items without `kSecAttrAccessibleWhenUnlocked*`.
- `FileManager` operations on paths assembled from URL/query input without
  resolving and bounding to the sandbox directory.
- `WKWebView` with `javaScriptEnabled` loading attacker-influenced URLs, or
  message handlers exposing privileged native calls.""",

    "scala": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for ObjectInputStream / Java serialization — Scala inherits JVM gadget-chain risk
- Check Play/Akka-HTTP routes for user input flowing into Twirl templates (@Html, raw output)
- Look for Slick/Anorm/Doobie queries built via string interpolation (s"...$x") instead of
  parameterized fragments (sql"...", fr"...")
- Check XML literals / scala.xml.XML.load* — external entities are enabled by default
- Look for sys.process / Process(...) / Seq(...).!! with user-influenced arguments
- Check Akka actors for shared mutable state accessed outside the actor's mailbox thread""",

    "cobol": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for EXEC SQL ... END-EXEC — look for host variables built via STRING/UNSTRING from
  terminal/CICS input (dynamic SQL injection into DB2)
- Grep for EXEC CICS RECEIVE / BMS maps — trace DFHCOMMAREA and map fields to where they
  reach EXEC SQL, CALL, file I/O, or EXEC CICS LINK/XCTL without validation
- Check ACCEPT FROM CONSOLE / SYSIN — untrusted batch input flowing into business logic
- Look for MOVE of larger PIC items into smaller ones (truncation) and COMPUTE without
  ON SIZE ERROR (silent overflow on COMP/COMP-3 fields used in amounts, indices, lengths)
- Check OCCURS ... DEPENDING ON where the count comes from input — out-of-bounds subscript
- Grep for CALL identifier (dynamic CALL with a variable program name) — can untrusted
  input pick the target program?
- Check copybooks (.cpy) shared across programs for REDEFINES that reinterpret tainted
  alphanumeric data as numeric/packed without validation""",

    "jcl": """\
Where to look first (non-exhaustive — reason beyond this list):
- Look for symbolic parameters (&VAR) that flow into DSN=, PGM=, PARM=, or SYSIN — if
  callers/schedulers can set them, check for dataset-name or program-name injection
- Check DD statements with DISP=(MOD|OLD,DELETE) or IDCAMS DELETE/IEFBR14 steps that
  target datasets named via substitutable parameters
- Grep for IKJEFT01 / IRXJCL / BPXBATCH steps — TSO, REXX, or USS commands built from
  PARM= or SYSTSIN that include externally supplied values (command injection)
- Look for FTP/SFTP (FTP PARM=, BPXBATCH SH) or NJE transmit steps with hardcoded
  credentials in inline SYSIN or unprotected PARMLIB members
- Check RACF/ACF2 context: jobs that run under high-privilege USER= but accept
  operator-supplied or scheduler-supplied parameters""",

    "web-template": """\
Where to look first (non-exhaustive — reason beyond this list):
- Find every spot where a variable is rendered WITHOUT auto-escaping: JSP <%= %> /
  ${} without <c:out>; Thymeleaf th:utext / [( )]; Razor @Html.Raw; ERB <%= raw %> /
  html_safe; Twig |raw; Jinja {{ x|safe }} / {% autoescape false %}; Handlebars {{{ }}};
  Freemarker ?no_esc / <#noescape>; EJS <%- %>; Vue v-html; Svelte {@html}; Angular
  [innerHTML] / bypassSecurityTrust*
- Trace each unescaped expression back to its controller — is the value user-controlled?
- Look for SSTI: places where the TEMPLATE SOURCE itself (not just a variable) is built
  from user input and passed to the engine
- Check inline <script> blocks and on*= attributes that interpolate server variables —
  even "escaped" HTML output is unsafe inside a JS string or event handler
- Check href=/src=/action= built from user input — javascript: URI and open redirect""",

    "dart": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for Process.run / Process.start with runInShell: true or string-concatenated args
- Check platform channels (MethodChannel) — untrusted args from the native side reaching
  File/Process/db without validation, or sensitive ops exposed to the platform
- Look for WebView (webview_flutter / InAppWebView) with javascriptMode unrestricted
  loading user-controlled URLs, or addJavaScriptHandler exposing privileged Dart calls
- Check http/dio requests where the URL host is user-influenced (SSRF / open redirect)
- Look for File/Directory paths built from user input without normalization
- Check certificate handling: badCertificateCallback returning true, or
  HttpOverrides that disable TLS verification""",

    "elixir": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for Code.eval_string / Code.eval_quoted / :erlang.binary_to_term on untrusted
  input (binary_to_term without [:safe] is RCE via atom/fun creation)
- Check String.to_atom / List.to_atom on user input — atom-table exhaustion DoS; use
  String.to_existing_atom instead
- Look for Ecto queries built with raw fragments: fragment("... #{x} ...") or
  Repo.query with interpolated SQL
- Check Phoenix templates for raw/1 or {:safe, ...} wrapping user content
- Grep for System.cmd / :os.cmd / Port.open({:spawn, ...}) with user-influenced args
- Check GenServer/Agent state for user-keyed maps that grow unbounded""",

    "erlang": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for binary_to_term/1 on network input (without the 'safe' option it creates
  atoms/funs → RCE); same for erlang:binary_to_atom/2 (atom-table DoS)
- Check os:cmd/1 and open_port({spawn, Cmd}, ...) for shell-interpreted user input
- Look for distributed-Erlang exposure: net_kernel started with a guessable cookie or
  epmd reachable from untrusted networks (full node RCE)
- Check ETS tables keyed by user input for unbounded growth
- Look for file:open / file:read_file with user-controlled paths""",

    "groovy": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for GroovyShell.evaluate / Eval.me / GroovyScriptEngine / @Grab on user input —
  direct RCE; Jenkins Script Console / shared-library code is a common sink
- Check GString SQL: "SELECT ... ${x}" passed to Sql.execute/rows instead of
  parameterized GString placeholders
- Grep for "cmd".execute() / ["sh","-c", x].execute() / ProcessBuilder with user input
- Look for XmlSlurper/XmlParser without disabling DOCTYPE/external entities (XXE)
- Inherits all Java sinks: ObjectInputStream, JNDI lookup, SpEL/OGNL evaluation""",

    "lua": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for load / loadstring / loadfile / dofile with user-influenced source — RCE
- Check os.execute / io.popen for shell-interpreted user input
- In OpenResty/nginx-lua: ngx.var.* or ngx.req.get_*_args() flowing into ngx.location.capture,
  resty.http, or redis/db queries built via string concat (SSRF / injection)
- Check string.format("%s") used to build SQL/shell/redis commands from request data
- Look for setfenv/_ENV or debug.* exposed to sandboxed user scripts (sandbox escape)
- Check io.open paths derived from request input (path traversal)""",

    "r": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for eval(parse(text=...)) / source() / do.call where the expression or function
  name comes from request input (Shiny input$*, plumber params)
- Check system / system2 / shell / pipe with user-influenced arguments
- Look for SQL built via paste()/sprintf()/glue() and sent through DBI::dbGetQuery /
  dbExecute instead of dbBind / sqlInterpolate
- Check readRDS / load / unserialize on uploaded or fetched files — arbitrary code via
  promise/active-binding deserialization
- In Shiny/plumber: file download/read endpoints where the path includes input$* without
  normalizePath + base-directory check""",

    "powershell": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for Invoke-Expression / iex / Invoke-Command -ScriptBlock built from user input,
  and Add-Type / [ScriptBlock]::Create with external strings — direct code execution
- Check Start-Process / & "..." / cmd /c where arguments are interpolated "..." strings
  containing user input (use argument arrays instead)
- Look for Invoke-WebRequest/Invoke-RestMethod where -Uri is user-controlled (SSRF) or
  whose response is piped straight into iex (download-cradle RCE)
- Check Get-Content/Set-Content/Remove-Item paths built from parameters without
  Resolve-Path under a fixed base (path traversal, wildcard injection)
- Look for ConvertTo-SecureString -AsPlainText / hardcoded PSCredential / secrets in
  transcripts; check for -SkipCertificateCheck / TrustAllCertsPolicy""",

    "batch": """\
Where to look first (non-exhaustive — reason beyond this list):
- FOR /F ... (`cmd`) DO ( SET var=%%F ) — %%F is re-tokenised by cmd.exe AFTER
  substitution, so &, |, >, < in file/command output become live operators.
  Unquoted `SET var=%%F` (instead of `SET "var=%%F"`) is second-order command
  injection when the file/command output is attacker-influenceable.
- %VAR% immediate expansion of tainted values inside ECHO, IF, redirection, or
  another command — same re-tokenisation problem. Only !VAR! delayed expansion
  (with EnableDelayedExpansion) is safe.
- CALL %var% / START %var% / %var%.exe where var is built from file content,
  argv (%1..%9), or environment — arbitrary process execution.
- Redirection targets built from tainted vars (>> %outfile%) — path injection
  and file clobber.
- Hardcoded credentials in NET USE / FTP / SQLCMD inline scripts.
- UNC paths (\\\\host\\share) read from config/input and passed to any command —
  forced SMB auth leaks the runner's NTLMv2 hash.""",

    "ansible": """\
Where to look first (non-exhaustive — reason beyond this list):
- shell: / command: / raw: / script: tasks whose cmd embeds {{ var }} that
  originates from inventory, extra-vars, survey input, or registered output —
  Jinja is rendered THEN passed to /bin/sh, so any unquoted {{ }} is shell
  injection. Same for win_shell / win_command.
- ansible.builtin.uri / get_url / unarchive where url: or src: is templated
  from a variable an operator/CI caller can set (SSRF, supply-chain pull)
- validate_certs: no / verify: false on uri/get_url/yum/apt_repository — TLS
  bypass to internal artefact servers
- lookup('pipe', …) / lookup('url', …) / lookup('file', var) with templated
  arguments — pipe runs on the CONTROL node, so injection here is RCE on the
  Ansible controller, not the target host
- copy/template with mode: 0777 / 0666, or dest: built from {{ var }} without
  a fixed base directory (path traversal onto the managed host)
- become: yes / become_user: root on tasks that consume untrusted vars
- Secrets in plain vars: / defaults/main.yml instead of ansible-vault;
  no_log: missing on tasks that register or echo credentials
- delegate_to: localhost + shell: — same control-node RCE surface as
  lookup('pipe', …)
- Inventory / group_vars committed with real hostnames + credentials""",

    "shell": """\
Where to look first (non-exhaustive — reason beyond this list):
- Grep for eval, bash -c, sh -c, backticks/$() that embed "$VAR" sourced from argv,
  env, or read — command injection via metacharacters
- Find unquoted variable expansions ($var instead of "$var") used as command arguments
  or in [ ] tests — word-splitting and glob injection
- Check curl/wget where the URL contains a variable, and any `curl ... | sh` pattern
- Look for filenames/paths from user input passed to rm/cp/mv/tar without `--` and
  without base-directory containment (option injection, traversal)
- Check `source` / `.` of files at user-writable or variable-derived paths
- Look for tempfile races: > /tmp/fixedname or `mktemp` output reused predictably;
  TOCTOU between [ -f ] check and use""",

    "typescript": """\
Where to look first (non-exhaustive — reason beyond this list):
- Type-erased trust: `as any` / `as unknown as T` / `@ts-ignore` / `@ts-nocheck`
  / non-null `!` on EXTERNAL input — the compile-time check is suppressed, so a
  runtime value the code "trusts" may be attacker-shaped. Validate at the boundary
  (zod / io-ts / class-validator); a cast is NOT validation. (CWE-20)
- Prototype pollution: `obj[userKey] = v`, lodash `merge`/`mergeWith`/`set`,
  `Object.assign({}, req.body)` with a request key `__proto__`/`constructor`/`prototype`.
- Code/command exec: `eval` / `new Function(str)` / `vm.runInContext` on external
  strings; `child_process.exec` with a template-string argument containing ${x} —
  `execFile`/`spawn` with a FIXED binary and array args is safe, `exec` of a built
  string is not.
- SQL: tagged-template clients are safe ONLY if parameterised; `knex.raw`,
  TypeORM `.query()`, Sequelize `literal()` with an interpolated string concatenate
  user input. (CWE-89)
- SSRF: `fetch`/`axios`/`got`/`http.request` where the URL host is user-influenced;
  confirm redirects aren't followed to internal hosts.
- Decorator-driven authz (NestJS/Angular): a route/handler missing
  `@UseGuards`/`@Roles`/`@CanActivate` that siblings have → missing access control.
- Deserialization: `JSON.parse` is safe; `node-serialize` `unserialize`, or
  `yaml.load` (not `safeLoad`) on untrusted bytes is RCE.
Easy-to-miss logic faults:
- TS types vanish at runtime: a value cast with `as` used as an index/length/loop
  bound without a runtime guard — the compiler is silent, the bug is not.
- Optional chaining swallowing a check: `user?.isAdmin` is `undefined` (falsy but
  not `false`); `if (!user?.isAdmin)` may behave unexpectedly when you meant deny.""",

    "sql": """\
Where to look first (non-exhaustive — reason beyond this list):
- Dynamic SQL built by concatenation then executed: Oracle EXECUTE IMMEDIATE /
  DBMS_SQL, T-SQL EXEC(@sql) / sp_executesql with a CONCATENATED (not parameter-
  bound) string, MySQL PREPARE FROM a built string — injection inside the DB tier.
  Bind variables (:x, @p, ?) are safe; string-built predicates are not. (CWE-89)
- Definer rights: procedures created WITH AUTHID DEFINER (Oracle) or
  EXECUTE AS OWNER (T-SQL) that run dynamic SQL from caller input → injection runs
  with the owner's privileges (escalation).
- OS / network reach: xp_cmdshell, DBMS_SCHEDULER / DBMS_JAVA, UTL_FILE / UTL_HTTP /
  UTL_SMTP (Oracle), MySQL LOAD_FILE / INTO OUTFILE, OPENROWSET / BULK — file or
  network egress from the DB; flag any reachable from parameterised input.
- Identifier injection: a caller string sets a TABLE/COLUMN name (bind vars cannot
  parameterise identifiers) — require an allow-list, not quoting.
- Excessive grants: GRANT ... TO PUBLIC, ANY-privileges (e.g. SELECT ANY TABLE),
  roles granted inside a proc body.
Easy-to-miss logic faults:
- NULL comparison: `x = NULL` is never true — an authz/filter predicate using
  `= NULL` instead of `IS NULL` silently matches nothing (or, negated, everything).
- Unbounded mutation: UPDATE/DELETE where `WHERE col = p_in` and `p_in` may be NULL
  or unfiltered → mass row change.
- WHEN OTHERS THEN NULL (Oracle) / empty CATCH swallowing a failed integrity or
  authz check so execution continues.""",

    "terraform": """\
Where to look first (non-exhaustive — reason beyond this list):
- IAM over-grant: `Action = "*"` or `Resource = "*"`; assume-role / trust policy
  with `Principal = "*"` or cross-account `sts:AssumeRole` without `ExternalId`. (CWE-732)
- Public exposure: `aws_s3_bucket` without block-public-access / SSE; RDS/Redshift
  `publicly_accessible = true`; security groups / NSGs with `0.0.0.0/0` (or `::/0`)
  on 22/3389/3306/5432/6379/9200/27017.
- Secret hygiene: literal `access_key`/`secret_key`/`password`/`token` in resource
  args, `user_data`, provider blocks, or committed `*.tfvars`; `aws_ssm_parameter`
  as `String` not `SecureString`; secrets in `locals` / `variable default`.
- State & supply chain: backends without encryption; `aws_kms_key` without
  `enable_key_rotation`; modules sourced from a mutable `?ref=branch/tag` (not a
  commit SHA); `local-exec`/`external` provisioners running `curl ... | sh`.
- Audit disabled: CloudTrail / S3 access logging / VPC flow logs off;
  `skip_final_snapshot = true` on a production data store.
Easy-to-miss logic faults:
- `count`/`for_each` on a sensitive resource gated by a variable that DEFAULTS to
  the insecure branch (e.g. `count = var.public ? 1 : 0` with `public = true`).
- A hardened resource shadowed by a later override file; last write in apply order
  wins, silently re-opening what an earlier block locked down.""",

    "vbnet": """\
Where to look first (non-exhaustive — reason beyond this list):
- SQL: `New SqlCommand("..." & userInput)` / string-concatenated CommandText;
  `cmd.Parameters.Add...` is safe, `&`-built SQL is not. (CWE-89)
- Command exec: `Shell(...)`, `Process.Start` with an argument string built from
  input, `CreateObject("WScript.Shell").Run` — a fixed exe with separated args is
  safe, a built command line is not. (CWE-78)
- Dynamic eval (VBA/VBScript): `Eval`, `Execute`, `ExecuteGlobal`, and late-bound
  `CallByName(obj, userName, ...)` on attacker-influenced names.
- Path/file: `My.Computer.FileSystem.*`, `Open ... For`, `Kill` on a path from
  input without a fixed-base + canonical-path containment check (traversal).
- Deserialization: `BinaryFormatter`/`SoapFormatter`/`LosFormatter`/
  `NetDataContractSerializer` on untrusted bytes is RCE; `Type.GetType(userName)` +
  `Activator.CreateInstance`.
- Crypto: `MD5`/`DES`/`TripleDES`, ECB mode, hardcoded keys/IVs; `Rnd()` /
  `System.Random` for tokens (not a CSPRNG).
Easy-to-miss logic faults:
- `Option Strict Off`: implicit narrowing / late binding hides type confusion — a
  string compared to a number, or a `Variant`/`Object` trusted as a typed value.
- VB `=` string compare is case-insensitive by default — a role/secret check with
  `=` may match unintended casings; and `Nothing` vs `""` vs `0` conflation.""",

    "abap": """\
Where to look first (non-exhaustive — reason beyond this list):
- Dynamic Open SQL: `SELECT ... WHERE (lv_where)` or table name in `(lv_tab)` built
  from input; native `EXEC SQL` blocks — ABAP SQL injection. Use bound host vars and
  validated identifiers. (CWE-89)
- OS command: `CALL 'SYSTEM'`, function modules SXPG_COMMAND_EXECUTE /
  SXPG_CALL_SYSTEM with arguments from input → OS command injection.
- Generic/dynamic invocation: `CALL FUNCTION lv_name`, `CALL METHOD (lv_dyn)`,
  `GENERATE SUBROUTINE POOL`, `INSERT REPORT` on attacker-influenced names → arbitrary
  code / RFC invocation.
- Authorization gaps: a transaction or RFC-enabled FM with NO `AUTHORITY-CHECK
  OBJECT`, or one whose `sy-subrc` result is read but not enforced (continues anyway)
  — missing authorization is the dominant SAP finding.
- File access: `OPEN DATASET ... FILENAME` from input without validation / authority
  check (path traversal on the app server); `GUI_DOWNLOAD`/`GUI_UPLOAD`.
Easy-to-miss logic faults:
- `sy-subrc` ignored after SELECT/CALL: the failure path falls through and the next
  statement runs on stale/initial data (wrong-record or bypassed check).
- Client field (MANDT) omitted in a dynamic/native query → cross-client data access.""",

    "clojure": """\
Where to look first (non-exhaustive — reason beyond this list):
- Code eval: `eval`, `read-string` / `load-string` on untrusted input (the default
  reader evaluates `#=()` and constructs arbitrary objects) — use
  `clojure.edn/read-string` with controlled `:readers`, not `clojure.core/read`. (CWE-95)
- Reflection/interop: `(Class/forName s)`, `(.invoke method ...)`, eval of Java
  interop forms on user-named classes/methods.
- SQL: `clojure.java.jdbc`/`next.jdbc` with a string-built query instead of a
  parameter vector `["... ?" x]`; HoneySQL raw fragments. (CWE-89)
- Command exec: `clojure.java.shell/sh` / `(ProcessBuilder. ...)` with arg strings
  from input.
- SSRF / deserialization: `clj-http`/`slurp` on a user URL; `nippy/thaw` or Java
  `ObjectInputStream` interop on untrusted bytes.
Easy-to-miss logic faults:
- Lazy-seq side effects: a security check inside a lazy `map`/`filter` that is never
  realized (result not consumed) → the check never runs.
- nil punning: `(get m k)` returning nil treated as a deny when it is a silent pass;
  `false`/`nil` collapsing in a conditional that gates access.""",

    "haskell": """\
Where to look first (non-exhaustive — reason beyond this list):
- Command/SQL: `System.Process` `callCommand`/`shell` (spawns via /bin/sh) with an
  interpolated string — use `proc exe [args]`; `postgresql-simple`/`persistent` raw
  `Query` built with `<>`/`printf` instead of `?`-params or the `sql` quasi-quoter. (CWE-89)
- Unsafe escape hatches: `unsafePerformIO`, `unsafeCoerce`, `System.IO.Unsafe` —
  they break the type/effect guarantees the rest of the code relies on.
- Deserialization/parsing: `read` on untrusted input can loop or throw;
  `Data.Binary`/`cereal` `decode` of attacker bytes; `aeson` decode into a partial record.
- Partial functions on external input: `head`/`tail`/`fromJust`/`!!` or a
  non-exhaustive `case` — a crafted input triggers an exception (DoS) or skips a branch.
- SSRF: `http-client`/`wreq` on a user-controlled URL.
Easy-to-miss logic faults:
- Laziness: a validating expression whose result is never forced (`seq`/bang) is
  never evaluated → the check is skipped while appearing present.
- `Integer` (unbounded) vs `Int` (machine word) confusion → overflow/truncation in
  an index or size derived from input.""",

    "ocaml": """\
Where to look first (non-exhaustive — reason beyond this list):
- Command/SQL: `Unix.system`/`Unix.open_process` (via the shell) with a built string
  — prefer `Unix.create_process exe [|args|]`; raw SQL strings to `postgresql`/`sqlite3`
  instead of bound params. (CWE-89)
- Unsafe casts: `Obj.magic`, `Obj.repr`, and `Marshal.from_*` on untrusted bytes —
  Marshal is NOT type-safe; crafted input causes memory unsafety / RCE.
- Partial functions: `List.hd`/`List.assoc`/`Option.get`/non-exhaustive `match` on
  external input → `Not_found`/`Match_failure` (DoS) or a skipped branch.
- FFI: `external` C stubs handling buffers/lengths from input without bounds checks.
- SSRF / file: `cohttp`/curl on user URLs; `open_in`/`Sys.command` on input paths
  without a fixed-base containment check.
Easy-to-miss logic faults:
- Polymorphic `compare`/`=` on values containing functions/closures raises at
  runtime; structural `=` on cyclic data loops.
- `int` is 63-bit and wraps silently — a size/index derived from input overflows
  with no exception.""",

    "fsharp": """\
Where to look first (non-exhaustive — reason beyond this list):
- SQL: string-interpolated queries (`$"... {x}"`) to `SqlCommand`/Dapper/EF Core
  `FromSqlRaw`; bound parameters are safe, interpolation is not. (CWE-89)
- Command exec: `System.Diagnostics.Process.Start` with a built argument string;
  shelling out / `dotnet fsi --exec` on input.
- Deserialization: `BinaryFormatter`/`NetDataContractSerializer` on untrusted bytes
  (RCE); `Type.GetType(userName)`; FsPickler Binary on untrusted input.
- Reflection: `Activator.CreateInstance`/`MethodInfo.Invoke` on input-named types.
- SSRF: `HttpClient`/`WebRequest` with a user-controlled host; redirect to internal ranges.
Easy-to-miss logic faults:
- `obj`-boxing / `:?>` downcast on external data throws or type-confuses; an `Option`
  matched with a wildcard `_ ->` that silently treats `None` as success.
- Lazy / `seq` computations carrying a security side-effect that is never enumerated.""",

    "julia": """\
Where to look first (non-exhaustive — reason beyond this list):
- Command exec: backtick command literals run via `run`/`read` are arg-safe per
  interpolation, BUT a single interpolated string passed to `sh -c "$x"` (or
  `Cmd(string)`) is injectable. (CWE-78)
- Code eval: `eval`, `Meta.parse` + `eval`, `include_string`, `@eval` on untrusted
  strings → arbitrary code execution.
- SQL: LibPQ/MySQL/SQLite with string-built queries instead of parameter binding. (CWE-89)
- Deserialization: `Serialization.deserialize` / JLD2 / BSON load of untrusted bytes
  can construct arbitrary types (RCE) — not safe for untrusted data.
- SSRF / file: `HTTP.get(userurl)`, `download`, `open(path)` from input without a
  fixed-base check.
Easy-to-miss logic faults:
- `@inbounds` disabling bounds checks on an index derived from input → OOB access.
- `parse(Int, s)` throwing on bad input — unhandled it aborts (DoS), or it is
  `try`-swallowed past a security check.""",

    "solidity": """\
Where to look first (non-exhaustive — reason beyond this list):
- Reentrancy: an external call (`.call{value:}`, `.transfer`, token `transferFrom`,
  ERC-777 hooks) BEFORE state updates — apply checks-effects-interactions or a
  `nonReentrant` guard. (CWE-841)
- Access control: state-changing / `selfdestruct` / `delegatecall` / owner-setter
  functions missing `onlyOwner`/role modifiers or left `public`/`external`;
  uninitialized owner; `tx.origin` used for authz (phishable — use `msg.sender`).
- Arbitrary delegatecall / proxy: `delegatecall` to an address from input, or an
  upgradeable proxy whose implementation slot is settable by non-admin → full takeover.
- Unchecked low-level call: `(bool ok,) = addr.call(...)` whose `ok` is ignored;
  unchecked ERC-20 return values.
- Arithmetic & funds: pre-0.8 overflow without SafeMath; rounding/precision loss in
  share math; `block.timestamp`/`blockhash` as randomness (miner-influenced); price
  read from a single spot AMM (oracle manipulation).
Easy-to-miss logic faults:
- Storage-collision in proxies / mis-ordered inherited state variables.
- Default visibility, shadowed state vars; a `require` with `||` where one clause is
  always true → the check is effectively disabled.""",

    "assembly": """\
Where to look first (non-exhaustive — reason beyond this list):
- Missing bounds before a copy/loop: `rep movs`/`stos`, hand-written memcpy loops,
  or a `lodsb`/`stosb` loop whose counter (length register) comes from input without
  a max cap → buffer overflow. (CWE-120)
- Stack frames: writes past an allocated `sub rsp, N` frame; `ret` after a buffer
  write with no canary/check; argument/length registers trusted as-is.
- Indirect control flow: `call`/`jmp` through a register or table index computed from
  input without a range check → control-flow hijack.
- Sign/width: a 32-bit length used in a 64-bit copy, or a signed compare (`jl`/`jg`)
  on an attacker length so a negative value passes a `> max` check then wraps.
- Syscalls: arguments (paths, fds, sizes) to `int 0x80`/`syscall` taken from input
  without validation.
Easy-to-miss logic faults:
- Stale flags: a branch keyed on a flags register that an intervening instruction
  altered (ZF/CF) so a security compare is read wrong.
- Off-by-one in `<=` vs `<` loop terminators on a buffer index.""",

    "zig": """\
Where to look first (non-exhaustive — reason beyond this list):
- Overflow in unchecked builds: arithmetic in `ReleaseFast`/`ReleaseSmall` (overflow
  is UB there) on input-derived values; `@intCast`/`@truncate`/`@ptrCast` narrowing a
  size or index from input. (CWE-190)
- Slicing: `slice[a..b]` / `ptr[0..len]` where `a`,`b`,`len` come from input without
  validating against the backing length → OOB; a `[]const u8` length trusted from a header.
- Allocator misuse: use-after-free / double-free across `defer`/`errdefer` paths;
  `alloc` size = `count * elem` with no overflow check.
- C interop: `@cImport`/`extern` calls passing Zig slices to C without the length the
  C side expects; `ChildProcess`/`std.c.system` with built args.
- Untrusted parsing: `std.json` or a custom parser reading a length field then
  copying/seeking that many bytes without capping to the buffer.
Easy-to-miss logic faults:
- `catch unreachable` / `orelse unreachable` on an error/null an attacker can trigger
  → panic (DoS) or, in unchecked builds, UB.
- Reading `undefined`-initialized memory before it is set on an error path.""",

    "nim": """\
Where to look first (non-exhaustive — reason beyond this list):
- Command exec: `execShellCmd`, `osproc.execProcess`/`startProcess` with
  `{poEvalCommand}`, or `execCmd` on a built string (goes through the shell) — prefer
  arg-array `startProcess` with a fixed exe. (CWE-78)
- Compile-time / FFI: `staticExec` (compile-time shell), `{.emit.}`/`importc` passing
  input to C without bounds checks.
- SQL: `db_postgres`/`db_mysql` `exec(sql"..." & x)` string-built instead of `?`
  bound args. (CWE-89)
- Bounds/overflow: `--checks:off` / `-d:danger` builds disable bounds & overflow
  checks — a `seq`/`array` index or `cast[T]` from input becomes OOB/UB; raw `ptr`/`addr`
  arithmetic.
- SSRF / file: `httpclient` on a user URL; `open`/`readFile` on an input path with no
  fixed-base containment.
Easy-to-miss logic faults:
- `cast[T](x)` reinterprets bits with no check (unlike a converter) — type/size
  confusion on input-derived values.
- An exception from `parseInt`/indexing swallowed by a bare `except:` past a security
  check, so execution continues on bad data.""",

    "crystal": """\
Where to look first (non-exhaustive — reason beyond this list):
- Command exec: `system`, backticks, or `Process.run` with `shell: true` and an
  interpolated string — prefer `Process.run(exe, [args])` with a fixed binary. (CWE-78)
- SQL: `crystal-db`/`crystal-pg` queries built with `#{}` interpolation instead of
  `?`/`$1` bound parameters. (CWE-89)
- Deserialization: `YAML.parse`/`from_yaml` and `Object.from_json` into types with
  custom converters on untrusted input.
- SSRF / file: `HTTP::Client.get(userurl)`; `File.open`/`File.read` on an input path
  without a fixed-base + expand-path containment check.
- Unsafe pointers / C bindings: `Pointer`/`Slice` built from an input length; `lib`/
  `fun` C calls passing buffers without the expected length.
Easy-to-miss logic faults:
- `as` unsafe cast / `not_nil!` on attacker-influenceable values → raises (DoS) or
  type-confuses; a `rescue` clause swallowing the error past a security gate.
- Wrapping operators `&+`/`&*` on input-derived sizes silently wrap (Crystal raises
  on plain `+`/`*` overflow by default, so these are the dangerous ones).""",
}


# ─────────────────────────────────────────────────────────────────────────────
# Specialist researcher bodies — repo-wide passes
# ─────────────────────────────────────────────────────────────────────────────

SPECIALIST_HINTS: dict[str, str] = {
    "crypto": """\
You are reviewing the cryptography, key-handling, and security-protocol
surfaces of this codebase. Target weaknesses an attacker can exploit
mathematically or by abusing protocol negotiation — not generic "uses MD5
somewhere" hygiene items.

Where to look first (non-exhaustive — reason beyond this list):
- Secret/HMAC/token equality checks done with `==` / `equals` / `memcmp`
  instead of a constant-time comparator — early-exit leaks match length.
- Signature/JWT verification that reads the algorithm or key-id from the
  token itself and trusts it (alg=none, HS↔RS key confusion, kid path
  traversal).
- Symmetric encryption where the IV/nonce is constant, predictable, or
  derived from data the attacker can replay (GCM nonce reuse = full key
  compromise of authenticity).
- Security-relevant randomness drawn from non-CSPRNG sources
  (`Math.random`, `rand()`, `Random()`, `random.random`) for tokens, IVs,
  keys, OTPs, reset codes.
- TLS / signature verification that is wired up but not enforced — empty
  trust managers, hostname checks returning `true`, verify result ignored.
- Hard-coded keys, salts, or passphrases in source or config; key bytes
  written to logs or error messages.""",

    "logic-bug": """\
You are reviewing for behavioural / state-machine defects — the class of bug
that has no single grep signature and only surfaces when you reason about
ordering, concurrency, and edge-case inputs.

HARD GATE — for every finding you MUST cite the exact trust boundary that is
crossed: the file:line where untrusted/external input enters, and the file:line
where the security decision is made on that input. If both sides are internal
(service-to-service, same trust domain, idempotent retry, intentional design),
DROP the finding. No trust-boundary citation → no finding.

Reason about behaviour, don't pattern-match. Seed questions:
- Check-then-act windows: between the permission/ownership/balance check and
  the mutation, can a second request, another thread, or a filesystem actor
  change what was checked?
- Auth/session state: what does the login or step-up flow do on empty, null,
  duplicated, or out-of-order messages? Can two concurrent requests against
  one session leave it half-authenticated?
- Numeric identity and counters: what happens at overflow, at zero, at
  negative after a narrowing cast? Does an ID truncated to 32-bit collide
  with a privileged record?
- Connection/protocol state: can a malformed or truncated message leave the
  parser mid-state so the NEXT request on the same connection is
  misinterpreted?
- Caches and memoised decisions: is the cache key missing the
  tenant/user/role dimension, so one principal's result is served to
  another? Does a cached "authorised" decision outlive a revocation?
- Sentinel return values: is the result of indexOf/find/search (which returns
  -1 / null when the token is absent) used as an offset or length WITHOUT the
  `== -1` guard, so "not found" silently becomes position 0 or a wrong
  substring slice? Same for parseInt→NaN or a lookup returning null treated as
  success.""",

    "access-control": """\
You are an Authorization / access-control expert. Hunt for IDOR (BOLA),
missing or incorrect authorization checks, horizontal/vertical privilege
escalation, and multi-tenant isolation bypass. The bug here is usually the
ABSENCE of a check — you are looking for what is NOT there.

HARD GATE — for every finding you MUST show:
  (a) the entry point (controller/handler/route) and the identity it
      authenticates as, and
  (b) the object/resource it acts on and WHERE ownership/tenant/role is
      verified for THAT object.
If (b) exists and is correct, DROP the finding. "Endpoint requires login" is
NOT authorization — the question is whether the logged-in user may act on
THIS specific record. A target that is a FIXED/HARDCODED constant (not derived
from the request) is NOT attacker-varied — it is at most a single-record issue
with bounded blast radius, NOT arbitrary/broad object access; do not label it
IDOR/BOLA. Do in depth analysis to confirm first.

Where to look first (non-exhaustive — reason beyond this list):
- Enumerate every externally reachable handler (Spring: @RequestMapping/@Get/
  @Post…, JAX-RS: @Path, servlets, message listeners). For each: what object
  ID comes from the request (path var, query, body)? Is that ID checked
  against the caller's identity/tenant before load/update/delete?
- Direct object references: findById(request.id), repository.getOne(id),
  file paths or S3 keys built from request fields — can user A pass user B's ID?
- Missing guards: methods with @PreAuthorize/@Secured/@RolesAllowed on
  siblings but NOT on this one; service-layer methods callable from multiple
  controllers where only some callers check authz.
- Vertical escalation: admin-only operations reachable via non-admin routes;
  role checks that compare strings case-sensitively or trust a role claim
  from the request body/JWT without signature verification.
- Mass assignment: request DTO bound directly to an entity (Spring
  @ModelAttribute / Jackson into JPA entity) letting a caller set owner_id,
  role, isAdmin, tenantId, price.
- Multi-tenant leakage: queries that filter by id but not tenant_id; caches
  or singletons keyed only by object id.
- Destructive bulk operations: deleteAll() / truncate / "DELETE FROM t" or a
  bulk UPDATE with no WHERE / owner / tenant scope, or a schema reset/drop
  reachable from a request — one call wipes or overwrites every record, not
  just the caller's. Treat an unscoped destructive bulk op as a first-class
  high-impact finding, not a lesser issue.""",

    "deserialization": """\
You are an Unsafe-deserialization expert. Hunt for deserialization of
attacker-influenced bytes through libraries that invoke code during object
reconstruction — the dominant remote-code-execution vector on the JVM.

HARD GATE — a finding requires BOTH:
  (a) a deserializer call site, AND
  (b) a path from untrusted input (HTTP body/header/param, message queue,
      file upload, cache, DB blob written by another tenant) to that call.
Deserializing your own freshly-serialized data, or data signed/HMAC'd before
serialize and verified before deserialize, is NOT a finding. Cite both
file:line points or drop it.

Where to look first (non-exhaustive — reason beyond this list):
- Java native: ObjectInputStream.readObject / readUnshared, Serializable +
  readObject/readResolve overrides, RMI/JMX/JNDI endpoints, Apache Commons
  SerializationUtils.
- Jackson: ObjectMapper with enableDefaultTyping / activateDefaultTyping,
  @JsonTypeInfo(use = Id.CLASS or Id.MINIMAL_CLASS), PolymorphicTypeValidator
  set to LaissezFaire, or polymorphic fields typed as Object/Serializable.
- XML: XMLDecoder, XStream without a hardened allow-list (fromXML on request
  data), JAXB with XmlAdapter that instantiates by class name.
- YAML: SnakeYAML new Yaml() / Yaml(new Constructor()) on untrusted input
  (allows !!javax.script… etc.); only SafeConstructor is safe.
- Others: Kryo, Hessian/Burlap, FST, Spring DefaultDeserializer,
  RedisTemplate with JdkSerializationRedisSerializer where Redis is shared.
- Mitigation check: is an ObjectInputFilter / serialFilter / class allow-list
  applied BEFORE readObject? If yes, evaluate whether the allow-list itself
  admits a known gadget (e.g. permits java.util.*, org.apache.commons.*).""",

    "batch-etl": """\
You are a Batch / ETL data-pipeline expert. The target is a file-in →
transform → file-out job (mainframe-migrated or scheduler-driven). The
attacker model is: an upstream producer, scheduler/operator parameter, or
shared landing directory — NOT an interactive web user.

HARD GATE — for every finding cite (a) the externally-influenced value
(job parameter, env var, upstream record field, filename in a watched dir)
and (b) the file:line where it reaches a path, command, SQL, or output
record WITHOUT validation. If both producer and consumer are inside the
same trust domain and the value cannot be set by a lower-privileged party,
DROP it.

Where to look first (non-exhaustive — reason beyond this list):
- Job parameters / env vars (sys.argv, os.environ, JCL PARM=, scheduler
  variables) flowing into open()/Path()/shutil.* / os.remove without a
  fixed base-directory + realpath check — path traversal lets an upstream
  caller read/overwrite arbitrary files as the batch service account
- Output filenames or staging dirs derived from input RECORD fields
  (account no, merchant id) — traversal / collision via crafted records
- Shared landing / spool directories: glob('*.dat') or "pick newest by
  mtime" where any writer to that dir can plant a file the job will
  ingest or overwrite (TOCTOU / untrusted-producer)
- Fixed-width / packed-decimal (COMP-3) / EBCDIC parsing: length taken
  from the record header and used to slice/seek without capping to the
  buffer; sign-nibble / zone-nibble not validated → negative amounts or
  index wrap; off-by-one between COBOL 1-based PIC offsets and Python
  0-based slices
- Record-count / hash-total trailer NOT verified against the body —
  truncation or injection of extra records goes undetected
- Emitted CSV / report files: cells sourced from input records written
  without stripping leading = + - @ (formula injection into downstream
  Excel consumers)
- subprocess / os.system invoking sort, sftp, gpg, db loaders with
  arguments built from job params or record fields
- Idempotency / restart: checkpoint files or "processed" markers in a
  world-writable dir; rerun after partial failure double-posts records""",

    "iac": """\
You are an Infrastructure-as-Code / cloud-config security expert. Targets
in scope include Terraform/HCL, Dockerfiles, Kubernetes & Helm manifests,
GitHub Actions / GitLab CI / Jenkinsfiles, Ansible, docker-compose, and
CloudFormation. Hunt for misconfigurations that expose data, escalate
privilege, or let an attacker inject code into the build / deploy pipeline.

HARD GATE — every finding MUST cite the specific resource block / step /
directive (file:line) AND the security property it violates (least
privilege, network isolation, supply-chain integrity, secret hygiene).
Aspirational best-practice items with no concrete attack path → LOW.
Vendor-default settings that match the platform baseline are NOT findings.

Where to look first (non-exhaustive — reason beyond this list):

TERRAFORM / HCL
- IAM policies with "*" Action or Resource; trust policies allowing
  wildcard principals or sts:AssumeRole without ExternalId on cross-account
- aws_s3_bucket without block_public_access / server_side_encryption,
  publicly_accessible RDS / Redshift, security groups with 0.0.0.0/0 on
  sensitive ports (22 / 3389 / 3306 / 5432 / 6379 / 9200 / 27017)
- Hardcoded credentials in resource args, user_data, template_file vars;
  provider blocks with literal access_key / secret_key
- aws_ssm_parameter as String instead of SecureString
- Audit disabled: CloudTrail off, S3 access logging off, VPC flow logs off
- KMS keys without rotation; default tenant keys protecting sensitive data

DOCKERFILE / CONTAINERFILE
- No USER directive (or USER root) → container runs as root
- ADD <URL> instead of COPY; `RUN curl ... | sh` / `wget ... | bash` →
  unverified supply-chain fetch
- ENV / ARG carrying secrets — visible in image history layers
- FROM image:latest or unpinned tag → reproducibility / supply-chain
- COPY . . dragging .git / .env / build secrets into the final image
- Missing HEALTHCHECK, no apk/apt cache cleanup → larger surface

KUBERNETES / HELM
- securityContext.runAsUser: 0, runAsNonRoot: false, or missing securityContext
- privileged: true, allowPrivilegeEscalation: true, capabilities.add
  containing SYS_ADMIN / NET_ADMIN / NET_RAW / SYS_PTRACE
- hostPath volumes mounting /var/run/docker.sock, /, /etc, /proc, /sys
- hostNetwork / hostPID / hostIPC true
- Secrets with plaintext `data:` (not `stringData` from a sealed source);
  secrets injected via env where any pod-reader can read process env
- ServiceAccount bound to cluster-admin / wildcard RBAC
- LoadBalancer / NodePort exposing internal services without auth
- Missing NetworkPolicy on namespaces handling sensitive data

GITHUB ACTIONS / GITLAB CI / JENKINS
- pull_request_target + actions/checkout pointed at PR head ref + running
  scripts / installs from the checkout → RCE in trusted context with
  access to repo secrets
- ${{ github.event.* }} (issue title, PR title, branch name, commit
  message, body) interpolated into a `run:` step — command injection
- Third-party actions referenced by mutable tag (uses: org/x@v1, @main)
  instead of full commit SHA → supply-chain pin
- secrets.* passed to steps that execute untrusted code, or written into
  env / outputs where downstream steps log them
- Self-hosted runners on public repos without per-job isolation
- Jenkinsfile sh "..." / bat "..." with parameter interpolation; agent {
  docker { args ... } } using attacker-controlled args
- GitLab CI include: remote: ... pulling pipeline templates without SHA
  pinning; rules: that bypass approval gates on certain branches

ANSIBLE / DOCKER-COMPOSE / CLOUDFORMATION
- shell:/command: with {{ unsanitised_var }} from untrusted inventory
- become: yes on plays driven by untrusted inventory
- no_log: false on tasks handling secrets
- docker-compose privileged: true, pid: host, network_mode: host
- docker-compose volumes mounting /var/run/docker.sock → host escape
- CloudFormation IAM with "*", PublicAccessBlockConfiguration disabled
  on S3 buckets, EC2 SecurityGroups with 0.0.0.0/0 ingress

CROSS-CUTTING
- Hardcoded credentials anywhere (connection strings, JWT signing keys,
  cloud access keys, DB passwords) — even in samples or template files
- Disabled TLS verification: insecure_skip_verify = true, verify = false,
  --insecure / -k on curl/wget, GIT_SSL_NO_VERIFY = true
- Default / sample credentials shipped in templates or vault-encrypted
  defaults committed alongside the matching vault key

For each finding give a concrete remediation (the exact directive to add
or remove) and rate severity from real-world exposure: a public S3 bucket
in prod = HIGH; missing log-retention setting on a dev account = LOW.""",
}


# ─────────────────────────────────────────────────────────────────────────────
# Framework-aware sub-hints — appended to the base language block ONLY when the
# chunk's source matches the marker regex. Keeps the RESEARCH LENS small on
# non-matching chunks. Generic mechanism: add other languages here later.
# ─────────────────────────────────────────────────────────────────────────────

FRAMEWORK_HINTS: dict[str, list[tuple[re.Pattern, str, str]]] = {
    "java": [
        (re.compile(r"org\.springframework|@SpringBootApplication|@RestController|@Controller\b|@Autowired"),
         "Spring / Spring Boot", """\
- Missing authz: @RequestMapping/@GetMapping/@PostMapping handlers WITHOUT a
  matching @PreAuthorize/@Secured/@RolesAllowed — or service methods called
  from multiple controllers where only some callers check authz
- Mass assignment: @ModelAttribute / @RequestBody bound directly to a JPA
  @Entity (caller can set id, role, isAdmin, tenantId, ownerId)
- SpEL injection: user input inside @Value("#{...}"), @Query("... ?#{...}"),
  @PreAuthorize("... #param ..."), SpelExpressionParser.parseExpression(x)
- SSRF: RestTemplate / WebClient / RestClient .getForObject/exchange where the
  URL or UriComponentsBuilder host is request-derived
- Actuator exposure: management.endpoints.web.exposure.include=* or env,
  heapdump, jolokia, gateway exposed without auth
- Path traversal: ResourceUtils.getFile / ClassPathResource / ResourceLoader
  .getResource on request input
- Request-scoped state on singletons: @Autowired @Component holding mutable
  fields written from handler threads (cross-request bleed)
- @Transactional on private/final/self-invoked methods (silently no-op →
  partial writes survive on exception)"""),

        (re.compile(r"javax\.ws\.rs|jakarta\.ws\.rs|@Path\b|@Produces\b|io\.quarkus|io\.micronaut"),
         "JAX-RS / Jakarta REST", """\
- @Path methods without a ContainerRequestFilter / @RolesAllowed guard
- @PathParam/@QueryParam flowing into File, exec, or query without validation
- @Consumes(APPLICATION_XML) hitting a JAXB unmarshaller with DTDs enabled
- Providers (MessageBodyReader) that deserialize arbitrary types"""),

        (re.compile(r"javax\.persistence|jakarta\.persistence|org\.hibernate|EntityManager|@Entity\b|@Repository\b"),
         "JPA / Hibernate", """\
- em.createQuery("... " + x) / createNativeQuery with string concat (JPQL/HQL
  injection — parameters via setParameter only)
- Spring Data @Query(nativeQuery=true, value="..."+...) or SpEL ?#{} on input
- findById(request.id) without owner/tenant check before update/delete (IDOR)
- @Formula / @Where with concatenated input"""),

        (re.compile(r"org\.apache\.ibatis|org\.mybatis|@Mapper\b|<mapper\b"),
         "MyBatis", """\
- ${param} (text substitution → SQLi) vs #{param} (bind) in mapper XML and
  @Select/@Update annotations — every ${} on a request-derived value is SQLi
- <if>/<foreach> building ORDER BY / column names from input"""),

        (re.compile(r"org\.apache\.struts|com\.opensymphony\.xwork|struts\.xml|ActionSupport"),
         "Struts 2", """\
- OGNL evaluation on request params (forced double evaluation, %{...} in
  results, redirect:/redirectAction: with ${}) — historic RCE class
- ParametersInterceptor reaching setters on the Action that mutate auth state"""),

        (re.compile(r"javax\.servlet|jakarta\.servlet|HttpServlet\b|doGet\(|doPost\("),
         "Servlet (raw)", """\
- request.getParameter/getHeader flowing unencoded into response.getWriter()
  .print (reflected XSS) or into File/Runtime/SQL
- getRequestDispatcher(param).forward / include (LFI via JSP path)
- response.sendRedirect(request.getParameter(...)) (open redirect)"""),

        (re.compile(r"\bandroid\.|\bandroidx\.|AndroidManifest|ContentProvider\b|BroadcastReceiver\b"),
         "Android", """\
- Exported Activity/Service/Receiver/Provider (android:exported="true" or
  intent-filter present) without permission gate — intent injection
- WebView: setJavaScriptEnabled(true) + addJavascriptInterface, or
  loadUrl/loadData on Intent extras
- ContentProvider.openFile with caller-supplied Uri (path traversal)
- PendingIntent without FLAG_IMMUTABLE; implicit Intents carrying extras"""),
    ],
}


def _framework_blocks(languages: list[str], code: str) -> list[str]:
    out: list[str] = []
    sample = code[:200_000]
    for lang in languages[:3]:
        for rx, name, body in FRAMEWORK_HINTS.get(lang, []):
            if rx.search(sample):
                out.append(f"── {name} (detected) ──\n{body}")
    return out


def hints_for(languages: list[str], specialist: str | None,
              code: str | None = None) -> str:
    """
    Build the hint block to inject into a researcher's system prompt.

    - If `specialist` is set (key in SPECIALIST_HINTS), return that body.
    - Otherwise concatenate hints for every detected language (max 3 to keep
      the prompt sane), each under a "── {Lang} ──" header.
    - Returns "" if nothing matches.
    """
    if specialist:
        return SPECIALIST_HINTS.get(specialist, "")

    parts: list[str] = []
    for lang in languages[:3]:
        block = LANG_HINTS.get(lang)
        if block:
            name = LANG_DISPLAY.get(lang, lang)
            parts.append(f"── {name} ──\n{block}")
    if code:
        parts.extend(_framework_blocks(languages, code))
    return "\n\n".join(parts)
