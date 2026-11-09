"""Pinned upstream AccessControl runner; fixture and policy inputs stay in evidence.py."""

from collections import Counter
import hashlib
import http.server
import importlib.util
import json
import os
import platform
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
_spec = importlib.util.spec_from_file_location(
    "external_rbac_report", HERE / "report.py"
)
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)
Refused = report.Refused
LOCK = json.loads((HERE / "runtime.lock.json").read_text())


def sha(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(item, dest):
    with (
        urllib.request.urlopen(item["url"], timeout=120) as source,
        open(dest, "xb") as target,
    ):
        shutil.copyfileobj(source, target)
    if sha(dest) != item["sha256"]:
        raise Refused("upstream archive digest mismatch")


def bootstrap(work):
    """All installed JARs are covered by the runtime/addon digests, no updater."""
    work = Path(work)
    work.mkdir(parents=True, exist_ok=False)
    archive = work / "runtime.zip"
    download(LOCK["runtime"], archive)
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            rel = Path(entry.filename)
            if rel.is_absolute() or ".." in rel.parts:
                raise Refused("unsafe upstream archive path")
            if "plugin" in rel.parts:
                if rel.name not in LOCK["bundled_plugins"]:
                    continue
                if (
                    hashlib.sha256(bundle.read(entry)).hexdigest()
                    != LOCK["bundled_plugins"][rel.name]
                ):
                    raise Refused("bundled dependency digest mismatch")
            bundle.extract(entry, work)
    archive.unlink()
    runtime = work / "ZAP_2.17.0"
    for item in LOCK["addons"]:
        download(item, runtime / "plugin" / item["name"])
    expected = set(LOCK["bundled_plugins"]) | {i["name"] for i in LOCK["addons"]}
    if {p.name for p in (runtime / "plugin").glob("*.zap")} != expected:
        raise Refused("missing or unpinned installed addon")
    platform_key = platform.system() + "-" + platform.machine()
    item = LOCK["jre"]["platforms"].get(platform_key)
    if item is None:
        raise Refused("no approved pinned JRE for " + platform_key)
    java_archive = work / "jre.tar.gz"
    download(item, java_archive)
    java_root = work / "java"
    java_root.mkdir()
    with tarfile.open(java_archive) as bundle:
        bundle.extractall(java_root, filter="data")
    java_archive.unlink()
    candidates = list(java_root.glob("*/bin/java")) + list(
        java_root.glob("*/Contents/Home/bin/java")
    )
    if len(candidates) != 1:
        raise Refused("pinned JRE executable missing or ambiguous")
    return runtime, candidates[0]


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def raw_request(method, uri, body):
    if method not in (
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT",
    ):
        raise Refused("unsupported HTTP operation")
    parsed = urllib.parse.urlsplit(uri)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username
        or parsed.fragment
        or "\r" in uri
        or "\n" in uri
    ):
        raise Refused("external RBAC fixture must be isolated HTTP loopback")
    return (
        f"{method} {uri} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
        "Connection: close\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body.encode())}\r\n\r\n{body}"
    )


class Credentials:
    """Fresh headers from existing fixture callbacks; no token is retained in evidence."""

    def __init__(self):
        self.active = None
        self.requests = Counter()
        self.responses = Counter()
        self.statuses = {}
        self.errors = []
        self.secret = secrets.token_hex(24)
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    query = urllib.parse.urlsplit(self.path)
                    if query.path != "/" + owner.secret:
                        raise Refused("unknown credential callback")
                    params = urllib.parse.parse_qs(query.query, strict_parsing=True)
                    args = {k: v[0] for k, v in params.items() if len(v) == 1}
                    data = owner.exchange(args)
                    payload = json.dumps(data).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except Exception:
                    # Do not serialize exception contents: callbacks may contain JWTs.
                    owner.errors.append("credential callback refused")
                    self.send_error(500, "credential transport refused")

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/{self.secret}"

    def exchange(self, args):
        active = self.active
        if (
            active is None
            or args.get("method") != active["method"]
            or args.get("uri") != active["uri"]
        ):
            raise Refused("credential callback outside declared operation")
        name = args.get("user")
        if name not in active["principals"]:
            raise Refused("unknown callback principal")
        if args.get("phase") == "request":
            self.requests[name] += 1
            if self.requests[name] != 1:
                raise Refused("duplicate credential request")
            headers = {k.lower(): v for k, v in active["principals"][name][0]().items()}
            if set(headers) - {"authorization"}:
                raise Refused("unexpected fixture credential headers")
            return {"authorization": headers.get("authorization")}
        if args.get("phase") == "response":
            self.responses[name] += 1
            if self.requests[name] != 1 or self.responses[name] != 1:
                raise Refused("unexpected response callback")
            self.statuses[name] = int(args["status"])
            return {}
        raise Refused("unknown callback phase")

    def begin(self, method, uri, principals):
        self.requests.clear()
        self.responses.clear()
        self.statuses.clear()
        self.errors.clear()
        self.active = {"method": method, "uri": uri, "principals": principals}

    def finish(self):
        expected = Counter({name: 1 for name in self.active["principals"]})
        if self.errors or self.requests != expected or self.responses != expected:
            raise Refused("missing/duplicate credential transport cells")
        self.active = None
        return dict(self.statuses)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ExternalRBAC:
    def __init__(self, work, output, timeout=900):
        self.work = Path(work) / "external-rbac"
        self.output = Path(output) / "external-rbac"
        private, public = self.work.resolve(), self.output.resolve()
        if (
            private == public
            or private.is_relative_to(public)
            or public.is_relative_to(private)
        ):
            raise Refused("private credential workspace overlaps published output")
        self.output.mkdir(parents=True, exist_ok=False)
        self.deadline = time.monotonic() + timeout
        self.proc = None
        self.credentials = None
        self.stream = None
        self.receipts = []

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Refused("external RBAC deadline exceeded")
        return remaining

    def api(self, component, kind, action, **params):
        self.remaining()
        # POST keeps API credentials/seed bodies out of URLs and logs.
        payload = urllib.parse.urlencode({"apikey": self.key, **params}).encode()
        req = urllib.request.Request(
            f"{self.base}/JSON/{component}/{kind}/{action}/", data=payload
        )
        try:
            with urllib.request.urlopen(
                req, timeout=min(30, self.remaining())
            ) as response:
                result = json.load(response)
        except (urllib.error.URLError, ValueError) as error:
            raise Refused(f"ZAP API transport failed: {type(error).__name__}") from None
        if isinstance(result, dict) and "code" in result:
            raise Refused(f"ZAP API refused {component}/{action}: {result['code']}")
        return result

    def __enter__(self):
        try:
            runtime, java = bootstrap(self.work)
            version = subprocess.run(
                [java, "-version"], capture_output=True, timeout=10
            )
            if version.returncode:
                raise Refused("Java runtime unavailable")
            self.key = secrets.token_hex(24)
            self.base = f"http://127.0.0.1:{port()}"
            home = self.work / "home"
            args = [
                java,
                "-Xmx512m",
                "-Djava.awt.headless=true",
                "-jar",
                str(runtime / "zap-2.17.0.jar"),
                "-daemon",
                "-silent",
                "-host",
                "127.0.0.1",
                "-port",
                self.base.rsplit(":", 1)[1],
                "-dir",
                str(home),
                "-config",
                "api.key=" + self.key,
                "-config",
                "autoupdate.checkOnStart=false",
                "-config",
                "autoupdate.downloadNewRelease=false",
                "-config",
                "autoupdate.installAddonUpdates=false",
                "-config",
                "connection.timeoutInSecs=5",
            ]
            self.stream = open(self.work / "runtime.log", "wb")
            self.proc = subprocess.Popen(
                args,
                cwd=runtime,
                stdout=self.stream,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            startup = min(self.deadline, time.monotonic() + 120)
            while True:
                if self.proc.poll() is not None:
                    raise Refused(
                        "pinned ZAP exited during startup; inspect private runtime.log"
                    )
                try:
                    found = self.api("core", "view", "version")
                    break
                except Refused:
                    if time.monotonic() >= startup:
                        raise Refused("pinned ZAP startup deadline exceeded") from None
                    time.sleep(0.2)
            if found != {"version": "2.17.0"}:
                raise Refused("unexpected ZAP version")
            addons = self.api("autoupdate", "view", "installedAddons")[
                "installedAddons"
            ]
            expected = {
                "accessControl": "13",
                "commonlib": "1.40.0",
                "graaljs": "0.12.0",
                "network": "0.25.0",
                "scripts": "45.17.0",
                "pscan": "0.6.0",
            }
            if {a["id"]: str(a["version"]) for a in addons} != expected:
                raise Refused("installed addon/dependency version mismatch")
            engines = self.api("script", "view", "listEngines")["listEngines"]
            names = [e for e in engines if isinstance(e, str) and "Graal" in e]
            if len(names) != 1:
                raise Refused("required pinned Graal JavaScript engine unavailable")
            self.engine = names[0]
            self.credentials = Credentials()
            self.api(
                "script",
                "action",
                "setGlobalVar",
                varKey="busbar.callback",
                varValue=self.credentials.url,
            )
            for name, kind in [("transport", "httpsender"), ("rules", "standalone")]:
                self.api(
                    "script",
                    "action",
                    "load",
                    scriptName="busbar." + name,
                    scriptType=kind,
                    scriptEngine=self.engine,
                    fileName=str(HERE / (name + ".js")),
                )
            self.api("script", "action", "enable", scriptName="busbar.transport")
            self.api("pscan", "action", "disableAllScanners")
            (self.output / "runtime.json").write_text(
                json.dumps(
                    {
                        "lock": LOCK,
                        "java_version": version.stderr.decode(errors="replace"),
                        "java_sha256": sha(java.resolve()),
                        "engine": self.engine,
                        "adapter_sha256": {
                            f.name: sha(f)
                            for f in HERE.iterdir()
                            if f.suffix in (".py", ".js", ".json")
                        },
                    },
                    indent=2,
                )
                + "\n"
            )
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _rules(self, spec):
        self.api(
            "script", "action", "setGlobalVar", varKey="busbar.rules.ready", varValue=""
        )
        self.api(
            "script",
            "action",
            "setGlobalVar",
            varKey="busbar.operation",
            varValue=json.dumps(spec),
        )
        self.api("script", "action", "runStandAloneScript", scriptName="busbar.rules")
        value = self.api("script", "view", "globalVar", varKey="busbar.rules.ready")[
            "globalVar"
        ]
        ready = json.loads(value)
        if (
            ready["method"] != spec["method"]
            or ready["uri"] != spec["uri"]
            or ready["cells"] != len(spec["users"])
        ):
            raise Refused("upstream access-rule input setup incomplete")
        return ready

    def matrix(
        self,
        label,
        port,
        ops,
        principals,
        *,
        concrete,
        negative=False,
        subject_binary=None,
        denied_statuses=(401, 403),
        subject_config=None,
    ):
        """Run all operations/users using existing fixture inputs; no new response judge."""
        if not re.fullmatch(r"[a-z0-9-]+", label) or not ops or not principals:
            raise Refused("invalid/empty external matrix")
        dest = self.output / label
        dest.mkdir(exist_ok=False)
        binding = None
        if subject_binary is not None:
            binary = Path(subject_binary).resolve(strict=True)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(REPO), *args], timeout=10
                )

            binding = {
                "binary_sha256": sha(binary),
                "source_commit": git("rev-parse", "HEAD").decode().strip(),
                "source_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
                "source_diff_sha256": hashlib.sha256(
                    git("diff", "--binary", "HEAD")
                ).hexdigest(),
                "config_sha256": hashlib.sha256(
                    json.dumps(subject_config, sort_keys=True).encode()
                ).hexdigest(),
            }
        results = []
        (dest / "result.json").write_text(
            json.dumps(
                {
                    "label": label,
                    "passed": False,
                    "expected_operations": len(ops),
                    "expected_cells": len(ops) * len(principals),
                    "actual_operations": 0,
                    "actual_cells": 0,
                    "binding": binding,
                },
                indent=2,
            )
            + "\n"
        )
        seen = set()
        required_bad_scope = required_bad_expiry = False
        unexpected_illegal = []
        for index, (method, path, scope, verb) in enumerate(ops):
            self.remaining()
            uri = f"http://127.0.0.1:{int(port)}" + concrete(path)
            key = (method, uri)
            if key in seen:
                raise Refused("duplicate declared method/URI operation")
            seen.add(key)
            body = "" if method in ("GET", "DELETE") else "{}"
            self.api("core", "action", "newSession", name="", overwrite="true")
            self.api(
                "script",
                "action",
                "setGlobalVar",
                varKey="busbar.callback",
                varValue=self.credentials.url,
            )
            name = f"{label}-{index:04d}"
            cid = int(
                self.api("context", "action", "newContext", contextName=name)[
                    "contextId"
                ]
            )
            self.api(
                "context",
                "action",
                "includeInContext",
                contextName=name,
                regex=re.escape(uri),
            )
            self.api(
                "context",
                "action",
                "setContextInScope",
                contextName=name,
                booleanInScope="true",
            )
            self.api(
                "authentication",
                "action",
                "setAuthenticationMethod",
                contextId=cid,
                authMethodName="manualAuthentication",
                authMethodConfigParams="",
            )
            pattern = (
                r"^HTTP/\S+ (?:"
                + "|".join(str(int(s)) for s in denied_statuses)
                + r")\b"
            )
            self.api(
                "authorization",
                "action",
                "setBasicAuthorizationDetectionMethod",
                contextId=cid,
                headerRegex=pattern,
                logicalOperator="OR",
            )
            users = []
            for pname, (_, expect) in principals.items():
                want = expect(scope, verb)
                if want not in ("admit", "deny", "forbid", "refuse"):
                    raise Refused("unknown access expectation")
                uid = int(
                    self.api("users", "action", "newUser", contextId=cid, name=pname)[
                        "userId"
                    ]
                )
                self.api(
                    "users",
                    "action",
                    "setUserEnabled",
                    contextId=cid,
                    userId=uid,
                    enabled="true",
                )
                users.append(
                    {
                        "id": uid,
                        "name": pname,
                        "rule": "ALLOWED" if want == "admit" else "DENIED",
                        "expect": want,
                    }
                )
            users.sort(key=lambda u: u["id"])
            self.api(
                "core",
                "action",
                "sendRequest",
                request=raw_request(method, uri, body),
                followRedirects="false",
            )
            spec = {
                "context": cid,
                "method": method,
                "uri": uri,
                "body": body,
                "users": users,
            }
            (dest / (name + ".inputs.json")).write_text(
                json.dumps(spec, indent=2) + "\n"
            )
            # core.sendRequest posts the tree mutation to the EDT. A standalone script
            # round trip can precede it: poll only fixture preparation, never test verdicts.
            setup_end = min(self.deadline, time.monotonic() + 5)
            while True:
                try:
                    node = self._rules(spec)
                    break
                except (Refused, ValueError):
                    if time.monotonic() >= setup_end:
                        raise Refused(
                            "exact method-bearing seed node/rules unavailable"
                        ) from None
                    time.sleep(0.05)
            context_file = dest / (name + ".context")
            self.api(
                "context",
                "action",
                "exportContext",
                contextName=name,
                contextFile=str(context_file),
            )
            self.credentials.begin(method, uri, principals)
            self.api(
                "script",
                "action",
                "setGlobalVar",
                varKey="busbar.transport.error",
                varValue="",
            )
            self.api(
                "accessControl",
                "action",
                "scan",
                contextId=cid,
                userId=",".join(str(u["id"]) for u in users),
                scanAsUnAuthUser="false",
                raiseAlert="true",
            )
            scan_end = min(self.deadline, time.monotonic() + 60)
            while True:
                progress = self.api(
                    "accessControl", "view", "getScanProgress", contextId=cid
                )
                if int(progress["getScanProgress"]) == 100:
                    break
                if time.monotonic() >= scan_end:
                    raise Refused("upstream operation scan deadline exceeded")
                time.sleep(0.1)
            error = self.api(
                "script", "view", "globalVar", varKey="busbar.transport.error"
            )["globalVar"]
            if error:
                raise Refused("credential transport script failed")
            statuses = self.credentials.finish()
            if any(status in (429, 500, 502, 503, 504) for status in statuses.values()):
                raise Refused("subject/control transport, rate-limit or server failure")
            html_file = dest / (name + ".html")
            self.api(
                "accessControl",
                "action",
                "writeHTMLreport",
                contextId=cid,
                fileName=str(html_file),
            )
            # Decode the upstream classifications, including explicit negative results.
            cells = report.read_cells(
                html_file.read_text(), method, uri, [u["name"] for u in users]
            )
            for cell in cells:
                if cell["upstream_result"] == "UNKNOWN":
                    raise Refused("upstream could not judge an expected cell")
                if cell["upstream_result"] == "ILLEGAL":
                    want = next(
                        u["expect"] for u in users if u["name"] == cell["principal"]
                    )
                    if want != "forbid" and not (
                        "expired" in cell["principal"] and want == "deny"
                    ):
                        unexpected_illegal.append(
                            {
                                "principal": cell["principal"],
                                "method": method,
                                "uri": uri,
                            }
                        )
                    if want == "forbid" and scope == "full":
                        required_bad_scope = True
                    if "expired" in cell["principal"] and want == "deny":
                        required_bad_expiry = True
            results.append(
                {
                    "method": method,
                    "uri": uri,
                    "scope": scope,
                    "verb": verb,
                    "users": users,
                    "node": node,
                    "statuses": statuses,
                    "cells": cells,
                    "report": html_file.name,
                    "report_sha256": sha(html_file),
                }
            )
            (dest / "partial.json").write_text(json.dumps(results, indent=2) + "\n")
        expected_cells = len(ops) * len(principals)
        actual_cells = sum(len(r["cells"]) for r in results)
        illegal = sum(
            c["upstream_result"] == "ILLEGAL" for r in results for c in r["cells"]
        )
        need_expiry = any("expired" in name for name in principals)
        ok = actual_cells == expected_cells and (
            required_bad_scope
            and (required_bad_expiry or not need_expiry)
            and not unexpected_illegal
            if negative
            else illegal == 0
        )
        receipt = {
            "label": label,
            "negative": negative,
            "binding": binding,
            "expected_operations": len(ops),
            "actual_operations": len(results),
            "expected_cells": expected_cells,
            "actual_cells": actual_cells,
            "upstream_illegal_cells": illegal,
            "negative_detected_scope": required_bad_scope,
            "negative_detected_expiry": required_bad_expiry,
            "unexpected_illegal": unexpected_illegal,
            "passed": bool(ok),
            "operations": results,
        }
        (dest / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
        self.receipts.append(receipt)
        if not ok:
            raise Refused(
                "upstream AccessControl rejected matrix or failed to detect deliberate violations"
            )
        return receipt

    def complete(self):
        required = {
            "control-full",
            "control-capped",
            "negative-full",
            "negative-capped",
            "subject-full",
            "subject-capped",
            "subject-data",
            "subject-admin-isolation",
            "subject-data-isolation",
            "subject-revoked",
        }
        labels = [r["label"] for r in self.receipts]
        if set(labels) != required or len(labels) != len(required):
            raise Refused("external RBAC mandatory leg roster incomplete")
        if any(not r["passed"] for r in self.receipts):
            raise Refused("external RBAC contains failed legs")
        if any(
            not r["binding"] for r in self.receipts if r["label"].startswith("subject-")
        ):
            raise Refused("external subject binary/source binding missing")
        summary = {
            "scope": "OWASP WSTG 4.2 authorization role replay using ZAP AccessControl 13",
            "passed": True,
            "legs": [
                {k: v for k, v in r.items() if k != "operations"} for r in self.receipts
            ],
            "wstg_full_assessment": False,
            "limitations": [
                "Does not assess horizontal resource ownership or arbitrary privilege-parameter manipulation",
                "Upstream binary access judge supplements existing exact status/code assertions",
            ],
        }
        (self.output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        return summary

    def __exit__(self, *_):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=5)
        if self.stream:
            self.stream.close()
        if self.credentials:
            ledger = {
                "requests": dict(self.credentials.requests),
                "responses": dict(self.credentials.responses),
                "statuses": self.credentials.statuses,
                "errors": self.credentials.errors,
            }
            (self.output / "final-transport.json").write_text(
                json.dumps(ledger, indent=2) + "\n"
            )
            self.credentials.close()
        private_log = self.work / "runtime.log"
        if private_log.exists():
            text = private_log.read_text(errors="replace")[-65536:]
            text = re.sub(r'(?i)Bearer\s+[^\s"<>]+', "Bearer [redacted]", text)
            text = re.sub(
                r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                "[redacted JWT]",
                text,
            )
            for secret in (
                getattr(self, "key", None),
                self.credentials.secret if self.credentials else None,
            ):
                if secret:
                    text = text.replace(secret, "[redacted]")
            (self.output / "runtime-tail.log").write_text(text)

        # Private ZAP sessions can contain JWTs. Never publish or retain them.
        if self.work.exists():
            shutil.rmtree(self.work)
