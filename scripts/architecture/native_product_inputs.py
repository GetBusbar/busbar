"""Parse candidate product locations as data; never import shell or arbitrary env."""

import json
from pathlib import Path

from check import Violation

PATH_KEYS = {
    "BUSBAR_TEST_MEMORY_STORE_CDYLIB",
    "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN",
    "BUSBAR_TEST_SQLITE_CDYLIB",
    "BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN",
    "BUSBAR_TEST_MYSQL_CDYLIB",
    "BUSBAR_TEST_SECRET_ENV_CDYLIB",
    "BUSBAR_BOOTSTRAP_TEST_SECRET_PLUGIN",
    "BUSBAR_TEST_SECRET_FILE_CDYLIB",
    "BUSBAR_TEST_VAULT_CDYLIB",
    "BUSBAR_TEST_TCP_CDYLIB",
    "BUSBAR_TEST_HTTP_CDYLIB",
    "BUSBAR_TEST_WS_CDYLIB",
    "BUSBAR_TEST_A2A_CDYLIB",
    "BUSBAR_TEST_DECISIONS_CDYLIB",
    "BUSBAR_GOVERNANCE_TEST_PLANE_PLUGIN",
    "BUSBAR_TEST_OIDC_CDYLIB",
    "BUSBAR_AUTH_TEST_OIDC_PLUGIN",
    "BUSBAR_TEST_LDAP_PLUGIN",
    "BUSBAR_AUTH_WEBHOOK_SIGNATURE_TEST_PLUGIN",
    "BUSBAR_TEST_RANKING_CDYLIB",
    "BUSBAR_TEST_WEBREQUEST_CDYLIB",
    "BUSBAR_TEST_EXPORT_FILE_CDYLIB",
    "BUSBAR_TEST_EXPORT_WEBHOOK_CDYLIB",
    "BUSBAR_TEST_EXPORT_OTLP_CDYLIB",
    "BUSBAR_TEST_OTLP_CDYLIB",
    "BUSBAR_TEST_EXPORT_PROMETHEUS_CDYLIB",
    "BUSBAR_TEST_PROMETHEUS_CDYLIB",
    *{
        "BUSBAR_TEST_EXPORT_" + name + "_" + kind
        for name in ("FILE", "WEBHOOK", "OTLP")
        for kind in ("MANIFEST", "DECLARES")
    },
}
SETTINGS = "BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS"


def regular_under(path, root):
    path, root = Path(path), Path(root).resolve()
    if not path.is_absolute() or not path.is_relative_to(root):
        raise Violation("product input escapes candidate workspace")
    for current in (path, *path.parents):
        if current == root:
            break
        if current.is_symlink():
            raise Violation("indirect product input")
    if not path.is_file() or not path.resolve().is_relative_to(root):
        raise Violation("missing or nonregular product input")
    return path


def load_product_inputs(stdout, work):
    filename = stdout.read_text().strip()
    work = Path(work).resolve()
    path = regular_under(filename, work / "cache")
    if path.stat().st_size > 128 * 1024:
        raise Violation("product input map exceeds limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Violation("duplicate product input")
            result[key] = value
        return result

    values = json.loads(path.read_text(), object_pairs_hook=pairs)
    if not isinstance(values, dict) or set(values) != PATH_KEYS | {SETTINGS}:
        raise Violation("product input map has missing or unexpected keys")
    if values[SETTINGS] != "{}":
        raise Violation("unexpected product fixture settings")
    for key in PATH_KEYS:
        if not isinstance(values[key], str):
            raise Violation("product path must be a string")
        path = Path(values[key])
        roots = [
            work / name
            for name in ("target", "cache")
            if path.is_relative_to(work / name)
        ]
        if len(roots) != 1:
            raise Violation("product path is outside candidate build/cache outputs")
        regular_under(path, roots[0])
    return values
