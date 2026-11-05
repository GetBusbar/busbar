"""Validate a conformance generation against the caller's independent job result."""
import datetime
import hashlib
import io
import json
import re
import tarfile


class Refused(ValueError):
    """An archive cannot prove a successful, complete conformance invocation."""


def validated_verdicts(data, *, repo, head, state, allow_failed=False):
    """Import mode requires success; release-reader mode may retain bound negative evidence.

    `state` is the artifact service's result, never a field copied from the archive.
    Pre-receipt archives intentionally cannot supply a PASS; rerun the current driver.
    `allow_failed` admits red/exit-one receipts, discarding every PASS in that invocation.
    """
    if state != "green" and not (allow_failed and state == "red"):
        raise Refused("the conformance job did not finish green")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            files = {}
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                name = member.name.removeprefix("./")
                if name in files:
                    raise Refused("duplicate artifact member")
                files[name] = member
            receipts = [name for name in files if name.endswith("/invocation.json") or name == "invocation.json"]
            if len(receipts) != 1:
                raise Refused("no unique completed invocation receipt; rerun the current driver")
            name = receipts[0]
            receipt = json.load(archive.extractfile(files[name]))
            if not isinstance(receipt, dict) or receipt.get("schema") != "busbar.conformance.invocation/1":
                raise Refused("invalid invocation receipt")
            if (receipt.get("repo"), receipt.get("commit")) != (repo, head):
                raise Refused("invocation does not name the requested repository and head")
            expected_exit = 0 if state == "green" else 1
            if type(receipt.get("exit_code")) is not int or receipt["exit_code"] != expected_exit:
                raise Refused("invocation exit does not match the job result")
            if not re.fullmatch(r"[0-9a-f]{32}", str(receipt.get("invocation_id", ""))):
                raise Refused("missing invocation identity")
            if not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("core_pin", ""))):
                raise Refused("missing invocation core pin")
            inputs = receipt.get("inputs")
            required = {"testing/conformance/run.sh", "testing/conformance/tools.sh", "testing/conformance/suites.tsv"}
            if not isinstance(inputs, dict) or not required <= inputs.keys() or not all(
                    isinstance(path, str) and re.fullmatch(r"[0-9a-f]{64}", str(digest))
                    for path, digest in inputs.items()):
                raise Refused("missing invocation input hashes")
            def timestamp(value):
                return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
            started, finished = timestamp(receipt["started_at"]), timestamp(receipt["finished_at"])
            if started > finished or finished > datetime.datetime.now(datetime.timezone.utc):
                raise Refused("invalid invocation time interval")
            hashes = receipt.get("verdicts")
            if not isinstance(hashes, dict) or not hashes:
                raise Refused("invocation carries no verdict hashes")
            prefix = name[:-len("invocation.json")] + "verdicts/"
            members = {path: member for path, member in files.items()
                       if "/verdicts/" in "/" + path and path.endswith(".json")}
            if set(members) != {prefix + filename for filename in hashes}:
                raise Refused("artifact verdicts differ from the completed invocation")
            verdicts = {}
            for filename, digest in hashes.items():
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.json", filename):
                    raise Refused("invalid invocation verdict name")
                payload = archive.extractfile(members[prefix + filename]).read()
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise Refused("verdict bytes differ from the completed invocation")
                verdict = json.loads(payload)
                sid = filename[:-5]
                if (verdict.get("repo"), verdict.get("commit"), verdict.get("core_pin"), verdict.get("suite")) != (
                        repo, head, receipt["core_pin"], sid):
                    raise Refused("verdict identity differs from the completed invocation")
                if state == "green" and (verdict.get("status") != "pass" or verdict.get("armed") is not True):
                    raise Refused("successful invocation carries a non-passing verdict")
                if not started <= timestamp(verdict["generated_at"]) <= finished:
                    raise Refused("verdict predates or follows the completed invocation")
                verdicts[sid] = verdict
            if state == "red":
                verdicts = {sid: verdict for sid, verdict in verdicts.items() if verdict.get("status") != "pass"}
                if not verdicts:
                    raise Refused("failed invocation carries no negative evidence")
            return verdicts
    except (KeyError, TypeError, ValueError, tarfile.TarError) as error:
        if isinstance(error, Refused):
            raise
        raise Refused(f"invalid conformance invocation: {error}") from error
