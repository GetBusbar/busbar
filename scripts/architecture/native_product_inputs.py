"""Validate candidate artifact paths against independently read pinned owner data."""

import json
from pathlib import Path

from product_artifacts import git, plan, regular_under, pairs, require


class ProductInputs(dict):
    """Controller-validated bindings, eligible for explicit confinement registration."""


def load_product_inputs(stdout, work, policy, vector, revision):
    work = Path(work).resolve()
    require(stdout.stat().st_size <= 4096, "product input map filename exceeds limit")
    filename = stdout.read_text().strip()
    path = regular_under(filename, work / "cache")
    require(path == work / "cache/ci-product-inputs" / revision / "environment.json",
            "unexpected product input map path")
    require(path.stat().st_size <= 128 * 1024, "product input map exceeds limit")
    def canonical_git(source, *args):
        # Confinement reowns candidate storage, including these controller-fetched
        # bare objects, to the remapped UID. Trust only this exact source for this
        # read; blob() still checks paths, immutable commits, blob type and bounds.
        require(Path(source).parent == work / "canonical-inputs", "unexpected canonical owner source")
        return git(source, "-c", "safe.directory=", "-c", "safe.directory=" + str(source), *args)
    _, expected = plan(policy, vector, lambda row: work / "canonical-inputs" / row["repo"],
                       work / "target", work / "cache", revision, git_reader=canonical_git)
    values = json.loads(path.read_text(), object_pairs_hook=pairs)
    require(isinstance(values, dict) and values == expected,
            "product input map has missing, unexpected or mismatched bindings")
    for key, value in values.items():
        if value == "{}":
            continue
        require(isinstance(value, str), "product path must be a string")
        path = Path(value)
        roots = [work / name for name in ("target", "cache") if path.is_relative_to(work / name)]
        require(len(roots) == 1, "product path is outside candidate build/cache outputs")
        regular_under(path, roots[0])
    return ProductInputs(values)
