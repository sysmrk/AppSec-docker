"""Reconstruct Debian binary package version from Trivy's explicit fields."""
from __future__ import annotations


def version(pkg, kind):
    value=pkg["Version"]
    if kind!="debian":
        return value
    release=pkg.get("Release")
    epoch=pkg.get("Epoch")
    if release and not value.endswith("-"+str(release)):
        value+="-"+str(release)
    if epoch and ":" not in value:
        value=str(epoch)+":"+value
    return value
