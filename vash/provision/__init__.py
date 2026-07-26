"""Project provisioning: fingerprint a repo, source a build recipe, render a
Dockerfile, and — when the operator opts in — build/verify/repair that image.

Phase 1 (`fingerprint`, `dockerfile`) is text/analysis only and never executes
anything. Phase 2 (`build`, `repair`) adds the Docker build + verify + repair
loop; every command it issues runs INSIDE a container, never on the host, and
only when explicitly requested (`vash run --provision` / `vash provision
--build`). See `build.py`'s module docstring for the isolation stance.
"""

from vash.provision.build import (
    DockerClient,
    ProvisionResult,
    SubprocessDocker,
    image_tag_for,
    provision_environment,
)
from vash.provision.dockerfile import RenderedRecipe, render_dockerfile
from vash.provision.fingerprint import ProjectFingerprint, fingerprint
from vash.provision.repair import repair_dockerfile

__all__ = [
    "DockerClient",
    "ProjectFingerprint",
    "ProvisionResult",
    "RenderedRecipe",
    "SubprocessDocker",
    "fingerprint",
    "image_tag_for",
    "provision_environment",
    "render_dockerfile",
    "repair_dockerfile",
]
