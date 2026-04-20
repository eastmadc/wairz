"""Post-scan service-risk annotation.

Walks the standard daemon directories (``/usr/sbin``, ``/sbin``,
``/usr/bin``, ``/bin``) and tags any component whose name matches a
known-service entry (``telnetd``, ``httpd``, ``sshd``, …) with its
risk tier. Services binaries found but not previously identified as a
component are added at low confidence so they surface in the SBOM.

Previously ``SbomService._annotate_service_risks`` in the
``sbom_service.py`` monolith.
"""

from __future__ import annotations

import os

from app.services.sbom.constants import (
    CPE_VENDOR_MAP,
    KNOWN_SERVICE_RISKS,
    IdentifiedComponent,
)
from app.services.sbom.normalization import ComponentStore

_DAEMON_DIRS = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")


def annotate_service_risks(extracted_root: str, store: ComponentStore) -> None:
    """Tag identified components with service risk levels.

    Checks binary names in standard daemon paths and annotates
    components that match known services with their risk level. Binaries
    that don't correspond to an existing component are added at low
    confidence with a ``service_risk`` metadata field.
    """
    for daemon_dir in _DAEMON_DIRS:
        abs_dir = os.path.join(extracted_root, daemon_dir.lstrip("/"))
        if not os.path.isdir(abs_dir):
            continue
        try:
            entries = os.listdir(abs_dir)
        except OSError:
            continue

        for entry in entries:
            risk = KNOWN_SERVICE_RISKS.get(entry)
            if not risk:
                continue

            # Find and annotate the matching component
            for comp in store.values():
                if comp.name.lower() == entry or entry in (
                    p.rsplit("/", 1)[-1] for p in comp.file_paths
                ):
                    comp.metadata["service_risk"] = risk
                    break
            else:
                # Service binary found but not yet identified as a component —
                # add it as a low-confidence detection so it shows up in SBOM
                rel_path = f"{daemon_dir}/{entry}"
                vendor_product = CPE_VENDOR_MAP.get(entry.lower())

                comp = IdentifiedComponent(
                    name=entry,
                    version=None,
                    type="application",
                    cpe=None,
                    purl=None,
                    supplier=vendor_product[0] if vendor_product else None,
                    detection_source="binary_strings",
                    detection_confidence="low",
                    file_paths=[rel_path],
                    metadata={"service_risk": risk},
                )
                store.add(comp)
