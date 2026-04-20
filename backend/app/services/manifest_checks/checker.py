"""Composition root for manifest security checks.

Replaces the legacy ``ManifestChecksMixin`` with a composition-based
``ManifestChecker`` that aggregates six topic modules:

- ``BackupAndDebugChecks`` (MANIFEST-001, -002, -004, -015)
- ``NetworkSecurityChecks`` (MANIFEST-003, -011)
- ``ComponentChecks`` (MANIFEST-006, -008, -009, -010, -012, -013, -017)
- ``PermissionChecks`` (MANIFEST-007, -016)
- ``SigningChecks`` (MANIFEST-014, -018 + ``_has_signature_or_system_protection``)
- ``MiscChecks`` (MANIFEST-005)

Each topic module is instantiated with a back-reference to the
composing scanner (``AndroguardService``) so helpers can reach scanner
state if needed.  ``AndroguardService`` consumes this via thin
forwarders (``def _check_debuggable(self, *a, **k): return
self.manifest_checker._check_debuggable(*a, **k)``) to preserve the
existing call sites in ``scan_manifest_security`` without a sweeping
rename.  The forwarders are a transitional surface — a future cleanup
pass can remove them once all call sites switch to
``self.manifest_checker._check_*`` directly.
"""

from __future__ import annotations

from typing import Any

from app.services.manifest_checks.backup_and_debug import BackupAndDebugChecks
from app.services.manifest_checks.components import ComponentChecks
from app.services.manifest_checks.misc import MiscChecks
from app.services.manifest_checks.network_security import NetworkSecurityChecks
from app.services.manifest_checks.permissions import PermissionChecks
from app.services.manifest_checks.signing import SigningChecks


class ManifestChecker:
    """Aggregates the six manifest-check topic modules.

    Exposes every ``_check_*`` method from each composed topic as an
    attribute of ``self``, so callers can use
    ``checker._check_debuggable(apk_obj)`` without caring which topic
    module owns the method.  The attribute binding happens in
    ``__init__`` so that each delegated method retains correct ``self``
    semantics of its owning topic instance.
    """

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

        # Instantiate topic modules, sharing the same scanner back-reference.
        self.backup_and_debug = BackupAndDebugChecks(scanner)
        self.network_security = NetworkSecurityChecks(scanner)
        self.components = ComponentChecks(scanner)
        self.permissions = PermissionChecks(scanner)
        self.signing = SigningChecks(scanner)
        self.misc = MiscChecks(scanner)

        # ---- Bind _check_* methods + _has_signature_or_system_protection
        # to this composition root so callers can use
        # ``checker._check_<name>(...)`` without a topic-module lookup.

        # backup_and_debug.py
        self._check_debuggable = self.backup_and_debug._check_debuggable
        self._check_allow_backup = self.backup_and_debug._check_allow_backup
        self._check_test_only = self.backup_and_debug._check_test_only
        self._check_backup_agent = self.backup_and_debug._check_backup_agent

        # network_security.py
        self._check_cleartext_traffic = self.network_security._check_cleartext_traffic
        self._check_network_security_config = (
            self.network_security._check_network_security_config
        )

        # components.py
        self._check_exported_components = self.components._check_exported_components
        self._check_strandhogg_v1 = self.components._check_strandhogg_v1
        self._check_strandhogg_v2 = self.components._check_strandhogg_v2
        self._check_app_links = self.components._check_app_links
        self._check_allow_task_reparenting = (
            self.components._check_allow_task_reparenting
        )
        self._check_implicit_intent_hijacking = (
            self.components._check_implicit_intent_hijacking
        )
        self._check_intent_scheme_hijacking = (
            self.components._check_intent_scheme_hijacking
        )

        # permissions.py
        self._check_custom_permissions = self.permissions._check_custom_permissions
        self._check_dangerous_permissions = (
            self.permissions._check_dangerous_permissions
        )

        # signing.py
        self._check_signing_scheme = self.signing._check_signing_scheme
        self._check_shared_user_id = self.signing._check_shared_user_id
        self._has_signature_or_system_protection = (
            self.signing._has_signature_or_system_protection
        )

        # misc.py
        self._check_min_sdk = self.misc._check_min_sdk
