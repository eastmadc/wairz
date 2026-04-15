"""Phase 2a: Androguard bytecode-level insecure API pattern detection.

Scans DEX bytecode for usage of dangerous/insecure Android APIs such as:
- Insecure crypto (ECB mode, DES, static IVs, static keys, weak hashes, bare AES)
- Hardcoded credentials (SharedPreferences storage, Base64 "encryption", secret strings)
- Insecure network (HTTP URLs, disabled cert validation, SSLv3/TLS1.0)
- Insecure data storage (MODE_WORLD_READABLE/WRITABLE, external storage secrets)
- Dangerous runtime operations (Runtime.exec, native library loading)
- Logging of sensitive data (Log.d/v in release builds)
- WebView misconfigs (JS enabled, file access, save password, debug mode, mixed content)
- Insecure random (java.util.Random instead of SecureRandom)
- Clipboard manager usage (data leakage)
- SQL injection (rawQuery with string concat)
- Reflection-based API access

39 patterns across 10 categories with context-aware false positive filtering.
Tested against InsecureBankv2, DIVA, and OVAA reference vulnerable apps.

All methods are synchronous (CPU-bound) and should be called via
``loop.run_in_executor()`` from async handlers.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bytecode pattern definitions
# ---------------------------------------------------------------------------


@dataclass
class BytecodePattern:
    """Defines a pattern to search for in DEX bytecode."""

    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    cwe_ids: list[str] = field(default_factory=list)
    # Class/method patterns to match (any match triggers the finding)
    class_patterns: list[str] = field(default_factory=list)
    method_patterns: list[str] = field(default_factory=list)
    # String constant patterns to search for
    string_patterns: list[str] = field(default_factory=list)
    # Category for grouping
    category: str = "general"
    # Base confidence level for this pattern type.
    # "high" = specific API call, low FP rate (e.g. NullCipher, ECB mode string)
    # "medium" = API that *can* be misused but isn't always (e.g. SharedPreferences)
    # "low" = broad heuristic / string pattern with significant FP potential
    base_confidence: str = "high"


# Confidence level ordering for threshold filtering
CONFIDENCE_ORDER: list[str] = ["low", "medium", "high"]


# Master pattern database - covers common insecure Android API usage
BYTECODE_PATTERNS: list[BytecodePattern] = [
    # ---- Insecure Crypto ----
    BytecodePattern(
        id="crypto_ecb_mode",
        title="ECB Mode Encryption Detected",
        description=(
            "ECB mode does not provide semantic security; identical plaintext "
            "blocks produce identical ciphertext blocks. Use CBC or GCM mode."
        ),
        severity="high",
        cwe_ids=["CWE-327"],
        string_patterns=["AES/ECB", "DES/ECB", "DESede/ECB"],
        category="crypto",
    ),
    BytecodePattern(
        id="crypto_des",
        title="DES/3DES Encryption Used",
        description=(
            "DES has a 56-bit key length and is considered broken. "
            "3DES is deprecated. Use AES-256."
        ),
        severity="high",
        cwe_ids=["CWE-327"],
        string_patterns=["DES/", "DESede/"],
        class_patterns=["Ljavax/crypto/spec/DESedeKeySpec;"],
        category="crypto",
    ),
    BytecodePattern(
        id="crypto_static_iv",
        title="Static/Hardcoded IV for Cipher",
        description=(
            "Initialization vectors should be random for each encryption operation. "
            "Static IVs enable pattern detection in ciphertext."
        ),
        severity="high",
        cwe_ids=["CWE-329"],
        class_patterns=["Ljavax/crypto/spec/IvParameterSpec;"],
        method_patterns=["Ljavax/crypto/spec/IvParameterSpec;-><init>"],
        category="crypto",
        base_confidence="medium",  # IvParameterSpec usage doesn't prove IV is static
    ),
    BytecodePattern(
        id="crypto_static_key",
        title="Hardcoded Encryption Key",
        description=(
            "Encryption keys should not be hardcoded in the application. "
            "Use Android Keystore system for key management."
        ),
        severity="critical",
        cwe_ids=["CWE-321"],
        class_patterns=["Ljavax/crypto/spec/SecretKeySpec;"],
        method_patterns=["Ljavax/crypto/spec/SecretKeySpec;-><init>"],
        category="crypto",
        base_confidence="medium",  # SecretKeySpec usage doesn't prove key is hardcoded
    ),
    BytecodePattern(
        id="crypto_insecure_random",
        title="Insecure Random Number Generator",
        description=(
            "java.util.Random is not cryptographically secure. "
            "Use java.security.SecureRandom for security-sensitive operations."
        ),
        severity="medium",
        cwe_ids=["CWE-330"],
        class_patterns=["Ljava/util/Random;"],
        method_patterns=["Ljava/util/Random;-><init>"],
        category="crypto",
        base_confidence="medium",  # java.util.Random may be used for non-security purposes
    ),
    BytecodePattern(
        id="crypto_null_cipher",
        title="NullCipher Usage Detected",
        description=(
            "NullCipher provides no encryption at all. This may indicate "
            "debug code left in a production build."
        ),
        severity="critical",
        cwe_ids=["CWE-327"],
        class_patterns=["Ljavax/crypto/NullCipher;"],
        category="crypto",
    ),
    BytecodePattern(
        id="crypto_static_seed",
        title="SecureRandom with Static Seed",
        description=(
            "Setting a static seed on SecureRandom makes it predictable. "
            "Let the system provide entropy."
        ),
        severity="high",
        cwe_ids=["CWE-330"],
        method_patterns=["Ljava/security/SecureRandom;->setSeed"],
        category="crypto",
    ),
    # ---- Insecure Network ----
    BytecodePattern(
        id="network_http_url",
        title="Cleartext HTTP URL in Code",
        description=(
            "HTTP traffic is unencrypted and vulnerable to man-in-the-middle attacks. "
            "Use HTTPS for all network communications."
        ),
        severity="medium",
        cwe_ids=["CWE-319"],
        string_patterns=["http://"],
        category="network",
        base_confidence="medium",  # many benign http:// strings despite filtering
    ),
    BytecodePattern(
        id="network_trust_all_certs",
        title="Custom TrustManager Bypasses Certificate Validation",
        description=(
            "Implementing a TrustManager that trusts all certificates disables "
            "TLS certificate validation, enabling MITM attacks."
        ),
        severity="critical",
        cwe_ids=["CWE-295"],
        class_patterns=[
            "Ljavax/net/ssl/X509TrustManager;",
        ],
        method_patterns=[
            "Ljavax/net/ssl/X509TrustManager;->checkServerTrusted",
        ],
        category="network",
    ),
    BytecodePattern(
        id="network_hostname_verifier",
        title="Custom HostnameVerifier May Bypass Checks",
        description=(
            "Custom HostnameVerifier implementations may return true for all "
            "hostnames, bypassing hostname verification."
        ),
        severity="high",
        cwe_ids=["CWE-295"],
        class_patterns=["Ljavax/net/ssl/HostnameVerifier;"],
        method_patterns=["Ljavax/net/ssl/HostnameVerifier;->verify"],
        category="network",
        base_confidence="medium",  # custom verifier doesn't always bypass checks
    ),
    BytecodePattern(
        id="network_ssl_error_handler",
        title="WebView SSL Error Handler Override",
        description=(
            "Overriding onReceivedSslError without calling handler.cancel() "
            "may bypass SSL certificate errors in WebViews."
        ),
        severity="high",
        cwe_ids=["CWE-295"],
        method_patterns=[
            "Landroid/webkit/WebViewClient;->onReceivedSslError",
        ],
        category="network",
    ),
    # ---- Insecure Data Storage ----
    BytecodePattern(
        id="storage_world_readable",
        title="World-Readable File Mode",
        description=(
            "MODE_WORLD_READABLE allows any app to read this file. "
            "Use MODE_PRIVATE or encrypted storage."
        ),
        severity="high",
        cwe_ids=["CWE-276"],
        string_patterns=["MODE_WORLD_READABLE"],
        method_patterns=[
            "Landroid/content/Context;->openFileOutput",
            "Landroid/content/Context;->getSharedPreferences",
        ],
        category="storage",
    ),
    BytecodePattern(
        id="storage_world_writable",
        title="World-Writable File Mode",
        description=(
            "MODE_WORLD_WRITABLE allows any app to write to this file. "
            "Use MODE_PRIVATE or encrypted storage."
        ),
        severity="high",
        cwe_ids=["CWE-276"],
        string_patterns=["MODE_WORLD_WRITABLE"],
        category="storage",
    ),
    BytecodePattern(
        id="storage_external_write",
        title="Sensitive Data on External Storage",
        description=(
            "External storage is world-readable. Sensitive data should "
            "be stored in internal storage with encryption."
        ),
        severity="medium",
        cwe_ids=["CWE-922"],
        method_patterns=[
            "Landroid/os/Environment;->getExternalStorageDirectory",
            "Landroid/os/Environment;->getExternalStoragePublicDirectory",
        ],
        category="storage",
        base_confidence="medium",  # external storage use may be for non-sensitive data
    ),
    BytecodePattern(
        id="storage_sqlite_plaintext",
        title="SQLite Database Without Encryption",
        description=(
            "Using SQLite without encryption (e.g., SQLCipher) means "
            "sensitive data is stored in plaintext on disk."
        ),
        severity="medium",
        cwe_ids=["CWE-312"],
        class_patterns=["Landroid/database/sqlite/SQLiteOpenHelper;"],
        method_patterns=[
            "Landroid/database/sqlite/SQLiteDatabase;->openOrCreateDatabase",
        ],
        category="storage",
        base_confidence="medium",  # SQLite without encryption is common; may not store secrets
    ),
    # ---- Dangerous Runtime ----
    BytecodePattern(
        id="runtime_exec",
        title="Runtime Command Execution",
        description=(
            "Runtime.exec() can execute arbitrary system commands. "
            "Verify that command arguments are not user-controlled."
        ),
        severity="high",
        cwe_ids=["CWE-78"],
        method_patterns=[
            "Ljava/lang/Runtime;->exec",
        ],
        category="runtime",
    ),
    BytecodePattern(
        id="runtime_process_builder",
        title="ProcessBuilder Command Execution",
        description=(
            "ProcessBuilder can execute system commands. Ensure inputs are sanitized."
        ),
        severity="medium",
        cwe_ids=["CWE-78"],
        class_patterns=["Ljava/lang/ProcessBuilder;"],
        method_patterns=["Ljava/lang/ProcessBuilder;-><init>"],
        category="runtime",
        base_confidence="medium",  # legitimate use in many system utilities
    ),
    BytecodePattern(
        id="runtime_native_load",
        title="Native Library Loading",
        description=(
            "Loading native libraries via System.loadLibrary/load. "
            "Native code bypasses Java security sandbox."
        ),
        severity="info",
        cwe_ids=["CWE-111"],
        method_patterns=[
            "Ljava/lang/System;->loadLibrary",
            "Ljava/lang/System;->load",
            "Ljava/lang/Runtime;->loadLibrary",
        ],
        category="runtime",
        base_confidence="low",  # very common in apps with native components
    ),
    BytecodePattern(
        id="runtime_reflection",
        title="Java Reflection API Usage",
        description=(
            "Reflection can bypass access controls and invoke private methods. "
            "May be used to access hidden Android APIs."
        ),
        severity="low",
        cwe_ids=["CWE-470"],
        method_patterns=[
            "Ljava/lang/Class;->forName",
            "Ljava/lang/Class;->getDeclaredMethod",
            "Ljava/lang/Class;->getDeclaredField",
            "Ljava/lang/reflect/Method;->invoke",
        ],
        category="runtime",
        base_confidence="low",  # reflection is extremely common in Android frameworks
    ),
    # ---- Logging ----
    BytecodePattern(
        id="logging_verbose",
        title="Verbose/Debug Logging in Code",
        description=(
            "Log.d()/Log.v() output is accessible to other apps on older "
            "Android versions and to ADB. Sensitive data may be leaked."
        ),
        severity="low",
        cwe_ids=["CWE-532"],
        method_patterns=[
            "Landroid/util/Log;->d",
            "Landroid/util/Log;->v",
            "Landroid/util/Log;->i",
        ],
        category="logging",
        base_confidence="low",  # logging is ubiquitous; sensitive data logging is rare
    ),
    BytecodePattern(
        id="logging_exception",
        title="Exception Stack Trace Printed",
        description=(
            "printStackTrace() exposes internal application structure. "
            "Use proper logging frameworks with appropriate log levels."
        ),
        severity="low",
        cwe_ids=["CWE-209"],
        method_patterns=[
            "Ljava/lang/Throwable;->printStackTrace",
            "Ljava/lang/Exception;->printStackTrace",
        ],
        category="logging",
        base_confidence="low",  # very common; information exposure is usually minor
    ),
    # ---- WebView Security ----
    BytecodePattern(
        id="webview_js_enabled",
        title="JavaScript Enabled in WebView",
        description=(
            "Enabling JavaScript in WebView increases the attack surface "
            "for XSS and other web-based attacks."
        ),
        severity="medium",
        cwe_ids=["CWE-79"],
        method_patterns=[
            "Landroid/webkit/WebSettings;->setJavaScriptEnabled",
        ],
        category="webview",
        base_confidence="medium",  # JS is commonly enabled; exploitability depends on context
    ),
    BytecodePattern(
        id="webview_file_access",
        title="File Access Enabled in WebView",
        description=(
            "File access in WebView can lead to local file disclosure "
            "if combined with JavaScript injection."
        ),
        severity="high",
        cwe_ids=["CWE-200"],
        method_patterns=[
            "Landroid/webkit/WebSettings;->setAllowFileAccess",
            "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs",
            "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs",
        ],
        category="webview",
    ),
    BytecodePattern(
        id="webview_js_interface",
        title="JavaScript Interface Exposed to WebView",
        description=(
            "addJavascriptInterface exposes Java objects to JavaScript. "
            "On Android < 4.2, this allows arbitrary code execution."
        ),
        severity="high",
        cwe_ids=["CWE-749"],
        method_patterns=[
            "Landroid/webkit/WebView;->addJavascriptInterface",
        ],
        category="webview",
    ),
    # ---- SQL Injection ----
    BytecodePattern(
        id="sql_raw_query",
        title="Raw SQL Query Execution",
        description=(
            "rawQuery with string concatenation may be vulnerable to SQL injection. "
            "Use parameterized queries (selection args)."
        ),
        severity="medium",
        cwe_ids=["CWE-89"],
        method_patterns=[
            "Landroid/database/sqlite/SQLiteDatabase;->rawQuery",
            "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
        ],
        category="sql",
        base_confidence="medium",  # rawQuery/execSQL not always used with string concat
    ),
    # ---- Clipboard ----
    BytecodePattern(
        id="clipboard_usage",
        title="Clipboard Manager Usage",
        description=(
            "Data placed on the clipboard is accessible to all apps. "
            "Avoid copying sensitive data (passwords, tokens) to clipboard."
        ),
        severity="low",
        cwe_ids=["CWE-200"],
        class_patterns=["Landroid/content/ClipboardManager;"],
        method_patterns=[
            "Landroid/content/ClipboardManager;->setPrimaryClip",
        ],
        category="clipboard",
        base_confidence="medium",  # clipboard use is common; sensitive data copy is rare
    ),
    # ---- Intent ----
    BytecodePattern(
        id="intent_implicit_sensitive",
        title="Implicit Intent for Sensitive Action",
        description=(
            "Sending sensitive data via implicit intents can be intercepted "
            "by any app with a matching intent filter."
        ),
        severity="medium",
        cwe_ids=["CWE-927"],
        method_patterns=[
            "Landroid/content/Context;->sendBroadcast",
            "Landroid/content/Context;->sendOrderedBroadcast",
        ],
        category="ipc",
        base_confidence="medium",  # implicit intents are common; not always with sensitive data
    ),
    BytecodePattern(
        id="pending_intent_mutable",
        title="PendingIntent Without FLAG_IMMUTABLE",
        description=(
            "PendingIntents without FLAG_IMMUTABLE can be modified by "
            "receiving apps, potentially redirecting actions."
        ),
        severity="medium",
        cwe_ids=["CWE-927"],
        method_patterns=[
            "Landroid/app/PendingIntent;->getActivity",
            "Landroid/app/PendingIntent;->getBroadcast",
            "Landroid/app/PendingIntent;->getService",
        ],
        category="ipc",
        base_confidence="medium",  # PendingIntent usage is common; FLAG_IMMUTABLE check needs context
    ),
    # ---- Temp Files ----
    BytecodePattern(
        id="temp_file_creation",
        title="Temporary File Creation",
        description=(
            "Temporary files may persist and be accessible to other apps "
            "depending on their location and permissions."
        ),
        severity="low",
        cwe_ids=["CWE-377"],
        method_patterns=[
            "Ljava/io/File;->createTempFile",
        ],
        category="storage",
        base_confidence="low",  # temp file creation is normal; rarely a security issue
    ),
    # ---- Hardcoded Credentials ----
    BytecodePattern(
        id="credentials_sharedprefs",
        title="Credentials Stored in SharedPreferences",
        description=(
            "SharedPreferences stores data in plaintext XML on disk. Sensitive "
            "credentials (passwords, tokens, PINs) should use EncryptedSharedPreferences "
            "or Android Keystore. InsecureBankv2 stores login credentials this way."
        ),
        severity="high",
        cwe_ids=["CWE-312", "CWE-256"],
        method_patterns=[
            "Landroid/content/SharedPreferences$Editor;->putString",
            "Landroid/content/SharedPreferences;->getString",
        ],
        category="credentials",
        base_confidence="medium",  # SharedPreferences is common; not all uses store credentials
    ),
    BytecodePattern(
        id="credentials_base64_encode",
        title="Base64 Encoding Used (Potential Credential Obfuscation)",
        description=(
            "Base64 is an encoding, not encryption. Using Base64 to 'protect' "
            "credentials or sensitive data provides zero security. "
            "InsecureBankv2 uses Base64 as a substitute for real encryption."
        ),
        severity="medium",
        cwe_ids=["CWE-261", "CWE-327"],
        method_patterns=[
            "Landroid/util/Base64;->encode",
            "Landroid/util/Base64;->encodeToString",
            "Landroid/util/Base64;->decode",
            "Ljava/util/Base64$Encoder;->encode",
            "Ljava/util/Base64$Decoder;->decode",
        ],
        category="credentials",
        base_confidence="low",  # Base64 is widely used for non-credential purposes
    ),
    BytecodePattern(
        id="credentials_hardcoded_string",
        title="Potential Hardcoded Secret/Password in Code",
        description=(
            "Strings resembling passwords, API keys, or secret keys were found "
            "hardcoded in the application bytecode. Secrets should be stored in "
            "Android Keystore or fetched from a secure backend."
        ),
        severity="high",
        cwe_ids=["CWE-798", "CWE-259"],
        string_patterns=[
            "password",
            "passwd",
            "secret_key",
            "api_key",
            "apikey",
            "secret key",
            "super secret",
        ],
        category="credentials",
        base_confidence="low",  # string pattern matching is inherently noisy
    ),
    # ---- Insecure Crypto (extended) ----
    BytecodePattern(
        id="crypto_weak_hash",
        title="Weak Hash Algorithm (MD5/SHA1)",
        description=(
            "MD5 and SHA-1 are cryptographically broken and should not be used "
            "for security purposes. Use SHA-256 or SHA-3."
        ),
        severity="high",
        cwe_ids=["CWE-328", "CWE-327"],
        string_patterns=["MD5", "SHA-1", "SHA1"],
        method_patterns=[
            "Ljava/security/MessageDigest;->getInstance",
        ],
        category="crypto",
        base_confidence="medium",  # MD5/SHA1 strings appear in many non-crypto contexts
    ),
    # Note: AES without mode specification ("AES" instead of "AES/CBC/..." etc.)
    # defaults to ECB on most Android implementations. This is detected via a
    # special check in _scan_strings that looks for the bare "AES" string
    # constant without a "/" separator. See _is_bare_aes_string().
    BytecodePattern(
        id="crypto_no_key_derivation",
        title="Raw Key Material Without Key Derivation",
        description=(
            "Using raw bytes as encryption keys without a key derivation function "
            "(PBKDF2, Argon2) is insecure. Hardcoded byte arrays as keys are trivially "
            "extractable from APKs. InsecureBankv2 uses getBytes() as the key directly."
        ),
        severity="critical",
        cwe_ids=["CWE-321", "CWE-916"],
        method_patterns=[
            "Ljava/lang/String;->getBytes",
        ],
        # Only flagged when near crypto context (will have high FP rate standalone,
        # but combined with SecretKeySpec finding it adds context)
        category="crypto",
        base_confidence="low",  # String.getBytes() is ubiquitous; only relevant in crypto context
    ),
    # ---- WebView Security (extended) ----
    BytecodePattern(
        id="webview_save_password",
        title="WebView Save Password Enabled",
        description=(
            "setSavePassword(true) stores user passwords in the WebView "
            "database in cleartext. This has been deprecated since API 18."
        ),
        severity="high",
        cwe_ids=["CWE-312"],
        method_patterns=[
            "Landroid/webkit/WebSettings;->setSavePassword",
        ],
        category="webview",
    ),
    BytecodePattern(
        id="webview_dom_storage",
        title="DOM Storage Enabled in WebView",
        description=(
            "Enabling DOM storage in WebView allows JavaScript to persist data "
            "locally. Combined with JavaScript injection, this can lead to "
            "data theft or session hijacking."
        ),
        severity="low",
        cwe_ids=["CWE-922"],
        method_patterns=[
            "Landroid/webkit/WebSettings;->setDomStorageEnabled",
        ],
        category="webview",
        base_confidence="low",  # DOM storage is commonly enabled; rarely exploitable alone
    ),
    BytecodePattern(
        id="webview_content_access",
        title="Content Provider Access Enabled in WebView",
        description=(
            "setAllowContentAccess allows WebView to access content:// URIs, "
            "potentially exposing data from other apps' content providers."
        ),
        severity="medium",
        cwe_ids=["CWE-200"],
        method_patterns=[
            "Landroid/webkit/WebSettings;->setAllowContentAccess",
        ],
        category="webview",
        base_confidence="medium",  # content access may be legitimate in some WebView contexts
    ),
    BytecodePattern(
        id="webview_mixed_content",
        title="Mixed Content Allowed in WebView",
        description=(
            "MIXED_CONTENT_ALWAYS_ALLOW lets WebView load HTTP resources in HTTPS "
            "pages, enabling man-in-the-middle attacks on sub-resources."
        ),
        severity="high",
        cwe_ids=["CWE-319"],
        method_patterns=[
            "Landroid/webkit/WebSettings;->setMixedContentMode",
        ],
        category="webview",
    ),
    BytecodePattern(
        id="webview_debug_enabled",
        title="WebView Debugging Enabled",
        description=(
            "setWebContentsDebuggingEnabled(true) allows Chrome DevTools to "
            "attach to the WebView, exposing all page data and JavaScript execution."
        ),
        severity="high",
        cwe_ids=["CWE-489"],
        method_patterns=[
            "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled",
        ],
        category="webview",
    ),
]

# Quick index: set of all method prefixes for fast matching
_METHOD_PREFIXES: set[str] = set()
_STRING_NEEDLES: set[str] = set()
_CLASS_DESCRIPTORS: set[str] = set()

for _p in BYTECODE_PATTERNS:
    _METHOD_PREFIXES.update(_p.method_patterns)
    _STRING_NEEDLES.update(_p.string_patterns)
    _CLASS_DESCRIPTORS.update(_p.class_patterns)

# Credential-related string needles (lowered) — used for FP filtering
_CREDENTIAL_NEEDLES: frozenset[str] = frozenset(
    sp.lower()
    for _p in BYTECODE_PATTERNS
    if _p.id == "credentials_hardcoded_string"
    for sp in _p.string_patterns
)


# ---------------------------------------------------------------------------
# Bytecode scanner
# ---------------------------------------------------------------------------


@dataclass
class BytecodeFinding:
    """A single finding from bytecode analysis."""

    pattern_id: str
    title: str
    description: str
    severity: str
    cwe_ids: list[str]
    category: str
    locations: list[dict[str, str]]  # class_name, method_name, etc.
    count: int = 0
    confidence: str = "high"  # high, medium, low — computed from base + signals

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe_ids": self.cwe_ids,
            "category": self.category,
            "locations": self.locations[:20],  # cap to avoid huge output
            "total_occurrences": self.count,
        }


class BytecodeAnalysisService:
    """Scans APK DEX bytecode for insecure API usage patterns.

    Uses Androguard's analysis objects (ClassAnalysis, MethodAnalysis)
    to detect cross-references to known-dangerous APIs without
    performing full decompilation.
    """

    def scan_apk(
        self,
        apk_path: str,
        *,
        apk_location: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Scan an APK's bytecode for insecure API patterns.

        Args:
            apk_path: Absolute path to the APK file on disk.
            apk_location: Firmware location path (e.g. /system/priv-app/...)
                          for severity adjustments.
            timeout: Maximum seconds before aborting (default 30).

        Returns:
            Dict with findings, summary statistics, and timing info.
        """
        from androguard.misc import AnalyzeAPK

        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        start = time.monotonic()

        # Phase 1: Parse APK and build analysis object
        apk_obj, dex_list, analysis = AnalyzeAPK(apk_path)
        parse_elapsed = time.monotonic() - start
        logger.info(
            "Bytecode: parsed %s in %.1fs (%d DEX files)",
            apk_obj.get_package(),
            parse_elapsed,
            len(dex_list) if dex_list else 0,
        )

        if analysis is None:
            return {
                "package": apk_obj.get_package() or "unknown",
                "error": "No DEX code found in APK",
                "findings": [],
                "summary": {},
                "elapsed_seconds": round(time.monotonic() - start, 2),
            }

        # Phase 2: Scan for patterns
        findings = self._scan_analysis(analysis, timeout, start)

        # Phase 3: Compute confidence scores for each finding
        self._compute_confidence(findings)

        # Phase 4: Apply firmware context adjustments
        if apk_location:
            findings = self._adjust_severity_for_context(findings, apk_location)

        elapsed = round(time.monotonic() - start, 2)

        # Build summary
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        confidence_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
            confidence_counts[f.confidence] = confidence_counts.get(f.confidence, 0) + 1

        return {
            "package": apk_obj.get_package() or "unknown",
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "by_category": category_counts,
                "by_confidence": confidence_counts,
            },
            "elapsed_seconds": elapsed,
            "dex_count": len(dex_list) if dex_list else 0,
        }

    def _scan_analysis(
        self,
        analysis: Any,
        timeout: float,
        start_time: float,
    ) -> list[BytecodeFinding]:
        """Scan the Androguard analysis object for all patterns."""
        # Collect findings keyed by pattern_id
        findings_map: dict[str, BytecodeFinding] = {}

        # Strategy 1: Scan method cross-references
        self._scan_method_xrefs(analysis, findings_map, timeout, start_time)

        # Strategy 2: Scan string constants
        if (time.monotonic() - start_time) < timeout:
            self._scan_strings(analysis, findings_map, timeout, start_time)

        # Strategy 3: Scan class usage
        if (time.monotonic() - start_time) < timeout:
            self._scan_class_usage(analysis, findings_map, timeout, start_time)

        # Post-processing: remove high-FP findings that require context
        self._filter_contextual_findings(findings_map)

        return list(findings_map.values())

    @staticmethod
    def _filter_contextual_findings(
        findings_map: dict[str, BytecodeFinding],
    ) -> None:
        """Remove findings that only make sense in certain contexts.

        - ``crypto_no_key_derivation`` (String.getBytes) is extremely common;
          only keep it when crypto APIs (SecretKeySpec, Cipher) are also used.
        - ``credentials_hardcoded_string`` string patterns like "password" are
          common in UI labels; keep only if SharedPreferences or crypto is used.
        """
        has_crypto_context = any(
            pid in findings_map
            for pid in (
                "crypto_static_key",
                "crypto_ecb_mode",
                "crypto_des",
                "crypto_static_iv",
                "crypto_null_cipher",
                "crypto_aes_default_mode",
            )
        )

        has_credential_storage = any(
            pid in findings_map
            for pid in ("credentials_sharedprefs", "storage_world_readable")
        )

        # String.getBytes() is everywhere — only relevant near crypto usage
        if "crypto_no_key_derivation" in findings_map and not has_crypto_context:
            del findings_map["crypto_no_key_derivation"]

        # "password"/"secret" strings are in UI labels — only flag with storage context
        if "credentials_hardcoded_string" in findings_map:
            if not has_credential_storage and not has_crypto_context:
                del findings_map["credentials_hardcoded_string"]

        # Weak hash (MD5/SHA1) string patterns: the string "MD5" appears in
        # many non-crypto contexts (HTTP headers, content-type negotiation).
        # Keep only when MessageDigest.getInstance is also called.
        if "crypto_weak_hash" in findings_map:
            has_message_digest = any(
                loc.get("target", "").startswith("Ljava/security/MessageDigest;")
                for loc in findings_map["crypto_weak_hash"].locations
            )
            # If we only have string matches (no method xrefs), it's likely FP
            if not has_message_digest and not has_crypto_context:
                del findings_map["crypto_weak_hash"]

    def _scan_method_xrefs(
        self,
        analysis: Any,
        findings_map: dict[str, BytecodeFinding],
        timeout: float,
        start_time: float,
    ) -> None:
        """Scan for cross-references to dangerous methods."""
        # Build a reverse index: method_pattern -> list of patterns
        method_to_patterns: dict[str, list[BytecodePattern]] = {}
        for pat in BYTECODE_PATTERNS:
            for mp in pat.method_patterns:
                method_to_patterns.setdefault(mp, []).append(pat)

        if not method_to_patterns:
            return

        # Get all methods from analysis and check for xrefs
        try:
            methods = analysis.get_methods()
        except Exception:
            return

        checked = 0
        for method_analysis in methods:
            if (time.monotonic() - start_time) >= timeout:
                logger.warning("Bytecode scan timed out during method xref scan")
                break

            checked += 1
            try:
                method_obj = method_analysis.get_method()
                if method_obj is None:
                    continue

                # Get the full method descriptor: Lclass;->methodName
                class_name = getattr(method_obj, "class_name", "") or ""
                method_name = getattr(method_obj, "name", "") or ""
                if not class_name or not method_name:
                    continue

                full_ref = f"{class_name}->{method_name}"

                # Check against patterns (prefix match)
                for pattern_key, pattern_list in method_to_patterns.items():
                    if full_ref.startswith(pattern_key) or full_ref == pattern_key:
                        # Found a match - get callers (xrefs_from)
                        xref_locations = []
                        try:
                            xrefs = method_analysis.get_xref_from()
                            for ref_class, ref_method, _ in xrefs:
                                loc = {
                                    "caller_class": str(
                                        getattr(ref_class, "name", "unknown")
                                    ),
                                    "caller_method": str(
                                        getattr(ref_method, "name", "unknown")
                                    ),
                                    "target": full_ref,
                                }
                                xref_locations.append(loc)
                        except Exception:
                            xref_locations = [{"target": full_ref}]

                        for pat in pattern_list:
                            if pat.id not in findings_map:
                                findings_map[pat.id] = BytecodeFinding(
                                    pattern_id=pat.id,
                                    title=pat.title,
                                    description=pat.description,
                                    severity=pat.severity,
                                    cwe_ids=pat.cwe_ids,
                                    category=pat.category,
                                    locations=[],
                                )
                            f = findings_map[pat.id]
                            f.locations.extend(xref_locations)
                            f.count += max(len(xref_locations), 1)
            except Exception:
                continue

    def _scan_strings(
        self,
        analysis: Any,
        findings_map: dict[str, BytecodeFinding],
        timeout: float,
        start_time: float,
    ) -> None:
        """Scan string constants in DEX for dangerous patterns."""
        string_to_patterns: dict[str, list[BytecodePattern]] = {}
        for pat in BYTECODE_PATTERNS:
            for sp in pat.string_patterns:
                string_to_patterns.setdefault(sp, []).append(pat)

        if not string_to_patterns:
            return

        try:
            strings = analysis.get_strings()
        except Exception:
            return

        # Pre-lowercase the needles for case-insensitive matching
        lower_needles = {k.lower(): k for k in string_to_patterns}

        for string_analysis in strings:
            if (time.monotonic() - start_time) >= timeout:
                logger.warning("Bytecode scan timed out during string scan")
                break

            try:
                value = string_analysis.get_value()
                if not value or len(value) > 2048:
                    continue

                value_lower = value.lower()

                # Special check: bare "AES" without mode (defaults to ECB)
                stripped = value.strip()
                if stripped == "AES":
                    self._record_bare_aes_finding(findings_map, stripped)

                for needle_lower, needle_orig in lower_needles.items():
                    if needle_lower in value_lower:
                        # Filter out false positives for http:// patterns
                        if needle_lower == "http://" and self._is_benign_http(value):
                            continue

                        # Filter credential strings that are clearly UI/metadata
                        if needle_lower in _CREDENTIAL_NEEDLES:
                            if self._is_benign_credential_string(value):
                                continue

                        for pat in string_to_patterns[needle_orig]:
                            if pat.id not in findings_map:
                                findings_map[pat.id] = BytecodeFinding(
                                    pattern_id=pat.id,
                                    title=pat.title,
                                    description=pat.description,
                                    severity=pat.severity,
                                    cwe_ids=pat.cwe_ids,
                                    category=pat.category,
                                    locations=[],
                                )
                            f = findings_map[pat.id]
                            # Truncate long strings
                            display = value[:120] + ("..." if len(value) > 120 else "")
                            f.locations.append({"string_value": display})
                            f.count += 1
            except Exception:
                continue

    @staticmethod
    def _record_bare_aes_finding(
        findings_map: dict[str, BytecodeFinding],
        value: str,
    ) -> None:
        """Record a finding for bare 'AES' cipher algorithm without mode."""
        pid = "crypto_aes_default_mode"
        if pid not in findings_map:
            findings_map[pid] = BytecodeFinding(
                pattern_id=pid,
                title="AES Without Explicit Mode Specification",
                description=(
                    "Using Cipher.getInstance('AES') without specifying a mode "
                    "defaults to ECB on most Android implementations, which is "
                    "insecure. Always specify mode and padding: "
                    "AES/GCM/NoPadding or AES/CBC/PKCS5Padding."
                ),
                severity="high",
                cwe_ids=["CWE-327"],
                category="crypto",
                locations=[],
            )
        f = findings_map[pid]
        f.locations.append({"string_value": value})
        f.count += 1

    @staticmethod
    def _is_benign_credential_string(value: str) -> bool:
        """Filter out credential-related strings that are clearly UI labels.

        Returns True for strings that are likely UI text, XML attribute names,
        or framework constants rather than actual hardcoded secrets.
        """
        v = value.strip()

        # Very short or very long strings are unlikely to be secrets
        if len(v) < 4 or len(v) > 200:
            return True

        # Common Android resource/UI patterns
        benign_patterns = (
            "password",          # Just the word "password" as a label
            "enter password",
            "enter your password",
            "password_toggle",
            "password_hint",
            "passwordToggle",
            "hint_password",
            "type_password",
            "inputType=\"textPassword\"",
            "android:password",
            "Password:",
            "Password",
            "password_visibility",
        )
        v_lower = v.lower()

        # If the string is EXACTLY one of the benign patterns, skip it
        if v_lower in {p.lower() for p in benign_patterns}:
            return True

        # Strings that look like XML attributes or resource IDs
        if v.startswith("@") or v.startswith("?") or "xmlns:" in v:
            return True

        return False

    @staticmethod
    def _is_benign_http(url: str) -> bool:
        """Filter out known-benign HTTP URLs to reduce false positives."""
        benign_prefixes = (
            "http://schemas.android.com",
            "http://www.w3.org",
            "http://ns.adobe.com",
            "http://xmlpull.org",
            "http://xml.org",
            "http://apache.org",
            "http://www.apache.org",
            "http://json.org",
            "http://localhost",
            "http://127.0.0.1",
            "http://10.0.2.2",  # Android emulator host
        )
        url_lower = url.lower().strip()
        return any(url_lower.startswith(p) for p in benign_prefixes)

    def _scan_class_usage(
        self,
        analysis: Any,
        findings_map: dict[str, BytecodeFinding],
        timeout: float,
        start_time: float,
    ) -> None:
        """Scan for usage of dangerous classes (without specific method filter)."""
        # Only check class_patterns that don't already have method_patterns
        # (method xref scan is more precise)
        class_only_patterns: dict[str, list[BytecodePattern]] = {}
        for pat in BYTECODE_PATTERNS:
            if pat.class_patterns and not pat.method_patterns:
                for cp in pat.class_patterns:
                    class_only_patterns.setdefault(cp, []).append(pat)

        if not class_only_patterns:
            return

        try:
            classes = analysis.get_classes()
        except Exception:
            return

        for class_analysis in classes:
            if (time.monotonic() - start_time) >= timeout:
                break

            try:
                class_name = class_analysis.name
                if not class_name:
                    continue

                # Check if this class extends/implements a dangerous class
                for pattern_class, pattern_list in class_only_patterns.items():
                    if class_name == pattern_class:
                        # This IS the dangerous class - look at who uses it
                        try:
                            xrefs = class_analysis.get_xref_from()
                            for ref_class, ref_method in xrefs:
                                for pat in pattern_list:
                                    if pat.id not in findings_map:
                                        findings_map[pat.id] = BytecodeFinding(
                                            pattern_id=pat.id,
                                            title=pat.title,
                                            description=pat.description,
                                            severity=pat.severity,
                                            cwe_ids=pat.cwe_ids,
                                            category=pat.category,
                                            locations=[],
                                        )
                                    f = findings_map[pat.id]
                                    loc = {
                                        "using_class": str(
                                            getattr(ref_class, "name", "unknown")
                                        ),
                                        "using_method": str(
                                            getattr(ref_method, "name", "unknown")
                                        ),
                                        "dangerous_class": pattern_class,
                                    }
                                    f.locations.append(loc)
                                    f.count += 1
                        except Exception:
                            # Still record the class as used
                            for pat in pattern_list:
                                if pat.id not in findings_map:
                                    findings_map[pat.id] = BytecodeFinding(
                                        pattern_id=pat.id,
                                        title=pat.title,
                                        description=pat.description,
                                        severity=pat.severity,
                                        cwe_ids=pat.cwe_ids,
                                        category=pat.category,
                                        locations=[],
                                    )
                                findings_map[pat.id].count += 1
            except Exception:
                continue

    @staticmethod
    def _compute_confidence(findings: list[BytecodeFinding]) -> None:
        """Compute final confidence for each finding based on detection signals.

        The confidence score starts at the pattern's ``base_confidence`` and is
        adjusted up or down based on evidence quality:

        **Boost signals** (can promote medium→high):
        - Has cross-reference locations with specific caller info (xref evidence)
        - Multiple independent call sites (≥3 distinct callers)

        **Reduction signals** (can demote medium→low):
        - Only string-based matches with no method xref backing
        - Single occurrence with no caller information

        The final confidence is clamped to [low, medium, high].
        """
        # Build a lookup for base confidence from patterns
        pattern_base: dict[str, str] = {
            p.id: p.base_confidence for p in BYTECODE_PATTERNS
        }

        for finding in findings:
            base = pattern_base.get(finding.pattern_id, "high")
            base_idx = CONFIDENCE_ORDER.index(base) if base in CONFIDENCE_ORDER else 2

            # Count evidence quality signals
            has_xref = any(
                "caller_class" in loc or "using_class" in loc
                for loc in finding.locations
            )
            string_only = all(
                "string_value" in loc and "caller_class" not in loc
                for loc in finding.locations
            ) if finding.locations else False

            # Count distinct callers
            distinct_callers = set()
            for loc in finding.locations:
                caller = loc.get("caller_class")
                if caller:
                    distinct_callers.add(caller)

            # Apply adjustments
            adj = 0

            # Boost: strong xref evidence with multiple callers
            if has_xref and len(distinct_callers) >= 3:
                adj += 1
            elif has_xref and len(distinct_callers) >= 1:
                # Mild boost: at least one concrete caller
                # Only boost if base is low (don't exceed high)
                if base_idx == 0:
                    adj += 1

            # Reduce: string-only match without xref backing
            if string_only and not has_xref:
                adj -= 1

            # Reduce: single occurrence without caller info (weak signal)
            if finding.count <= 1 and not has_xref:
                adj -= 1

            final_idx = max(0, min(len(CONFIDENCE_ORDER) - 1, base_idx + adj))
            finding.confidence = CONFIDENCE_ORDER[final_idx]

    @staticmethod
    def _adjust_severity_for_context(
        findings: list[BytecodeFinding],
        apk_location: str,
    ) -> list[BytecodeFinding]:
        """Adjust finding severity based on firmware context.

        - priv-app: bump severity (system privileged apps have more impact)
        - system/app with platform cert: reduce some findings (expected behavior)
        """
        is_priv_app = "priv-app" in apk_location
        is_system_app = (
            apk_location.startswith("/system/")
            or apk_location.startswith("system/")
        )

        severity_order = ["info", "low", "medium", "high", "critical"]

        for finding in findings:
            idx = severity_order.index(finding.severity) if finding.severity in severity_order else 2

            if is_priv_app:
                # Privileged apps: crypto/network/storage/credential issues are worse
                if finding.category in ("crypto", "network", "storage", "credentials"):
                    idx = min(idx + 1, len(severity_order) - 1)
                    finding.severity = severity_order[idx]

            if is_system_app:
                # System apps commonly use reflection, native code, runtime exec
                # These are expected; reduce noise
                if finding.category == "runtime" and finding.pattern_id in (
                    "runtime_native_load",
                    "runtime_reflection",
                    "runtime_process_builder",
                ):
                    idx = max(idx - 1, 0)
                    finding.severity = severity_order[idx]

                # Logging in system apps is less of a concern
                if finding.category == "logging":
                    idx = max(idx - 1, 0)
                    finding.severity = severity_order[idx]

        return findings
