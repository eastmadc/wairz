"""Manifest XML definitions for synthetic APK test fixtures.

Each manifest is designed to trigger specific MANIFEST-NNN security checks
in AndroguardService.scan_manifest_security(). The manifests are used both
by the APK generator script (to create real APK files) and by the pytest
fixture factories (to create mock APK objects for unit tests).

Naming convention: MANIFEST_<check_ids>_<description>
  - check_ids: comma-separated MANIFEST-NNN IDs the APK is expected to trigger
  - description: short human-readable label

Each entry is a dict with:
  - xml: the AndroidManifest.xml content (plain text XML)
  - package: the APK package name
  - min_sdk: minSdkVersion (str)
  - target_sdk: targetSdkVersion (str)
  - permissions: list of requested permissions
  - expected_checks: set of MANIFEST-NNN IDs this APK should trigger
  - description: human-readable description of what vulnerabilities are present
  - network_security_config: optional XML content for network_security_config.xml
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 1. Debuggable APK (MANIFEST-001)
# ---------------------------------------------------------------------------
DEBUGGABLE_APK = {
    "filename": "debuggable.apk",
    "package": "com.test.debuggable",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-001"},
    "description": "APK with android:debuggable=true",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.debuggable"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:debuggable="true"
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Debuggable Test">
        <activity android:name="com.test.debuggable.MainActivity"
                  android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 2. AllowBackup APK (MANIFEST-002)
# ---------------------------------------------------------------------------
ALLOW_BACKUP_APK = {
    "filename": "allow_backup.apk",
    "package": "com.test.allowbackup",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-002"},
    "description": "APK with android:allowBackup=true",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.allowbackup"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="true"
        android:usesCleartextTraffic="false"
        android:label="AllowBackup Test">
        <activity android:name="com.test.allowbackup.MainActivity"
                  android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 3. Cleartext Traffic APK (MANIFEST-003)
# ---------------------------------------------------------------------------
CLEARTEXT_TRAFFIC_APK = {
    "filename": "cleartext_traffic.apk",
    "package": "com.test.cleartext",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": ["android.permission.INTERNET"],
    "expected_checks": {"MANIFEST-003"},
    "description": "APK with android:usesCleartextTraffic=true",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.cleartext"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="true"
        android:label="Cleartext Traffic Test">
        <activity android:name="com.test.cleartext.MainActivity"
                  android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 4. Test Only APK (MANIFEST-004)
# ---------------------------------------------------------------------------
TEST_ONLY_APK = {
    "filename": "test_only.apk",
    "package": "com.test.testonly",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-004"},
    "description": "APK with android:testOnly=true",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.testonly"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:testOnly="true"
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="TestOnly Test">
        <activity android:name="com.test.testonly.MainActivity"
                  android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 5. Outdated minSdk APK (MANIFEST-005)
# ---------------------------------------------------------------------------
MIN_SDK_OUTDATED_APK = {
    "filename": "min_sdk_outdated.apk",
    "package": "com.test.minsdk",
    "min_sdk": "15",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-005"},
    "description": "APK with critically outdated minSdkVersion=15 (< API 19)",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.minsdk"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="15" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="MinSdk Outdated Test">
        <activity android:name="com.test.minsdk.MainActivity"
                  android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 6. Exported Components APK (MANIFEST-006)
# ---------------------------------------------------------------------------
EXPORTED_COMPONENTS_APK = {
    "filename": "exported_components.apk",
    "package": "com.test.exported",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-006"},
    "description": "APK with 5+ exported components without permission protection",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.exported"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Exported Components Test">

        <activity android:name=".MainActivity"
                  android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- 6 exported activities without permission protection -->
        <activity android:name=".ExportedActivity1" android:exported="true" />
        <activity android:name=".ExportedActivity2" android:exported="true" />
        <activity android:name=".ExportedActivity3" android:exported="true" />
        <activity android:name=".ExportedActivity4" android:exported="true" />
        <activity android:name=".ExportedActivity5" android:exported="true" />

        <!-- Exported service -->
        <service android:name=".ExportedService" android:exported="true" />

        <!-- Exported receiver -->
        <receiver android:name=".ExportedReceiver" android:exported="true" />

        <!-- Exported provider without readPermission/writePermission -->
        <provider
            android:name=".ExportedProvider"
            android:authorities="com.test.exported.provider"
            android:exported="true" />
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 7. Weak Custom Permissions APK (MANIFEST-007)
# ---------------------------------------------------------------------------
WEAK_PERMISSIONS_APK = {
    "filename": "weak_permissions.apk",
    "package": "com.test.weakperms",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": ["com.test.weakperms.NORMAL_PERM", "com.test.weakperms.DANGEROUS_PERM"],
    "expected_checks": {"MANIFEST-007"},
    "description": "APK with custom permissions using weak protectionLevel (normal/dangerous)",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.weakperms"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <!-- Custom permissions with weak protection levels -->
    <permission
        android:name="com.test.weakperms.NORMAL_PERM"
        android:protectionLevel="normal"
        android:label="Normal Permission" />
    <permission
        android:name="com.test.weakperms.DANGEROUS_PERM"
        android:protectionLevel="dangerous"
        android:label="Dangerous Permission" />

    <uses-permission android:name="com.test.weakperms.NORMAL_PERM" />
    <uses-permission android:name="com.test.weakperms.DANGEROUS_PERM" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Weak Permissions Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 8. StrandHogg v1 APK (MANIFEST-008)
# ---------------------------------------------------------------------------
STRANDHOGG_V1_APK = {
    "filename": "strandhogg_v1.apk",
    "package": "com.test.strandhogg1",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-008"},
    "description": "APK with StrandHogg v1 task hijacking pattern (non-default taskAffinity + allowTaskReparenting)",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.strandhogg1"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="StrandHogg v1 Test">

        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- StrandHogg v1: non-default taskAffinity + allowTaskReparenting -->
        <activity
            android:name=".HijackActivity"
            android:taskAffinity="com.victim.app"
            android:allowTaskReparenting="true"
            android:exported="true" />

        <!-- Another StrandHogg v1 variant: singleTask with foreign affinity -->
        <activity
            android:name=".TaskHijack2"
            android:taskAffinity="com.another.victim"
            android:launchMode="singleTask"
            android:exported="true" />
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 9. StrandHogg v2 APK (MANIFEST-009)
# ---------------------------------------------------------------------------
STRANDHOGG_V2_APK = {
    "filename": "strandhogg_v2.apk",
    "package": "com.test.strandhogg2",
    "min_sdk": "26",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-009"},
    "description": "APK with StrandHogg v2 pattern (exported activities with singleTask/singleInstance launchMode)",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.strandhogg2"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="StrandHogg v2 Test">

        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- StrandHogg v2: exported singleTask activity -->
        <activity
            android:name=".VulnActivity1"
            android:launchMode="singleTask"
            android:exported="true" />

        <!-- StrandHogg v2: exported singleInstance activity -->
        <activity
            android:name=".VulnActivity2"
            android:launchMode="singleInstance"
            android:exported="true" />
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 10. Browsable Intent / App Links APK (MANIFEST-010)
# ---------------------------------------------------------------------------
APP_LINKS_APK = {
    "filename": "app_links.apk",
    "package": "com.test.applinks",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-010"},
    "description": "APK with browsable intents using custom schemes and missing autoVerify",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.applinks"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="App Links Test">

        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Browsable with custom scheme (no autoVerify) -->
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="myapp" android:host="open" />
            </intent-filter>
        </activity>

        <!-- HTTP browsable without autoVerify -->
        <activity android:name=".WebLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 11. Network Security Config APK (MANIFEST-011)
# ---------------------------------------------------------------------------
NETWORK_SECURITY_CONFIG_APK = {
    "filename": "network_security_config.apk",
    "package": "com.test.netsec",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": ["android.permission.INTERNET"],
    "expected_checks": {"MANIFEST-011"},
    "description": "APK with insecure network security config (cleartext, user certs, debug overrides)",
    "network_security_config": """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">*.example.com</domain>
    </domain-config>
</network-security-config>
""",
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.netsec"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="NetSec Config Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 12. Task Reparenting APK (MANIFEST-012)
# ---------------------------------------------------------------------------
TASK_REPARENTING_APK = {
    "filename": "task_reparenting.apk",
    "package": "com.test.reparenting",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-012"},
    "description": "APK with allowTaskReparenting=true on application element",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.reparenting"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:allowTaskReparenting="true"
        android:label="Task Reparenting Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 13. Implicit Intent Hijacking APK (MANIFEST-013)
# ---------------------------------------------------------------------------
IMPLICIT_INTENT_APK = {
    "filename": "implicit_intent.apk",
    "package": "com.test.implicitintent",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-013"},
    "description": "APK with services/receivers using implicit intent filters (no explicit export=false)",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.implicitintent"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Implicit Intent Test">

        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Service with intent-filter but no explicit exported=false -->
        <service android:name=".VulnService" android:exported="true">
            <intent-filter>
                <action android:name="com.test.implicitintent.ACTION_DO_WORK" />
            </intent-filter>
        </service>

        <!-- Receiver with implicit intent filter -->
        <receiver android:name=".VulnReceiver" android:exported="true">
            <intent-filter>
                <action android:name="com.test.implicitintent.ACTION_NOTIFY" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 14. Signing Scheme APK (MANIFEST-014)
# ---------------------------------------------------------------------------
# Note: This check inspects the APK signature, not the manifest XML.
# The mock needs to simulate old signing (v1 only).
SIGNING_SCHEME_APK = {
    "filename": "signing_scheme.apk",
    "package": "com.test.signing",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-014"},
    "description": "APK signed with v1 only (no v2/v3 signing)",
    "network_security_config": None,
    "signing_v1": True,
    "signing_v2": False,
    "signing_v3": False,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.signing"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Signing Scheme Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 15. Backup Agent APK (MANIFEST-015)
# ---------------------------------------------------------------------------
BACKUP_AGENT_APK = {
    "filename": "backup_agent.apk",
    "package": "com.test.backupagent",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-015"},
    "description": "APK with custom backupAgent and allowBackup=true",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.backupagent"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="true"
        android:backupAgent=".MyBackupAgent"
        android:usesCleartextTraffic="false"
        android:label="Backup Agent Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 16. Dangerous Permissions APK (MANIFEST-016)
# ---------------------------------------------------------------------------
DANGEROUS_PERMISSIONS_APK = {
    "filename": "dangerous_permissions.apk",
    "package": "com.test.dangperms",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
    ],
    "expected_checks": {"MANIFEST-016"},
    "description": "APK requesting many dangerous permissions (SMS, camera, mic, location, contacts, call log)",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.dangperms"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Dangerous Permissions Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 17. Intent Scheme Hijacking APK (MANIFEST-017)
# ---------------------------------------------------------------------------
INTENT_SCHEME_APK = {
    "filename": "intent_scheme.apk",
    "package": "com.test.intentscheme",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-017"},
    "description": "APK with browsable activity handling intent:// scheme URLs",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.intentscheme"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Intent Scheme Test">

        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Activity handling intent:// scheme — vulnerable to intent scheme hijacking -->
        <activity android:name=".SchemeHandlerActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="intent" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# 18. Shared User ID APK (MANIFEST-018)
# ---------------------------------------------------------------------------
SHARED_USER_ID_APK = {
    "filename": "shared_user_id.apk",
    "package": "com.test.shareduid",
    "min_sdk": "28",
    "target_sdk": "33",
    "permissions": [],
    "expected_checks": {"MANIFEST-018"},
    "description": "APK with android:sharedUserId set (deprecated, security risk)",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.shareduid"
    android:sharedUserId="com.test.shared"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="SharedUserId Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# Composite: Kitchen Sink APK (triggers ALL checks)
# ---------------------------------------------------------------------------
KITCHEN_SINK_APK = {
    "filename": "kitchen_sink.apk",
    "package": "com.test.kitchensink",
    "min_sdk": "15",
    "target_sdk": "24",
    "permissions": [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
        "android.permission.INTERNET",
        "com.test.kitchensink.WEAK_PERM",
    ],
    "expected_checks": {
        "MANIFEST-001", "MANIFEST-002", "MANIFEST-003", "MANIFEST-004",
        "MANIFEST-005", "MANIFEST-006", "MANIFEST-007", "MANIFEST-008",
        "MANIFEST-009", "MANIFEST-010", "MANIFEST-013",
        "MANIFEST-015", "MANIFEST-016", "MANIFEST-017", "MANIFEST-018",
    },
    "description": "APK with ALL possible manifest vulnerabilities enabled",
    "network_security_config": """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
""",
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.kitchensink"
    android:sharedUserId="com.test.shared"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="15" android:targetSdkVersion="24" />

    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="com.test.kitchensink.WEAK_PERM" />

    <permission
        android:name="com.test.kitchensink.WEAK_PERM"
        android:protectionLevel="normal"
        android:label="Weak Permission" />

    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:testOnly="true"
        android:usesCleartextTraffic="true"
        android:allowTaskReparenting="true"
        android:backupAgent=".KitchenSinkBackupAgent"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="Kitchen Sink Test">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- 5+ exported activities without permission -->
        <activity android:name=".Exported1" android:exported="true" />
        <activity android:name=".Exported2" android:exported="true" />
        <activity android:name=".Exported3" android:exported="true" />
        <activity android:name=".Exported4" android:exported="true" />
        <activity android:name=".Exported5" android:exported="true" />

        <!-- StrandHogg v1: non-default taskAffinity + allowTaskReparenting -->
        <activity
            android:name=".StrandHogg1Activity"
            android:taskAffinity="com.victim.app"
            android:allowTaskReparenting="true"
            android:exported="true" />

        <!-- StrandHogg v2: singleTask exported activity -->
        <activity
            android:name=".StrandHogg2Activity"
            android:launchMode="singleTask"
            android:exported="true" />

        <!-- Browsable with custom scheme (no autoVerify) -->
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="kitchensink" android:host="open" />
            </intent-filter>
        </activity>

        <!-- Intent scheme hijacking -->
        <activity android:name=".IntentSchemeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="intent" />
            </intent-filter>
        </activity>

        <!-- Implicit intent service -->
        <service android:name=".ImplicitService" android:exported="true">
            <intent-filter>
                <action android:name="com.test.kitchensink.DO_WORK" />
            </intent-filter>
        </service>

        <!-- Exported provider -->
        <provider
            android:name=".UnsafeProvider"
            android:authorities="com.test.kitchensink.provider"
            android:exported="true" />
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# Clean APK (should trigger NO findings)
# ---------------------------------------------------------------------------
CLEAN_APK = {
    "filename": "clean.apk",
    "package": "com.test.clean",
    "min_sdk": "28",
    "target_sdk": "34",
    "permissions": ["android.permission.INTERNET"],
    "expected_checks": set(),
    "description": "Clean APK with no manifest vulnerabilities — should produce zero findings",
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.clean"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Clean Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ===========================================================================
# KNOWN-GOOD (SECURE) FIXTURES
# These APK stubs demonstrate correct/secure manifest configurations.
# They should produce ZERO findings from scan_manifest_security().
# ===========================================================================

# ---------------------------------------------------------------------------
# Secure: Full best-practices APK (modern SDK, v2+v3 signing, strict NSC)
# ---------------------------------------------------------------------------
SECURE_FULL_APK = {
    "filename": "secure_full.apk",
    "package": "com.test.secure.full",
    "min_sdk": "28",
    "target_sdk": "34",
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    ],
    "expected_checks": set(),
    "description": (
        "Fully hardened APK: modern SDK, allowBackup=false, no cleartext, "
        "no debuggable, no testOnly, v2+v3 signing, strict NSC, no exports, "
        "no sharedUserId, no dangerous permissions"
    ),
    "signing_v1": False,
    "signing_v2": True,
    "signing_v3": True,
    "network_security_config": """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
""",
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.secure.full"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
        android:debuggable="false"
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="Secure Full Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".SyncService" android:exported="false" />
        <receiver android:name=".BootReceiver" android:exported="false" />
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# Secure: Exported components with proper permission protection
# ---------------------------------------------------------------------------
SECURE_WITH_EXPORTS_APK = {
    "filename": "secure_with_exports.apk",
    "package": "com.test.secure.exports",
    "min_sdk": "28",
    "target_sdk": "34",
    "permissions": ["android.permission.INTERNET"],
    "expected_checks": set(),
    "description": (
        "APK with exported components that are properly protected by "
        "signature-level permissions — should NOT trigger MANIFEST-006"
    ),
    "signing_v1": True,
    "signing_v2": True,
    "signing_v3": False,
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.secure.exports"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />

    <permission
        android:name="com.test.secure.exports.PROVIDER_ACCESS"
        android:protectionLevel="signature" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Secure Exports Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Exported provider protected by signature permission -->
        <provider
            android:name=".SecureProvider"
            android:authorities="com.test.secure.exports.provider"
            android:exported="true"
            android:permission="com.test.secure.exports.PROVIDER_ACCESS" />

        <!-- Exported service protected by signature permission -->
        <service
            android:name=".SecureService"
            android:exported="true"
            android:permission="com.test.secure.exports.PROVIDER_ACCESS" />

        <!-- Non-exported receiver — no permission needed -->
        <receiver android:name=".InternalReceiver" android:exported="false" />
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# Secure: Custom permissions with proper signature protectionLevel
# ---------------------------------------------------------------------------
SECURE_CUSTOM_PERMS_APK = {
    "filename": "secure_custom_perms.apk",
    "package": "com.test.secure.perms",
    "min_sdk": "26",
    "target_sdk": "34",
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ],
    "expected_checks": set(),
    "description": (
        "APK with custom permissions at signature/signatureOrSystem level — "
        "should NOT trigger MANIFEST-007; CAMERA is only 1 dangerous perm "
        "which is under the MANIFEST-016 threshold"
    ),
    "signing_v1": True,
    "signing_v2": True,
    "signing_v3": False,
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.secure.perms"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />

    <permission
        android:name="com.test.secure.perms.MY_PERM"
        android:protectionLevel="signature" />

    <permission
        android:name="com.test.secure.perms.SYSTEM_PERM"
        android:protectionLevel="signatureOrSystem" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Secure Perms Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# Secure: Proper network security config (pinning, no cleartext, system CAs)
# ---------------------------------------------------------------------------
SECURE_NETWORK_CONFIG_APK = {
    "filename": "secure_network_config.apk",
    "package": "com.test.secure.network",
    "min_sdk": "28",
    "target_sdk": "34",
    "permissions": ["android.permission.INTERNET"],
    "expected_checks": set(),
    "description": (
        "APK with proper network_security_config: cleartext disabled, "
        "system CAs only, certificate pinning — should NOT trigger MANIFEST-011"
    ),
    "signing_v1": True,
    "signing_v2": True,
    "signing_v3": False,
    "network_security_config": """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="false">api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
""",
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.secure.network"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="Secure Network Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# Secure: Minimal manifest (relies on safe defaults for modern SDK)
# ---------------------------------------------------------------------------
SECURE_MINIMAL_APK = {
    "filename": "secure_minimal.apk",
    "package": "com.test.secure.minimal",
    "min_sdk": "30",
    "target_sdk": "34",
    "permissions": [],
    "expected_checks": set(),
    "description": (
        "Minimal secure APK with high SDK levels and no extras — "
        "relies on safe Android defaults (API 30+: allowBackup defaults to "
        "false-equivalent, cleartext blocked by default)"
    ),
    "signing_v1": False,
    "signing_v2": True,
    "signing_v3": True,
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.secure.minimal"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="34" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Secure Minimal Test">
        <activity android:name=".MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# Secure: Complex app with multiple components, all properly secured
# ---------------------------------------------------------------------------
SECURE_COMPLEX_APK = {
    "filename": "secure_complex.apk",
    "package": "com.test.secure.complex",
    "min_sdk": "26",
    "target_sdk": "34",
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.VIBRATE",
    ],
    "expected_checks": set(),
    "description": (
        "Complex app with activities, services, receivers, providers — all "
        "non-exported or permission-protected. Standard (non-dangerous) perms "
        "only. No task affinity tricks, no browsable intents, proper signing."
    ),
    "signing_v1": True,
    "signing_v2": True,
    "signing_v3": False,
    "network_security_config": None,
    "xml": """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.secure.complex"
    android:versionCode="5"
    android:versionName="2.1.0">

    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.VIBRATE" />

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Secure Complex App">

        <!-- Main launcher activity (exported=false is fine with LAUNCHER) -->
        <activity android:name=".ui.MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Internal-only activities -->
        <activity android:name=".ui.SettingsActivity" android:exported="false" />
        <activity android:name=".ui.DetailActivity" android:exported="false" />
        <activity android:name=".ui.OnboardingActivity" android:exported="false" />

        <!-- Foreground service (not exported) -->
        <service
            android:name=".service.SyncService"
            android:exported="false"
            android:foregroundServiceType="dataSync" />

        <!-- Boot receiver (not exported) -->
        <receiver android:name=".receiver.BootReceiver" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <!-- Internal content provider -->
        <provider
            android:name=".data.AppProvider"
            android:authorities="com.test.secure.complex.provider"
            android:exported="false" />
    </application>
</manifest>
""",
}

# ---------------------------------------------------------------------------
# List of all known-good (secure) fixtures for easy iteration in tests
# ---------------------------------------------------------------------------
SECURE_FIXTURES: list[dict] = [
    CLEAN_APK,
    SECURE_FULL_APK,
    SECURE_WITH_EXPORTS_APK,
    SECURE_CUSTOM_PERMS_APK,
    SECURE_NETWORK_CONFIG_APK,
    SECURE_MINIMAL_APK,
    SECURE_COMPLEX_APK,
]

# ---------------------------------------------------------------------------
# Registry: all fixture definitions indexed by filename
# ---------------------------------------------------------------------------
ALL_FIXTURES: dict[str, dict] = {
    f["filename"]: f
    for f in [
        DEBUGGABLE_APK,
        ALLOW_BACKUP_APK,
        CLEARTEXT_TRAFFIC_APK,
        TEST_ONLY_APK,
        MIN_SDK_OUTDATED_APK,
        EXPORTED_COMPONENTS_APK,
        WEAK_PERMISSIONS_APK,
        STRANDHOGG_V1_APK,
        STRANDHOGG_V2_APK,
        APP_LINKS_APK,
        NETWORK_SECURITY_CONFIG_APK,
        TASK_REPARENTING_APK,
        IMPLICIT_INTENT_APK,
        SIGNING_SCHEME_APK,
        BACKUP_AGENT_APK,
        DANGEROUS_PERMISSIONS_APK,
        INTENT_SCHEME_APK,
        SHARED_USER_ID_APK,
        KITCHEN_SINK_APK,
        CLEAN_APK,
        # Known-good (secure) fixtures
        SECURE_FULL_APK,
        SECURE_WITH_EXPORTS_APK,
        SECURE_CUSTOM_PERMS_APK,
        SECURE_NETWORK_CONFIG_APK,
        SECURE_MINIMAL_APK,
        SECURE_COMPLEX_APK,
    ]
}
