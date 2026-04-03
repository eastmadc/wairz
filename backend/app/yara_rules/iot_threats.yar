/*
 * YARA rules for IoT-specific threats and insecure patterns
 * commonly exploited in embedded device attacks.
 */

rule IoT_Default_Web_Credentials
{
    meta:
        description = "Default web interface credentials in firmware configuration"
        severity = "high"
        category = "credentials"
        cwe = "CWE-798"
    strings:
        $http_passwd1 = "http_passwd" ascii
        $http_passwd2 = "http_password" ascii
        $web_passwd = "web_passwd" ascii
        $login_passwd = "login_password" ascii
        $admin_pass = /admin[_\s]*pass(word|wd)?\s*[=:]\s*["']?[^\s"']+/i ascii
        $default1 = "admin:admin" ascii nocase
        $default2 = "admin:password" ascii nocase
        $default3 = "root:root" ascii nocase
        $default4 = "user:user" ascii nocase
    condition:
        any of them
}

rule IoT_UPnP_Vulnerability
{
    meta:
        description = "UPnP implementation with known vulnerable patterns"
        severity = "medium"
        category = "vulnerability"
        cwe = "CWE-284"
    strings:
        $upnp = "miniupnpd" ascii
        $ssdp = "SSDP" ascii
        $igd = "InternetGatewayDevice" ascii
        $add_port = "AddPortMapping" ascii
        $no_auth = /allow\s*(all|any|0\.0\.0\.0)/i ascii
    condition:
        ($upnp or $ssdp or $igd) and $add_port and $no_auth
}

rule IoT_Insecure_Update_Mechanism
{
    meta:
        description = "Firmware update over HTTP (not HTTPS) — vulnerable to MITM"
        severity = "high"
        category = "vulnerability"
        cwe = "CWE-494"
    strings:
        $http_update = /http:\/\/[^\s]*\.(bin|img|fw|firmware|update)/i ascii
        $ftp_update = /ftp:\/\/[^\s]*\.(bin|img|fw|firmware|update)/i ascii
        $no_verify = /verify\s*=\s*(false|0|no)/i ascii
        $no_check = "--no-check" ascii
    condition:
        ($http_update or $ftp_update) or $no_verify or $no_check
}

rule IoT_Weak_Encryption
{
    meta:
        description = "Use of weak or deprecated cryptographic algorithms"
        severity = "medium"
        category = "crypto"
        cwe = "CWE-327"
    strings:
        $des = "DES_" ascii
        $rc4 = "RC4" ascii
        $sha1_cert = "sha1WithRSA" ascii
        $ssl2 = "SSLv2" ascii
        $ssl3 = "SSLv3" ascii
        $wep = "WEP" ascii nocase
    condition:
        any of ($ssl2, $ssl3, $wep, $rc4, $des, $sha1_cert)
}

rule IoT_Command_Injection_Vector
{
    meta:
        description = "Potential command injection in CGI/web handler"
        severity = "high"
        category = "vulnerability"
        cwe = "CWE-78"
    strings:
        $system = "system(" ascii
        $popen = "popen(" ascii
        $exec = "exec(" ascii
        $query_string = "QUERY_STRING" ascii
        $http_get = "HTTP_GET" ascii
        $request = "REQUEST_URI" ascii
        $content_type = "CONTENT_TYPE" ascii
        $sprintf_cmd = /sprintf\s*\([^;]*"[^"]*%s[^"]*"/ ascii
    condition:
        ($system or $popen or $exec) and
        ($query_string or $http_get or $request or $content_type) and
        $sprintf_cmd
}

rule IoT_Exposed_Serial_Console
{
    meta:
        description = "Serial console (UART) enabled without authentication"
        severity = "medium"
        category = "configuration"
        cwe = "CWE-284"
    strings:
        $inittab_console = /::respawn:.*\/bin\/(sh|ash|bash)\s*$/ ascii
        $getty_nologin = /getty.*-n.*-l\s*\/bin\/(sh|ash)/ ascii
        $console_login = "console::sysinit" ascii
        $ttyS = /ttyS[0-9]\s*::/ ascii
    condition:
        ($inittab_console or $getty_nologin) and ($console_login or $ttyS)
}
