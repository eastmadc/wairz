/*
 * YARA rules for detecting backdoors and malicious implants in firmware.
 * These rules target known firmware trojans, hardcoded backdoor accounts,
 * suspicious network callbacks, and implant indicators.
 */

rule Backdoor_Hardcoded_Root_Password
{
    meta:
        description = "Hardcoded root password hash in passwd/shadow file"
        severity = "critical"
        category = "backdoor"
        cwe = "CWE-798"
    strings:
        $shadow_root = /root:\$[156y]\$[^\n]{10,120}/ ascii
        $passwd_uid0 = /^[a-z]+:x:0:0:/ ascii
    condition:
        $shadow_root or #passwd_uid0 > 1
}

rule Backdoor_Hidden_Service_Listener
{
    meta:
        description = "Binary binds to a network port with suspicious patterns"
        severity = "high"
        category = "backdoor"
        cwe = "CWE-912"
    strings:
        $bind = "bind" ascii
        $listen = "listen" ascii
        $accept = "accept" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $dup2 = "dup2" ascii
        $execve = "execve" ascii
    condition:
        $bind and $listen and $accept and ($shell1 or $shell2) and ($dup2 or $execve)
}

rule Backdoor_Reverse_Shell
{
    meta:
        description = "Reverse shell patterns — binary connects back to external host"
        severity = "critical"
        category = "backdoor"
        cwe = "CWE-506"
    strings:
        $connect = "connect" ascii
        $socket = "socket" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $dup2 = "dup2" ascii
        $inet_addr = "inet_addr" ascii
    condition:
        $connect and $socket and ($shell1 or $shell2) and $dup2 and $inet_addr
}

rule Backdoor_Hardcoded_Credentials_Binary
{
    meta:
        description = "Hardcoded credentials embedded in firmware binary"
        severity = "high"
        category = "backdoor"
        cwe = "CWE-798"
    strings:
        $user_admin = "admin" ascii nocase wide
        $user_root = "root" ascii nocase wide
        $pass1 = "password" ascii nocase wide
        $pass2 = "123456" ascii wide
        $pass3 = "admin123" ascii nocase wide
        $pass4 = "default" ascii nocase wide
        $auth = "authentication" ascii nocase
        $login = "login" ascii nocase
    condition:
        ($user_admin or $user_root) and any of ($pass*) and ($auth or $login)
}

rule Backdoor_Hidden_Telnet
{
    meta:
        description = "Hidden telnet service in firmware — often a manufacturer backdoor"
        severity = "high"
        category = "backdoor"
        cwe = "CWE-912"
    strings:
        $telnetd = "telnetd" ascii
        $utelnetd = "utelnetd" ascii
        $hidden1 = "-l /bin/sh" ascii
        $hidden2 = "-l /bin/login" ascii
        $port = "-p" ascii
    condition:
        ($telnetd or $utelnetd) and ($hidden1 or $hidden2) and $port
}

rule Backdoor_Wget_Curl_Download
{
    meta:
        description = "Script downloads and executes external payload"
        severity = "critical"
        category = "backdoor"
        cwe = "CWE-494"
    strings:
        $wget_exec = /wget\s+[^\n]*\|\s*sh/ ascii
        $curl_exec = /curl\s+[^\n]*\|\s*sh/ ascii
        $wget_chmod = /wget\s+[^\n]*;\s*chmod\s+\+?[0-7]*x/ ascii
        $curl_chmod = /curl\s+[^\n]*;\s*chmod\s+\+?[0-7]*x/ ascii
    condition:
        any of them
}
