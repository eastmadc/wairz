/*
 * YARA rules for suspicious patterns commonly found in compromised
 * or trojanized firmware. These are lower-confidence than malware
 * signatures but indicate potential tampering or poor security practice.
 */

rule Suspicious_Encoded_Commands
{
    meta:
        description = "Base64-encoded shell commands — possible obfuscation"
        severity = "medium"
        category = "suspicious"
        cwe = "CWE-506"
    strings:
        // base64 of common shell prefixes
        $b64_bin_sh = "L2Jpbi9zaA" ascii   // /bin/sh
        $b64_bin_bash = "L2Jpbi9iYXNo" ascii  // /bin/bash
        $b64_wget = "d2dldCA" ascii  // wget
        $b64_curl = "Y3VybCA" ascii  // curl
        $decode1 = "base64 -d" ascii
        $decode2 = "base64 --decode" ascii
        $eval = "eval " ascii
    condition:
        any of ($b64_*) and ($decode1 or $decode2 or $eval)
}

rule Suspicious_Data_Exfiltration
{
    meta:
        description = "Patterns suggesting data exfiltration from device"
        severity = "high"
        category = "suspicious"
        cwe = "CWE-200"
    strings:
        $tar_pipe = /tar\s+[cz]+\s+[^\n]*\|\s*(nc|curl|wget)/ ascii
        $dd_pipe = /dd\s+if=[^\n]*\|\s*(nc|curl|wget)/ ascii
        $cat_nc = /cat\s+[^\n]*\|\s*nc\s/ ascii
        $etc_shadow = "/etc/shadow" ascii
        $etc_passwd = "/etc/passwd" ascii
        $upload = "upload" ascii nocase
    condition:
        any of ($tar_pipe, $dd_pipe, $cat_nc)
        or (($etc_shadow or $etc_passwd) and $upload)
}

rule Suspicious_Persistence_Mechanism
{
    meta:
        description = "Firmware persistence mechanism — survives reboot or factory reset"
        severity = "high"
        category = "suspicious"
        cwe = "CWE-912"
    strings:
        $crontab = "crontab" ascii
        $rclocal = "/etc/rc.local" ascii
        $initd = "/etc/init.d/" ascii
        $mtd_write = /mtd\s+(write|erase)/ ascii
        $flash_write = "flash_write" ascii
        $nvram_set = "nvram set" ascii
        $wget = "wget " ascii
        $curl = "curl " ascii
        $chmod_x = "chmod +x" ascii
        $nohup = "nohup " ascii
    condition:
        ($mtd_write or $flash_write or $nvram_set) and ($wget or $curl)
        or (($crontab or $rclocal or $initd) and ($wget or $curl) and $chmod_x)
        or ($nohup and ($wget or $curl) and $chmod_x)
}

rule Suspicious_Debug_Interface
{
    meta:
        description = "Debug or diagnostic interface left enabled in production firmware"
        severity = "medium"
        category = "suspicious"
        cwe = "CWE-489"
    strings:
        $gdbserver = "gdbserver" ascii
        $strace = "strace" ascii
        $ltrace = "ltrace" ascii
        $debug_enable = /debug[_\s]*=\s*(1|true|on|yes)/i ascii
    condition:
        any of them
}

rule Suspicious_Firmware_Modification_Tools
{
    meta:
        description = "Tools that modify firmware from within — possible supply chain implant"
        severity = "high"
        category = "suspicious"
        cwe = "CWE-494"
    strings:
        $fw_upgrade = "fwupgrade" ascii
        $fw_update = "firmware_update" ascii
        $sysupgrade = "sysupgrade" ascii
        $flash = "flashcp" ascii
        $dd_mtd = /dd\s+[^\n]*\/dev\/mtd/ ascii
        $no_check = /--no-check|--force/ ascii
    condition:
        any of ($fw_upgrade, $fw_update, $sysupgrade, $flash, $dd_mtd) and $no_check
}

rule Suspicious_Network_Recon
{
    meta:
        description = "Network reconnaissance tools or commands in firmware"
        severity = "medium"
        category = "suspicious"
        cwe = "CWE-200"
    strings:
        $nmap = "nmap" ascii
        $masscan = "masscan" ascii
        $arp_scan = "arp-scan" ascii
        $proc_net = "/proc/net/arp" ascii
        $scan_subnet = /192\.168\.[0-9]+\.[0-9]+\/[0-9]+/ ascii
        $port_scan = /for\s+port\s+in/ ascii
    condition:
        any of ($nmap, $masscan, $arp_scan) or ($proc_net and ($scan_subnet or $port_scan))
}

rule Suspicious_Embedded_Private_Key
{
    meta:
        description = "Private key embedded in firmware — never ship private keys"
        severity = "critical"
        category = "crypto"
        cwe = "CWE-321"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $pkcs8 = "-----BEGIN PRIVATE KEY-----" ascii
        $dsa = "-----BEGIN DSA PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule Suspicious_Hardcoded_IP_With_Download
{
    meta:
        description = "Script downloads from hardcoded IP address — possible C2 endpoint"
        severity = "medium"
        category = "suspicious"
        cwe = "CWE-798"
    strings:
        $ip_url1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $wget = "wget" ascii
        $curl = "curl" ascii
        $nc = "nc " ascii
    condition:
        $ip_url1 and ($wget or $curl or $nc)
}
