/*
 * macOS Persistence Detection Rules
 * Detects malicious persistence patterns, NOT legitimate system files
 */

rule Malicious_LaunchAgent_Pattern {
    meta:
        description = "Suspicious LaunchAgent with hidden/temp executable"
        severity = "high"
        mitre = "T1543.001"
    strings:
        $plist = "<!DOCTYPE plist" ascii
        $prog = "<key>Program</key>" ascii
        $runload = "<key>RunAtLoad</key>" ascii
        $true = "<true/>" ascii
        // Suspicious paths
        $tmp_path = /\/tmp\/[^<]+/ ascii
        $hidden = /\/\.[^<\/]+\// ascii
        $users_shared = "/Users/Shared" ascii
    condition:
        $plist and $prog and $runload and $true and any of ($tmp_path, $hidden, $users_shared)
}

rule Cron_Reverse_Shell {
    meta:
        description = "Cron job with reverse shell or download"
        severity = "critical"
        mitre = "T1053.003"
    strings:
        $cron_header = /^\s*[\*0-9,\-\/]+\s+[\*0-9,\-\/]+\s+[\*0-9,\-\/]+\s+[\*0-9,\-\/]+\s+[\*0-9,\-\/]+\s+/ ascii
        $curl_sh = /curl.*\|\s*(ba)?sh/ ascii
        $wget_sh = /wget.*\|\s*(ba)?sh/ ascii
        $nc_connect = /nc\s+[0-9.]+\s+[0-9]+/ ascii
        $dev_tcp = "/dev/tcp/" ascii
    condition:
        $cron_header and any of ($curl_sh, $wget_sh, $nc_connect, $dev_tcp)
}

rule Login_Hook_Persistence {
    meta:
        description = "Login/logout hook persistence"
        severity = "high"
        mitre = "T1037.002"
    strings:
        $defaults = "defaults write" ascii
        $loginhook = "LoginHook" ascii
        $logouthook = "LogoutHook" ascii
    condition:
        $defaults and ($loginhook or $logouthook)
}

rule Dylib_Hijack_Marker {
    meta:
        description = "Potential dylib hijacking setup"
        severity = "high"
        mitre = "T1574.004"
    strings:
        $dylib_insert = "DYLD_INSERT_LIBRARIES" ascii
        $dylib_path = "DYLD_LIBRARY_PATH" ascii
        $env_plist = "<key>EnvironmentVariables</key>" ascii
    condition:
        ($dylib_insert or $dylib_path) and $env_plist
}

rule At_Job_Persistence {
    meta:
        description = "at job scheduling for persistence"
        severity = "medium"
        mitre = "T1053.002"
    strings:
        $at_cmd = /echo\s+.*\|\s*at\s+/ ascii
        $at_now = /at\s+now\s*\+/ ascii
    condition:
        any of them
}

rule Periodic_Script_Persistence {
    meta:
        description = "Malicious periodic script"
        severity = "high"
        mitre = "T1053.003"
    strings:
        $periodic_path = "/etc/periodic/" ascii
        $bash_header = "#!/bin/bash" ascii
        $curl_exec = /curl.*\|\s*(ba)?sh/ ascii
        $python_exec = /python[23]?\s+-c/ ascii
    condition:
        $periodic_path and $bash_header and ($curl_exec or $python_exec)
}

rule Emond_Persistence {
    meta:
        description = "Event Monitor Daemon (emond) persistence"
        severity = "high"
        mitre = "T1546.014"
    strings:
        $emond_path = "/etc/emond.d/rules/" ascii
        $emond_plist = "emond" ascii
        $action_cmd = "<key>command</key>" ascii
    condition:
        $emond_path or ($emond_plist and $action_cmd)
}
