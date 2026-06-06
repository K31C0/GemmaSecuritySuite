/*
    EICAR Test Rule — validates that the YARA engine is operational.
    This rule detects the standard EICAR anti-virus test string,
    which is harmless and used solely for testing security scanners.
*/

rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR anti-virus test file"
        author = "GemmaSecuritySuite"
        severity = "test"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $eicar
}

/*
    Suspicious PowerShell patterns commonly seen in post-exploitation.
*/

rule Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell download cradles and encoded commands"
        author = "GemmaSecuritySuite"
        severity = "high"

    strings:
        $dl1 = "Invoke-WebRequest" ascii nocase
        $dl2 = "Net.WebClient" ascii nocase
        $dl3 = "DownloadString" ascii nocase
        $dl4 = "DownloadFile" ascii nocase
        $dl5 = "Start-BitsTransfer" ascii nocase
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "FromBase64String" ascii nocase
        $bypass = "ExecutionPolicy Bypass" ascii nocase

    condition:
        any of ($dl*) or any of ($enc*) or $bypass
}

rule Suspicious_Credential_Access
{
    meta:
        description = "Detects common credential harvesting patterns"
        author = "GemmaSecuritySuite"
        severity = "critical"

    strings:
        $m1 = "mimikatz" ascii nocase
        $m2 = "sekurlsa" ascii nocase
        $m3 = "kerberos::list" ascii nocase
        $lsass = "lsass.exe" ascii nocase
        $sam = "reg save HKLM\\SAM" ascii nocase
        $ntds = "ntds.dit" ascii nocase
        $dcsync = "DCSync" ascii nocase
        $hashdump = "hashdump" ascii nocase

    condition:
        2 of them
}

rule Suspicious_Persistence_Mechanisms
{
    meta:
        description = "Detects common persistence techniques"
        author = "GemmaSecuritySuite"
        severity = "high"

    strings:
        $reg1 = "CurrentVersion\\Run" ascii nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii nocase
        $schtask = "schtasks /create" ascii nocase
        $wmi = "Win32_Process" ascii nocase
        $service = "New-Service" ascii nocase
        $startup = "shell:startup" ascii nocase

    condition:
        any of them
}

rule Suspicious_Network_Reconnaissance
{
    meta:
        description = "Detects network discovery and enumeration commands"
        author = "GemmaSecuritySuite"
        severity = "medium"

    strings:
        $net1 = "net user /domain" ascii nocase
        $net2 = "net group" ascii nocase
        $net3 = "net localgroup administrators" ascii nocase
        $nltest = "nltest /dclist" ascii nocase
        $blood = "bloodhound" ascii nocase
        $sharphound = "sharphound" ascii nocase
        $portscan = "Test-NetConnection" ascii nocase

    condition:
        2 of them
}
