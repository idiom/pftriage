rule Info_SFX_RAR_Archive
{
    meta:
        description="Detect SFX RAR Archive"
        author="@seanmw"
        date="2015.10.28"
        severity=2
    strings:
        $rar1=";The comment below contains SFX script commands" ascii
        $rar2="\\WinRAR\\SFX" ascii
        $rar3="WINRAR.SFX" ascii
        $rar4="WinRAR SFX" ascii
    condition:
        3 of them
}


rule Info_NSIS_Installer
{
    meta:
        description="NSIS Installer"
        author="@seanmw"
        date="2015.10.28"
        severity=2
    strings:
        $rar1="Nullsoft Install System" ascii
        $rar2="Nullsoft" ascii
        $rar3="nsis.sf.net" ascii
    condition:
        3 of them
}