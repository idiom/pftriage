/*
    Place holder rule to bootstrap the file
*/
rule Info_PE_File
{
    meta:
        description="Simple rule to bootstrap the rule file"
        author="@seanmw"
        date="8.8.2015"
        severity=2
    strings:
        $magic = { 4D 5A 90 00 03 00 00 00 }

    condition:
        $magic at 0
}

rule VM_Detection_Strings
{
    meta:
        description="Common Strings VM Detect Strings"
        author="@seanmw"
        date="8.8.2015"
        severity=1
    strings:
        $grpA_1 = "filemon" ascii
        $grpA_2 = "regmon" ascii
        $grpA_3 = "wireshark" ascii
        $grpA_4 = "VBOX" ascii
        $grpA_5 = "QEMU" ascii
        $grpA_6 = "VMWARE" ascii
        $grpA_7 = "VIRTUAL HD" ascii
    condition:
        any of them
}

include "packers.yar"