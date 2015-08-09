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
