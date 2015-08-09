/*
    Place holder rule to bootstrap the file
*/
rule PE_File
{
    strings:
        $magic = { 4D 5A 90 00 03 00 00 00 }

    condition:
        $magic at 0
}
