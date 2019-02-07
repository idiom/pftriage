# pftriage  [![Build Status](https://travis-ci.org/idiom/pftriage.svg?branch=master)](https://travis-ci.org/idiom/pftriage)


pftriage is a tool to help analyze files during malware triage. It allows an analyst to quickly 
view and extract properties of a file to help during the triage process. The tool also has an
analyze function which can detect common malicious indicators used by malware.

# Dependencies

 * pefile
 * filemagic 
 
_Note: On Mac - Apple has implemented their own version of the file command. However, libmagic can be installed using homebrew_
```
$ brew install libmagic
```  

# Usage

```
usage: pftriage [options]

Show information about a file for triage.

positional arguments:
  file                  The file to triage.

optional arguments:
  -h, --help            show this help message and exit
  -i, --imports         Display import tree
  -s, --sections        Display overview of sections. For more detailed info
                        pass the -v switch
  --removeoverlay       Remove overlay data.
  --extractoverlay      Extract overlay data.
  -r, --resources       Display resource information
  -R, --rich            Display Rich Header information
  -D DUMP_OFFSET, --dump DUMP_OFFSET
                        Dump data using the passed offset or 'ALL'. Currently
                        only works with resources.
  -e, --exports         Display exports
  -a, --analyze         Analyze the file.
  -v, --verbose         Display version.
  -V, --version         Print version and exit.
 ```

## Sections
Display Section information by using the `-s` or `--sections` switch. Additionally you can pass (`-v`) for a more verbose
view of section details. 

To export a section pass `--dump` and the desired section Virtual Address. (ex: `--dump 0x00001000`)

```
 ---- Section Overview (use -v for detailed section info)  ----

 Name        Raw Size    Raw Data Pointer  Virtual Address     Virtual Size        Entropy             Hash
 .text       0x00012200  0x00000400        0x00001000          0x000121d8          6.71168555177       ff38fce4f48772f82fc77b4ef223fd74
 .rdata      0x00005a00  0x00012600        0x00014000          0x0000591a          4.81719489022       b0c15ee9bf8480a07012c2cf277c3083
 .data       0x00001a00  0x00018000        0x0001a000          0x0000ab80          5.28838495072       5d969a878a5106ba526aa29967ef877f
 .rsrc       0x00002200  0x00019a00        0x00025000          0x00002144          7.91994689603       d361caffeadb934c9f6b13b2474c6f0f
 .overlay    0x00009b30  0x0001bc00        0x00000000          0x00000000          0                   N/A
```

## Resources
Display resource data by using `-r` or `--resources`.


```
 ---- Resource Overview ----

 Type: CODATA
  Name        Language        SubLang             Offset      Size        Code Page   Type
  0x68        LANG_RUSSIAN    RUSSIAN             0x000250e0  0x00000cee  0x000004e4
  0x69        LANG_RUSSIAN    RUSSIAN             0x00025dd0  0x000011e6  0x000004e4

 Type: RT_MANIFEST
  Name        Language        SubLang             Offset      Size        Code Page   Type
  0x1         LANG_ENGLISH    ENGLISH_US          0x00026fb8  0x0000018b  0x000004e4

```

To extract a specific resource use `-D` with the desired offset. If you want to extract all resources pass ALL istead
 of a specific offset.  

## Imports
Display Import data and modules using `-i` or `--imports`. Imports which are identified as ordinals will be identified
and include the Ordinal used. 

```
[*] Loading File...
 ---- Imports ----
 Number of imported modules: 4

 KERNEL32.dll
  |-- GetProcessHeap
  |-- HeapFree
  |-- HeapAlloc
  |-- SetLastError
  |-- GetLastError

 WS2_32.dll
  |-- getaddrinfo
  |-- freeaddrinfo
  |-- closesocket Ordinal[3] (Imported by Ordinal)
  |-- WSAStartup Ordinal[115] (Imported by Ordinal)
  |-- socket Ordinal[23] (Imported by Ordinal)
  |-- send Ordinal[19] (Imported by Ordinal)
  |-- recv Ordinal[16] (Imported by Ordinal)
  |-- connect Ordinal[4] (Imported by Ordinal)

 ole32.dll
  |-- CoCreateInstance
  |-- ...
  
```

## Exports

Display exports using `-e` or `--exports`.

```
[*] Loading File...

 ---- Exports ----
 Total Exports: 5
 Address     Ordinal   Name
 0x00001151  1         FindResources
 0x00001103  2         LoadBITMAP
 0x00001137  3         LoadICON
 0x000010e9  4         LoadIMAGE
 0x0000111d  5         LoadSTRINGW

```


## Rich Headers
Display Rich headers using the `-R` or `--rich` flags.
```
[*] Loading File...
-- Rich Header Details --

 Checksum: 0x2b41e6a9
 Id  Product         Count   Build Id  Build
 --  -------         -----   --------  -----
 150 AliasObj900     1       20413     <Unknown>
 132 Utc1500_CPP     36      21022     9.0 2008
 149 Masm900         17      21022     9.0 2008
 123 Implib800       3       50727     11.0 2012
 1   Import0         102     0         <Unknown>
 131 Utc1500_C       123     21022     9.0 2008
 145 Linker900       1       21022     9.0 2008
```


## Metadata
File and version metadata is displayed if no options are passed on the commandline. 


```
[*] Loading File...
[*] Processing File details...


---- File Summary ----

 General
     Filename         samaple.exe
     Magic Type       PE32 executable (GUI) Intel 80386, for MS Windows
     Size             135168
     First Bytes      4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00

 Hashes
     MD5              8e8a8fe8361c7238f60d6bbfdbd304a8
     SHA1             557832efe10daff3f528a3c3589eb5a6dfd12447
     SHA256           118983ba4e1c12a366d7d6e9461c68bf222e2b03f3c1296091dee92ac0cc9dd8
     Import Hash      0239fd611af3d0e9b0c46c5837c80e09
     ssdeep           

 Headers
     Subsystem        IMAGE_SUBSYSTEM_WINDOWS_GUI
     Linker Version   12.0 - (Visual Studio 2013)
     Image Base       0x400000
     Compile Time     Thu Jun 23 16:04:21 2016 UTC
     Checksum         0
     Filename         sample.exe
     EP Bytes         55 8b ec 51 83 65 fc 00 8d 45 fc 56 57 50 e8 64
     Signature        0x4550
     First Bytes      4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00
     Sections         4
     Entry Point      0x139de
     Packed           False
     Size             135168
     Characteristics
                      IMAGE_FILE_32BIT_MACHINE
                      IMAGE_FILE_EXECUTABLE_IMAGE
                      IMAGE_FILE_RELOCS_STRIPPED

```


## Analyze 
PFTriage can perform simple analysis of a file to help identify malicious characteristics.

```
[*] Loading File...
[*] Analyzing File...
[*] Analysis Complete...

  [!] Checksum        Invalid CheckSum
  [!] AntiDebug       AntiDebug Function import [GetTickCount]
  [!] AntiDebug       AntiDebug Function import [QueryPerformanceCounter]
  [!] Imports         Suspicious API Call [TerminateProcess]
  [!] AntiDebug       AntiDebug Function import [SetUnhandledExceptionFilter]
  [!] AntiDebug       AntiDebug Function import [IsDebuggerPresent]

``` 


## Overlay Data
Overlay data is identified by analyzing or displaying section information of the file. If overlay data exists PFTriage
can either remove the data by using the (`--removeoverlay`) switch or export the overlay data by using the (--extractoverlay)
switch.  


