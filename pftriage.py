#!/usr/bin/env python
# -*- coding: utf-8 -*-
__description__ = 'Display info about a file.'
__author__ = 'Sean Wilson'
__version__ = '0.0.9'

"""
 --- History ---

  1.19.2015 - Initial Revision
  1.20.2015 - Fixed import issues and minor bugsThis inspection detects situations when dictionary creation could be rewritten with dictionary literal.
            - Added sha256 to default output
            - Updated Stringtable info
            - Fixed default display
  1.21.2015 - Fixed output issue with VarOutputInfo
            - Moved VersionInfo from default output
  1.22.2015 - Minor updates.
  2.01.2015 - Added resources
            - Added option to extract resource data by passing rva_offset or 'ALL'
            - Updated section output
  2.03.2015 - Updated resource output
  2.11.2015 - Removed type lookup when printing resource names
            - Minor updates
  3.02.2015 - Updated to use pefile lang/sublang lookups.
  5.06.2015 - Added analysis option to analzye the file for common indicators of bad
            - removed -v switch for version info this will be output when printing file details
  6.07.2015 - updates to analysis checks
  8.08.2015 - Updated to use python-magic
            - Added setup.py
            - Added yara rule scan in analysis
            - Bug fixes
  8.16.2015 -

"""

import argparse 
import hashlib 
import os
import time
import sys

try:
    import pefile
    import peutils
except Exception as e:
    print 'Error - Please ensure you install the pefile library %s ' % e
    sys.exit(-1)

try:
    import magic
except ImportError:
    pass

use_yara = False

try:
    import yara
    use_yara = True
except ImportError:
    pass

    
class PFTriage(object):
        
    # https://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
    resource_type = {
        1: 'RT_CURSOR',
        2: 'RT_BITMAP',
        3: 'RT_ICON',
        4: 'RT_MENU',
        5: 'RT_DIALOG',
        6: 'RT_STRING',
        7: 'RT_FONTDIR',
        8: 'RT_FONT',
        9: 'RT_ACCELERATOR',
        10: 'RT_RCDATA',
        11: 'RT_MESSAGETABLE',
        12: 'RT_GROUP_CURSOR',
        13: '<UNDEFINED>',
        14: 'RT_GROUP_ICON',
        15: '<UNDEFINED>',
        16: 'RT_VERSION',
        17: 'RT_DLGINCLUDE',
        18: '<UNDEFINED>',
        19: 'RT_PLUGPLAY',
        20: 'RT_VXD',
        21: 'RT_ANICURSOR',
        22: 'RT_ANIICON',
        23: 'RT_HTML',
        24: 'RT_MANIFEST',
    }
    
    # https://msdn.microsoft.com/en-us/library/aa381057.aspx
    charsetID = {
        0: "7-bit ASCII",
        932: "Japan (Shift - JIS X-0208)",
        949: "Korea (Shift - KSC 5601)",
        950: "Taiwan (Big5)",
        1200: "Unicode",
        1250: "Latin-2 (Eastern European)",
        1251: "Cyrillic",
        1252: "Multilingual",
        1253: "Greek",
        1254: "Turkish",
        1255: "Hebrew",
        1256: "Arabic"
    }
    
    # https://msdn.microsoft.com/en-us/library/aa381057.aspx
    langID = {
        0x0000: "Unknown",
        0x0401: "Arabic",
        0x0402: "Bulgarian",    
        0x0403: "Catalan",
        0x0404: "Traditional Chinese",
        0x0405: "Czech",
        0x0406: "Danish",   
        0x0407: "German",   
        0x0408: "Greek",    
        0x0409: "U.S. English", 
        0x040A: "Castilian Spanish",    
        0x040B: "Finnish",
        0x040C: "French",   
        0x040D: "Hebrew",   
        0x040E: "Hungarian",    
        0x040F: "Icelandic",    
        0x0410: "Italian",  
        0x0411: "Japanese", 
        0x0412: "Korean",   
        0x0413: "Dutch",    
        0x0414: "Norwegian - Bokmal",   
        0x0415: "Polish",
        0x0416: "Portuguese (Brazil)",
        0x0417: "Rhaeto-Romanic",
        0x0418: "Romanian",
        0x0419: "Russian",
        0x041A: "Croato-Serbian (Latin)",
        0x041B: "Slovak",
        0x041C: "Albanian",
        0x041D: "Swedish",
        0x041E: "Thai",
        0x041F: "Turkish",
        0x0420: "Urdu",
        0x0421: "Bahasa",
        0x0804: "Simplified Chinese",
        0x0807: "Swiss German",
        0x0809: "U.K. English",
        0x080A: "Spanish (Mexico)",
        0x080C: "Belgian French",
        0x0C0C: "Canadian French",
        0x100C: "Swiss French",
        0x0810: "Swiss Italian",    
        0x0813: "Belgian Dutch",    
        0x0814: "Norwegian - Nynorsk",
        0x0816: "Portuguese (Portugal)",
        0x081A: "Serbo-Croatian (Cyrillic)"
    }

    # Common/Default versions
    linker_versions = {
        "6.0": "Visual Studio 6",
        "7.0": "Visual Studio .NET (2002)",
        "7.1": "Visual Studio .NET 2003",
        "8.0": "Visual Studio 2005",
        "9.0": "Visual Studio 2008",
        "10.0": "Visual Studio 2010",
        "11.0": "Visual Studio 2012",
        "12.0": "Visual Studio 2013",
        "14.0": "Visual Studio 2015"
    }

    def __init__(self, tfile, yararules='', peiddb='', verbose=False, loglevel='Error'):
        
        if not os.path.isfile(tfile):
            raise Exception('Error! File does not exist...')
            
        self.filename = tfile
        self.pe       = None
        self.filesize = os.path.getsize(self.filename)
        self.verbose = verbose
        self.loglevel = loglevel

        defaultyarapath = 'data/default.yara'
        defaultpeidpath = 'data/userdb.txt'

        if not yararules:
            self.yararules = '%s/%s' % (self._getpath(), defaultyarapath)
        else:
            self.yararules = yararules

        if not peiddb:
            self.peiddb = '%s/%s' % (self._getpath(), defaultpeidpath)
        else:
            self.peiddb = peiddb

        try:
            self.pe = pefile.PE(self.filename)
        except Exception as per:
            sys.exit('Error! %s' % per)

    def _getpath(self):
        return os.path.abspath(os.path.dirname(__file__))

    def magic_type(self, data, isdata=False):
        try:
            if isdata:
                magictype = magic.from_buffer(data)
            else:
                magictype = magic.from_file(data)
        except NameError:
            magictype = 'Error - python-magic library required.'
        except Exception as e:
            magictype = 'Error getting magic type - %s' % e
        return magictype
            
    def gethash(self, htype):
        if htype == 'md5':
            m = hashlib.md5() 
        elif htype == 'sha1':
            m = hashlib.sha1() 
        elif htype == 'sha256':
            m = hashlib.sha256() 
        m.update(self.pe.__data__)
        return m.hexdigest()    
    
    def getimphash(self):
        ihash = ''
        try:
            if self.pe is not None:
                ihash = self.pe.get_imphash()
            else:
                ihash = 'Skipped...'
        except AttributeError as ae:
            ihash = 'No imphash support, upgrade pefile to a version >= 1.2.10-139'
        finally:
            return ihash
    
    def getstringentries(self):
        versioninfo = {}
        varfileinfo = {}
        stringfileinfo = {}
        if self.pe is not None:
            try:                
                for t in self.pe.FileInfo:
                    if t.name == 'VarFileInfo':
                        for vardata in t.Var:
                            for key in vardata.entry:   
                                try:
                                    varfileinfo[key] = vardata.entry[key]                                                               
                                    tparms = vardata.entry[key].split(' ')                                    
                                    varfileinfo['LangID'] = tparms[0]
                                    # TODO: Fix this...this is terrible
                                    varfileinfo['charsetID'] = str(int(tparms[1], 16))
                                except Exception as e:
                                    # Todo Update error handling to better support being called from code.
                                    print e
                                    
                    elif t.name == 'StringFileInfo':
                        for vdata in t.StringTable:
                            for key in vdata.entries:
                                stringfileinfo[key] = vdata.entries[key]
                    else:
                        versioninfo['unknown'] = 'unknown'
            except AttributeError as ae:
                versioninfo['Error'] = ae
        else:
            versioninfo['Error'] = 'Not a PE file.'
        
        versioninfo["VarInfo"] = varfileinfo 
        versioninfo["StringInfo"] = stringfileinfo
        
        return versioninfo 
        
    def listimports(self):
        modules = {}
        try:
            for module in self.pe.DIRECTORY_ENTRY_IMPORT:
                modules[module.dll] = module.imports
        except Exception as e:
            # Todo Update error handling to better support being called from code.
            print 'Error processing imports - %s ' % e
        return modules
                        
                        
    def getheaderinfo(self):
        info = {}
        info['Checksum'] = self.pe.OPTIONAL_HEADER.CheckSum
        info['Compile Time'] = '%s UTC' % time.asctime(time.gmtime(self.pe.FILE_HEADER.TimeDateStamp))
        info['Signature'] = hex(self.pe.NT_HEADERS.Signature)
        info['Packed'] = peutils.is_probably_packed(self.pe)
        info['Image Base'] = hex(self.pe.OPTIONAL_HEADER.ImageBase)
        info['Sections'] = self.pe.FILE_HEADER.NumberOfSections
        info['Entry Point'] = hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        info['Subsystem'] = pefile.subsystem_types[self.pe.OPTIONAL_HEADER.Subsystem][0]

        linker = '{}.{}'.format(self.pe.OPTIONAL_HEADER.MajorLinkerVersion, self.pe.OPTIONAL_HEADER.MinorLinkerVersion)

        try:
            info['Linker Version'] = '{} - ({})'.format(linker, self.linker_versions[linker])
        except KeyError:
            info['Linker Version'] = '{}'.format(linker)

        info['EP Bytes'] = self.getbytestring(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint, 16, True)
        return info
    
    def getfuzzyhash(self):
        try:
            import ssdeep
        except Exception as e:
            return 'Error - Please ensure you install the ssdeep library.'
        
        f = open(self.filename, 'rb')
        fdat = f.read()
        f.close()
        return ssdeep.hash(fdat)
    
    def extractdata(self, offset, size):
        try:
            data = self.pe.get_memory_mapped_image()[offset:offset+size]
        except Exception as e:
            print e
            data = None
        return data
        
    def getbytestring(self, start, length, mmap=False):

        dat = ''
        if mmap:
            mmdat = self.pe.get_memory_mapped_image()
            dat = mmdat[start:start+length]
        else:
            dat = self.pe.__data__[start:start+length]
        
        bstr = ''
        for c in dat:
            bstr += '%s ' % c.encode('hex')
        return bstr

    def scan_signatures(self, sigfile):
        sigs = peutils.SignatureDatabase(sigfile)
        matches = sigs.match_all(self.pe, ep_only=True)
        return matches

    def analyze(self):
        """

        Analyze the loaded file.

        :return: -- A List of results
        """

        results = []

        modbl = ['MSVBVM60.DLL', 'MSVBVM50.DLL']

        modlist = ['KERNEL32.DLL', 'USER32.DLL', 'WINMM.DLL', 'NTDLL.DLL', 'PSAPI.DLL']

        dbglist = ['isdebuggerpresent', 'checkremotedebuggerpresent', 'gettickcount', 'outputdebugstring',
                   'ntqueryobject', 'findwindow', 'timegettime', 'ntqueryinformationprocess',
                   'isprocessorfeaturepresent', 'ntquerysysteminformation', 'createtoolhelp32snapshot', 'blockinput',
                   'setunhandledexceptionfilter', 'queryperformancecounter', 'ntsetdebugfilterstate', 'dbgbreakpoint',
                   'rtlqueryprocessdebuginformation', 'blockinput']

        dsdcalls = ['createdesktop', 'switchdesktop']

        importbl = ['openprocess', 'virtualallocex', 'writeprocessmemory', 'createremotethread', 'readprocessmemory',
                    'createprocess', 'winexec', 'shellexecute', 'httpsendrequest', 'internetreadfile', 'internetconnect',
                    'createservice', 'startservice']

        # Standard section names.
        predef_sections = ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.idata', '.pdata', '.debug',
                           '.reloc', '.sxdata', '.tls']



        # Get filetype
        results.append(AnalysisResult(2, 'File Type', self.magic_type(self.filename)))

        if not self.pe.verify_checksum():
            results.append(AnalysisResult(0, 'Checksum', "Invalid CheckSum"))

        if peutils.is_probably_packed(self.pe):
            results.append(AnalysisResult(1, 'Packed', "Sample is probably packed"))

        modules = self.listimports()
        impcount = len(modules)

        dsd = 0
        dotnet = False
        for modulename in modules:

            if modulename == 'mscoree.dll':
                dotnet = True
                continue

            if modulename in modbl:
                results.append(AnalysisResult(0, 'Imports', "Suspicious Import [%s]" % modulename))

            if modulename.upper() in modlist:
                for symbol in modules[modulename]:
                    if symbol.name.lower() in dbglist:
                        results.append(AnalysisResult(0, 'AntiDebug', 'AntiDebug Function import [%s]' % symbol.name))
                    if symbol.name.lower() in importbl:
                        results.append(AnalysisResult(0, 'Imports', 'Suspicious API Call [%s]' % symbol.name))
                    if symbol.name.lower() in dsdcalls:
                        dsd += 1

        # If the sample is dotnet, don't warn on a low import count.
        if impcount < 3 and not dotnet:
            results.append(AnalysisResult(1, 'Imports', "Low import count %d " % impcount))

        if dsd == 2:
            results.append(AnalysisResult(0, 'AntiDebug', 'AntiDebug Function import CreateDesktop/SwitchDestkop'))

        sections = self.pe.sections
        for section in sections:
            if section.Name.strip('\0') not in predef_sections:
                results.append(AnalysisResult(1, 'Sections', 'Uncommon Section Name [%s]' % section.Name.strip('\0')))

            if section.SizeOfRawData == 0:
                results.append(AnalysisResult(1, 'Sections', 'Raw Section Size is 0 [%s]' % section.Name.strip('\0')))

        # Scan for peid matches
        matches = self.scan_signatures(self.peiddb)
        if matches is not None:
            for match in matches:
                results.append(AnalysisResult(2, 'PeID', 'Match [%s]' % match[0]))
        else:
            results.append(AnalysisResult(2, 'PeID', 'No Matches'))

        # Run yara rules
        # TODO: Look at how to retern verbose rule info. This may be useful for upstream callers
        if use_yara:
            try:
                ymatches = self.yara_scan()
                if len(ymatches) > 0:
                    for sections in ymatches:
                        for match in ymatches[sections]:
                            if match['matches']:
                                # Check if the rule metadata has a severity field and use it otherwise default to sev 2
                                if 'severity' in match['meta']:
                                    results.append(AnalysisResult(match['meta']['severity'], 'Yara Rule', '%s' % match['rule']))
                                else:
                                    results.append(AnalysisResult(2, 'Yara Rule', 'Match [%s]' % match['rule']))
                else:
                    results.append(AnalysisResult(2, 'Yara Rule', 'No Matches'))
            except Exception as e:
                results.append(AnalysisResult(2, 'Yara Rule', 'Error running yara rules: %s' % e))
        else:
            results.append(AnalysisResult(0, 'Yara Rule', 'Yara not run.'))

        return results

    def yara_scan(self):
        rules = yara.compile(self.yararules)
        matches = rules.match(data=self.pe.__data__)
        return matches

    def __repr__(self):
        fobj = "\n\n"
        fobj += "---- File Summary ----\n"
        fobj += "\n"
        fobj += ' General\n'
        fobj += ' {:4}{:<16} {}\n'.format('', "Filename", self.filename)
        fobj += ' {:4}{:<16} {}\n'.format('', "Magic Type", self.magic_type(self.filename))
        fobj += ' {:4}{:<16} {}\n'.format('', "Size", self.filesize)
        fobj += ' {:4}{:<16} {}\n\n'.format('', "First Bytes", self.getbytestring(0, 16))
        fobj += ' Hashes\n'
        fobj += ' {:4}{:<16} {}\n'.format('', "MD5", self.gethash('md5'))
        fobj += ' {:4}{:<16} {}\n'.format('', "SHA1", self.gethash('sha1'))
        fobj += ' {:4}{:<16} {}\n'.format('', "SHA256", self.gethash('sha256'))
        fobj += ' {:4}{:<16} {}\n'.format('', "Import Hash", self.getimphash())
        fobj += ' {:4}{:<16} {}\n\n'.format('', "ssdeep", self.getfuzzyhash())
        fobj += ' Headers\n'

        if self.pe is not None:
            hinfo = self.getheaderinfo()
            for str_key in hinfo:
                fobj += ' {:4}{:<16} {}\n'.format('', str_key, hinfo[str_key])
            iflags = pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')

            flags = []
            fobj += ' {:4}{:<16} \n'.format('', "Characteristics")
            for flag in iflags:
                if getattr(self.pe.FILE_HEADER, flag[0]):
                    fobj += " {:20s} {:<20s}\n".format('', str(flag[0]))
                                
        return fobj


class AnalysisResult:

    def __init__(self, severity, restype, message):
        self.severity = severity
        self.restype = restype
        self.message = message


    def _formatmsg(self, sev, string):
        # 31 - Error
        # 33 - Warning
        # 37 - Info
        if sev == 0:
            return "\033[31m [!] %s \033[0m" % string
        elif sev == 1:
            return "\033[33m [!] %s \033[0m" % string
        elif sev == 2:
            return "\033[37m [*] %s \033[0m" % string
        else:
            return " [*] " + string

    def __repr__(self):
        return ' {:<30s}{:<20s}'.format(self._formatmsg(self.severity, self.restype), self.message)

def print_imports(modules):

    print " ---- Imports ----  "
    print ' Number of imported modules: %s \n ' % len(modules)
    for str_entry in modules:
        print '\n %s ' % str_entry
        for symbol in modules[str_entry]:
            if symbol.import_by_ordinal is True:
                if symbol.name is not None:
                    print '  |-- %s Ordinal[%s] (Imported by Ordinal)' % (symbol.name, str(symbol.ordinal))
                else:
                    print '  |-- Ordinal[%s] (Imported by Ordinal)' % (str(symbol.ordinal))
            else:
                print '  |-- %s' % symbol.name
    print '\n\n'


def print_versioninfo(versioninfo):

    # output the version info blocks.
    print '\n---- Version Info ----  \n'
    if 'StringInfo' in versioninfo:
        sinfo = versioninfo['StringInfo']
        if len(sinfo) == 0:
            print ' No version info block...'
        else:
            for str_entry in sinfo:
                print ' {:<16} {}'.format(str_entry, sinfo[str_entry].encode('utf-8'))

    if 'VarInfo' in versioninfo:
        vinfo = versioninfo['VarInfo']
        if len(vinfo) == 0:
            print ' No language info block...'
        else:
            print ''
            for str_entry in vinfo:
                if str_entry == 'LangID':
                    try:
                        print ' {:<16} {} ({})'.format('LangID', PFTriage.langID[int(vinfo[str_entry], 16)], vinfo[str_entry].encode('utf-8'))
                    except KeyError:
                        print ' {:<16} {} ({})'.format('LangID', 'Invalid Identifier!', vinfo[str_entry].encode('utf-8'))
                elif str_entry == 'charsetID':
                    try:
                        print ' {:<16} {} ({})'.format('charsetID', PFTriage.charsetID[int(vinfo[str_entry])], vinfo[str_entry].encode('utf-8'))
                    except KeyError:
                        print ' {:<16} {} ({})'.format('charsetID: Invalid Identifier!', vinfo[str_entry].encode('utf-8'))
                else:
                    print ' {:<16} {}'.format(str_entry, vinfo[str_entry].encode('utf-8'))
    print ''

    

def print_resources(target, dumprva):
    try:
        dumpaddress = dumprva[0]
    except:
        dumpaddress = 0
    
    data = "\n ---- Resource Overview ----  \n\n"


    try:
        resdir = target.pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        data += 'Resources not found...\n'
        print data
        return
        
    for entry in resdir.entries:

        if entry.id is not None:
            try:
                rname = PFTriage.resource_type[entry.id]
            except KeyError:
                rname = "Unknown (%s)" % entry.id
        else:
            # Identified by name
            rname = str(entry.name)

        data += ' Type: %s\n' % rname
        if hasattr(entry, 'directory'):
            data += "  {:12}{:16}{:20}{:12}{:12}{:12}{:64}\n".format("Name",
                                                                "Language",
                                                                "SubLang",
                                                                "Offset",
                                                                "Size",
                                                                "Code Page",
                                                                "Type")

            for resname in entry.directory.entries:
                if resname.id is not None:
                    data += '  {:<12}'.format(hex(resname.id))
                else:
                    data += '  {:<12}'.format(resname.name)

                for resentry in resname.directory.entries:
                    if hasattr(resentry, 'data'):
                        offset = '{0:#0{1}x}'.format(resentry.data.struct.OffsetToData, 10)
                        data += '{:16}'.format(pefile.LANG[resentry.data.lang])
                        data += '{:20}'.format(pefile.get_sublang_name_for_lang(resentry.data.lang,
                                                                                resentry.data.sublang).replace('SUBLANG_', ''))
                        data += '{:12}'.format(offset)
                        data += '{:12}'.format("{0:#0{1}x}".format(resentry.data.struct.Size, 10))
                        data += '{:12}'.format("{0:#0{1}x}".format(resentry.data.struct.CodePage, 10))
                        data += '{:64}'.format(target.magic_type(target.extractdata(resentry.data.struct.OffsetToData,
                                                                                   resentry.data.struct.Size)[:64], True))
                        
                        if dumpaddress == 'ALL' or dumpaddress == offset:
                            data += '\n\n  Matched offset[%s] -- dumping resource' % dumpaddress
                            tmpdata = target.extractdata(resentry.data.struct.OffsetToData, resentry.data.struct.Size)
                            filename = 'export-%s.bin' % offset
                            f = open(filename, 'wb')
                            f.write(tmpdata)
                            f.close()
                data += '\n'
            data += '\n'
    print data


def print_analysis(target):

    print '[*] Analyzing File...'
    results = target.analyze()
    print '[*] Analysis Complete...'
    print
    for analysis_result in results:
        print analysis_result
    print ''


def print_sections(target):

    if not target.verbose:

        sdata = "\n ---- Section Overview (use -v for detailed section info)  ----  \n\n"
        sdata += " {:10}{:12}{:18}{:20}{:20}{:20}{:20}\n".format("Name",
                                                        "Raw Size",
                                                        "Raw Data Pointer",
                                                        "Virtual Address",
                                                        "Virtual Size",
                                                        "Entropy",
                                                        "Hash")
    
        for section in target.pe.sections:
            sdata += " {:10}".format(section.Name.strip('\0'))
            sdata += "{:12}".format("{0:#0{1}x}".format(section.SizeOfRawData, 10))
            sdata += "{:18}".format("{0:#0{1}x}".format(section.PointerToRawData, 10))
            sdata += "{:20}".format("{0:#0{1}x}".format(section.VirtualAddress, 10))
            sdata += "{:20}".format("{0:#0{1}x}".format(section.Misc_VirtualSize, 10))
            sdata += "{:<20}".format(section.get_entropy())
            sdata += "{:<20}".format(hashlib.md5(section.get_data()).hexdigest())
            sdata += "\n"

    else:
        cflags = pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, 'IMAGE_SCN_')

        sdata = '\n ---- Detailed Section Info ----  \n\n'
        for section in target.pe.sections:
            sdata += " {:10}\n".format(section.Name.strip('\0'))
            sdata += "  {:24} {:>10}\n".format("|-Entropy:", section.get_entropy())
            sdata += "  {:24} {:>10}\n".format("|-MD5 Hash:", hashlib.md5(section.get_data()).hexdigest())
            sdata += "  {:24} {:>10} ({:})\n".format("|-Raw Data Size:", "{0:#0{1}x}".format(section.SizeOfRawData, 10),
                                                     section.SizeOfRawData)
            sdata += "  {:24} {:>10}\n".format("|-Raw Data Pointer:", "{0:#0{1}x}".format(section.PointerToRawData, 10))
            sdata += "  {:24} {:>10}\n".format("|-Virtual Address:", "{0:#0{1}x}".format(section.VirtualAddress, 10))
            sdata += "  {:24} {:>10} ({:})\n".format("|-Virtual Size:", "{0:#0{1}x}".format(section.Misc_VirtualSize, 10),
                                                     section.Misc_VirtualSize)
            sdata += "  {:24} {:>10}\n".format("|-Characteristics:", "{0:#0{1}x}".format(section.Characteristics, 10))
            for flag in cflags:
                if getattr(section, flag[0]):
                    sdata += "  {:24}{:>5}{:<24}\n".format('|', '|-', str(flag[0]))
            sdata += "  {:24} {:<10}\n".format("|-Number Of Relocations:", section.NumberOfRelocations)
            sdata += "  {:24} {:<10}\n".format("|-Line Numbers:", section.NumberOfLinenumbers)
            sdata += '\n'

    print sdata


def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print
    print '-----------------------------'
    print
    print '  pftriage %s' % __version__
    print
    print '-----------------------------'
    print




def main():
    parser = argparse.ArgumentParser(prog='pftriage', usage='%(prog)s [options]',
                                     description="Show information about a file for triage.")
    parser.add_argument("file", help="The file to triage.")
    parser.add_argument('-i', '--imports', dest='imports', action='store_true', help="Display import tree")
    parser.add_argument('-s', '--sections', dest='sections', action='store_true',
                        help="Display overview of sections. For more detailed info pass the -v switch")
    parser.add_argument('-r', '--resources', dest='resources', action='store_true', help="Display resource information")
    parser.add_argument('-D', '--dump', nargs=1, dest='dump_offset',
                        help="Dump data using the passed offset or 'ALL'. Currently only works with resources.")
    parser.add_argument('-p', '--peidsigs', dest='peidsigs', action='store', default='',
                        help="Alternate PEiD Signature File")
    parser.add_argument('-y', '--yararules', dest='yararules', action='store', default='',
                        help="Alternate Yara Rule File")
    parser.add_argument('-a', '--analyze', dest='analyze', action='store_true', help="Analyze the file.")
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False, help="Display version.")
    parser.add_argument('-V', '--version', dest='version', action='store_true', help="Print version and exit.")


    # display banner
    banner()

    try:
        args = parser.parse_args()
    except:
        parser.print_help()
        return -1

    if args.version:
        # Just exit
        return 0

    print '[*] Loading File...'
    targetfile = PFTriage(args.file, yararules=args.yararules, peiddb=args.peidsigs, verbose=args.verbose)

    # if no options are selected print the file details
    if not args.imports and not args.sections and not args.resources and not args.analyze:
        print '[*] Processing File details...'
        print targetfile
        print '[*] Loading Version Info'
        print_versioninfo(targetfile.getstringentries())

    if args.analyze:
        print_analysis(targetfile)
    
    if args.imports:
        print_imports(targetfile.listimports())
    
    if args.sections:
        print_sections(targetfile)
        
    if args.resources:
        print_resources(targetfile, args.dump_offset)

if __name__ == '__main__':
    main()

