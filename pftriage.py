#!/usr/bin/env python
# -*- coding: utf-8 -*-
__description__ = 'pftriage is a tool to help analyze files during malware triage.'
__author__ = 'Sean Wilson'
__version__ = '1.0.4'

import hashlib
import os
import time
import pefile
import peutils
import argparse

try:
    import magic
except ImportError:
    print("[!] Warning file-magic required.")


class PFTriage(object):
    """


    """
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
        "14.0": "Visual Studio 2015",
        "14.1": "1910 (Visual Studio 2017 version 15.0)",
        "14.11": "1911 (Visual Studio 2017 version 15.3)",
        "14.12": "1912 (Visual Studio 2017 version 15.5)",
        "14.13": "1913 (Visual Studio 2017 version 15.6)",
        "14.14": "1914 (Visual Studio 2017 version 15.7)",
        "14.15": "1915 (Visual Studio 2017 version 15.8)",
        "14.16": "1916 (Visual Studio 2017 version 15.9)"
    }

    #
    # From: http://bytepointer.com/articles/the_microsoft_rich_header.htm
    #
    # The build ids don't seem like they overlap..(which means they probably will).....
    # so for now throw everthing in a single dict
    #
    masm_build_map ={
        7299: "6.13.7299",
        8444: "6.14.8444",
        8803: "6.15.8803",
        9030: "6.15.9030(VS.NET 7.0 BETA 1)"
    }

    vb_build_map = {
        8169: "6.0(also reported with SP1 and SP2)",
        8495: "6.0 SP3",
        8877: "6.0 SP4",
        8964: "6.0 SP5",
        9782: "6.0 SP6 (same as reported by VC++ but different id)",
    }

    vs_build_map = {
        8168: "6.0 (RTM, SP1 or SP2)",
        8447: "6.0 SP3",
        8799: "6.0 SP4",
        8966: "6.0 SP5",
        9044: "6.0 SP5 Processor Pack",
        9782: "6.0 SP6",
        9030: "7.0 2000 (BETA 1)",
        9254: "7.0 2001 (BETA 2)",
        9466: "7.0 2002",
        9955: "7.0 2002 SP1",
        3077: "7.1 2003",
        3052: "7.1 2003 Free Toolkit",
        4035: "7.1 2003",
        6030: "7.1 2003 SP1",
        50327: "8.0 2005 (Beta)",
        50727: "8.0 2005",
        21022: "9.0 2008",
        30729: "9.0 2008 SP1",
        30319: "10.0 2010",
        40219: "10.0 2010 SP1",
        50727: "11.0 2012",
        51025: "11.0 2012",
        51106: "11.0 2012 update 1",
        60315: "11.0 2012 update 2",
        60610: "11.0 2012 update 3",
        61030: "11.0 2012 update 4",
        21005: "12.0 2013",
        30501: "12.0 2013 update 2",
        31101: "12.0 2013 update 4",
        40629: "12.0 2013 SP5",
        22215: "14.0 2015",
        23026: "14.0 2015",
        23506: "14.0 2015 SP1",
        23824: "14.0 2015 update 2",
        24215: "14.0 2015",
        24218: "14.0 2015",
        25019: "14.1 2017"
    }

    # Prod Ids based on code and research
    #
    # https://gist.github.com/skochinsky/07c8e95e33d9429d81a75622b5d24c8b
    # http://bytepointer.com/articles/the_microsoft_rich_header.htm
    # http://trendystephen.blogspot.com/2008/01/rich-header.html
    #
    rich_prod_ids = {
        0: "Unknown",
        1: "Import0",
        2: "Linker510",
        3: "Cvtomf510",
        4: "Linker600",
        5: "Cvtomf600",
        6: "Cvtres500",
        7: "Utc11_Basic",
        8: "Utc11_C",
        9: "Utc12_Basic",
        10: "Utc12_C",
        11: "Utc12_CPP",
        12: "AliasObj60",
        13: "VisualBasic60",
        14: "Masm613",
        15: "Masm710",
        16: "Linker511",
        17: "Cvtomf511",
        18: "Masm614",
        19: "Linker512",
        20: "Cvtomf512",
        21: "Utc12_C_Std",
        22: "Utc12_CPP_Std",
        23: "Utc12_C_Book",
        24: "Utc12_CPP_Book",
        25: "Implib700",
        26: "Cvtomf700",
        27: "Utc13_Basic",
        28: "Utc13_C",
        29: "Utc13_CPP",
        30: "Linker610",
        31: "Cvtomf610",
        32: "Linker601",
        33: "Cvtomf601",
        34: "Utc12_1_Basic",
        35: "Utc12_1_C",
        36: "Utc12_1_CPP",
        37: "Linker620",
        38: "Cvtomf620",
        39: "AliasObj70",
        40: "Linker621",
        41: "Cvtomf621",
        42: "Masm615",
        43: "Utc13_LTCG_C",
        44: "Utc13_LTCG_CPP",
        45: "Masm620",
        46: "ILAsm100",
        47: "Utc12_2_Basic",
        48: "Utc12_2_C",
        49: "Utc12_2_CPP",
        50: "Utc12_2_C_Std",
        51: "Utc12_2_CPP_Std",
        52: "Utc12_2_C_Book",
        53: "Utc12_2_CPP_Book",
        54: "Implib622",
        55: "Cvtomf622",
        56: "Cvtres501",
        57: "Utc13_C_Std",
        58: "Utc13_CPP_Std",
        59: "Cvtpgd1300",
        60: "Linker622",
        61: "Linker700",
        62: "Export622",
        63: "Export700",
        64: "Masm700",
        65: "Utc13_POGO_I_C",
        66: "Utc13_POGO_I_CPP",
        67: "Utc13_POGO_O_C",
        68: "Utc13_POGO_O_CPP",
        69: "Cvtres700",
        70: "Cvtres710p",
        71: "Linker710p",
        72: "Cvtomf710p",
        73: "Export710p",
        74: "Implib710p",
        75: "Masm710p",
        76: "Utc1310p_C",
        77: "Utc1310p_CPP",
        78: "Utc1310p_C_Std",
        79: "Utc1310p_CPP_Std",
        80: "Utc1310p_LTCG_C",
        81: "Utc1310p_LTCG_CPP",
        82: "Utc1310p_POGO_I_C",
        83: "Utc1310p_POGO_I_CPP",
        84: "Utc1310p_POGO_O_C",
        85: "Utc1310p_POGO_O_CPP",
        86: "Linker624",
        87: "Cvtomf624",
        88: "Export624",
        89: "Implib624",
        90: "Linker710",
        91: "Cvtomf710",
        92: "Export710",
        93: "Implib710",
        94: "Cvtres710",
        95: "Utc1310_C",
        96: "Utc1310_CPP",
        97: "Utc1310_C_Std",
        98: "Utc1310_CPP_Std",
        99: "Utc1310_LTCG_C",
        100: "Utc1310_LTCG_CPP",
        101: "Utc1310_POGO_I_C",
        102: "Utc1310_POGO_I_CPP",
        103: "Utc1310_POGO_O_C",
        104: "Utc1310_POGO_O_CPP",
        105: "AliasObj710",
        106: "AliasObj710p",
        107: "Cvtpgd1310",
        108: "Cvtpgd1310p",
        109: "Utc1400_C",
        110: "Utc1400_CPP",
        111: "Utc1400_C_Std",
        112: "Utc1400_CPP_Std",
        113: "Utc1400_LTCG_C",
        114: "Utc1400_LTCG_CPP",
        115: "Utc1400_POGO_I_C",
        116: "Utc1400_POGO_I_CPP",
        117: "Utc1400_POGO_O_C",
        118: "Utc1400_POGO_O_CPP",
        119: "Cvtpgd1400",
        120: "Linker800",
        121: "Cvtomf800",
        122: "Export800",
        123: "Implib800",
        124: "Cvtres800",
        125: "Masm800",
        126: "AliasObj800",
        127: "PhoenixPrerelease",
        128: "Utc1400_CVTCIL_C",
        129: "Utc1400_CVTCIL_CPP",
        130: "Utc1400_LTCG_MSIL",
        131: "Utc1500_C",
        132: "Utc1500_CPP",
        133: "Utc1500_C_Std",
        134: "Utc1500_CPP_Std",
        135: "Utc1500_CVTCIL_C",
        136: "Utc1500_CVTCIL_CPP",
        137: "Utc1500_LTCG_C",
        138: "Utc1500_LTCG_CPP",
        139: "Utc1500_LTCG_MSIL",
        140: "Utc1500_POGO_I_C",
        141: "Utc1500_POGO_I_CPP",
        142: "Utc1500_POGO_O_C",
        143: "Utc1500_POGO_O_CPP",
        144: "Cvtpgd1500",
        145: "Linker900",
        146: "Export900",
        147: "Implib900",
        148: "Cvtres900",
        149: "Masm900",
        150: "AliasObj900",
        151: "Resource900",
        152: "AliasObj1000",
        154: "Cvtres1000",
        155: "Export1000",
        156: "Implib1000",
        157: "Linker1000",
        158: "Masm1000",
        170: "Utc1600_C",
        171: "Utc1600_CPP",
        172: "Utc1600_CVTCIL_C",
        173: "Utc1600_CVTCIL_CPP",
        174: "Utc1600_LTCG_C ",
        175: "Utc1600_LTCG_CPP",
        176: "Utc1600_LTCG_MSIL",
        177: "Utc1600_POGO_I_C",
        178: "Utc1600_POGO_I_CPP",
        179: "Utc1600_POGO_O_C",
        180: "Utc1600_POGO_O_CPP",
        183: "Linker1010",
        184: "Export1010",
        185: "Implib1010",
        186: "Cvtres1010",
        187: "Masm1010",
        188: "AliasObj1010",
        199: "AliasObj1100",
        201: "Cvtres1100",
        202: "Export1100",
        203: "Implib1100",
        204: "Linker1100",
        205: "Masm1100",
        206: "Utc1700_C",
        207: "Utc1700_CPP",
        208: "Utc1700_CVTCIL_C",
        209: "Utc1700_CVTCIL_CPP",
        210: "Utc1700_LTCG_C ",
        211: "Utc1700_LTCG_CPP",
        212: "Utc1700_LTCG_MSIL",
        213: "Utc1700_POGO_I_C",
        214: "Utc1700_POGO_I_CPP",
        215: "Utc1700_POGO_O_C",
        216: "Utc1700_POGO_O_CPP",
    }

    def __init__(self, tfile, verbose=False, loglevel='Error'):

        if not os.path.isfile(tfile):
            raise Exception('Error! File does not exist...')

        self.filename = tfile
        self.pe = None
        self.filesize = os.path.getsize(self.filename)
        self.verbose = verbose
        self.loglevel = loglevel
        self.pe = pefile.PE(self.filename)

        self.metadata = self._populate_metadata()
        self.hashes = self._calcHashes()

    def get_image_flags(self, imageflags='IMAGE_FILE_'):
        iflags = pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, imageflags)
        flags = []
        for flag in iflags:
            if getattr(self.pe.FILE_HEADER, flag[0]):
                flags.append(flag[0])
        return flags

    def magic_type(self, data, isdata=False):
        try:
            if isdata:
                magictype = magic.detect_from_content(data[0:512]).name
            else:
                magictype = magic.detect_from_filename(data).name
        except NameError:
            magictype = 'Error - file-magic library required.'
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
        except AttributeError as ae:
            ihash = 'No imphash support, upgrade pefile to a version >= 1.2.10-139'
        finally:
            return ihash

    def process_overlay_data(self, action):
        """
        Process overlay data

        :param action:
        :return:
        """

        overlay = self.detect_overlay()
        if overlay > 0:
            with open(self.filename, 'rb') as rf:
                raw = rf.read()
            if action == 0:
                out_data = raw[:overlay]
            elif action == 1:
                out_data = raw[overlay:]
            else:
                raise Exception('Unknown Action!')
            return out_data
        else:
            return ""

    def remove_overlay_data(self):
        """
        Remove any overlay data appened to the PE file.

        :return:
        """

        overlay = self.detect_overlay()
        if overlay > 0:
            with open(self.filename,'rb') as rf:
                raw = rf.read()
            out_data = raw[:overlay]
            return out_data
        else:
            return ""

    def getstringentries(self):
        """
        Process Version and File Info

        :return:
        """
        versioninfo = {}
        varfileinfo = {}
        stringfileinfo = {}
        try:
            if hasattr(self.pe, 'VS_VERSIONINFO') and hasattr(self.pe, 'FileInfo'):
                for t in self.pe.FileInfo:

                    # Terrible hack to work around an issue I keep seeing with ~1/2 the bins.
                    # Something may have changed in pefile, but I need some time to look into this.
                    # For now cast as a list and then process.
                    if not isinstance(t, (list,)):
                        entry = [t]
                    else:
                        entry = t

                    for sub_e in entry:
                        if sub_e.name == 'VarFileInfo':
                            for vardata in sub_e.Var:
                                for key in vardata.entry:
                                    try:
                                        varfileinfo[key] = vardata.entry[key]
                                        tparms = vardata.entry[key].split(' ')
                                        varfileinfo['LangID'] = tparms[0]
                                        # TODO: Fix this...this is terrible
                                        varfileinfo['charsetID'] = str(int(tparms[1], 16))
                                    except Exception as e:
                                        # Todo Update error handling to better support being called from code.
                                        print(" [!] Error processing VarFileInfo :: %s" % e)

                        elif sub_e.name == 'StringFileInfo':
                            for vdata in sub_e.StringTable:
                                for key in vdata.entries:
                                    # for now strip any non-ascii chars
                                    stringfileinfo[key] = vdata.entries[key].decode('utf8').encode('ascii', 'ignore')
                        else:
                            versioninfo['unknown'] = 'unknown'
        except AttributeError as ae:
            print(' [!] Error parsing Version Info :: %s' % ae)

        versioninfo["VarInfo"] = varfileinfo
        versioninfo["StringInfo"] = stringfileinfo

        return versioninfo

    def listimports(self):
        modules = {}
        try:
            for module in self.pe.DIRECTORY_ENTRY_IMPORT:
                modules[module.dll] = module.imports
        except AttributeError:
            pass

        return modules

    def get_pdb_path(self):
        path = None
        try:
            path = self.pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName
        except:
            pass
        return path

    def get_exports(self):
        """
        Get exports as an array of tuples (ordinal, name)
        :return:
        """

        exports = []
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append((exp.address, exp.ordinal, exp.name))
        except Exception as e:
            # Todo Update error handling to better support being called from code.
            print(' [!] Error processing exports - %s ' % e)
        return exports

    def getfuzzyhash(self):
        try:
            import ssdeep
        except ImportError:
            return 'Error - Please ensure you install the ssdeep library.'

        f = open(self.filename, 'rb')
        fdat = f.read()
        f.close()
        return ssdeep.hash(fdat)

    def extractdata(self, offset, size):
        try:
            data = self.pe.get_memory_mapped_image()[offset:offset+size]
        except Exception as e:
            print(e)
            data = None
        return data

    def get_byte_string(self, start, length, mmap=False):

        if mmap:
            mmdat = self.pe.get_memory_mapped_image()
            try:
                return mmdat[start:start+length].hex()
            except AttributeError:
                return ''.join(x.encode('hex') for x in mmdat[start:start+length])
        else:
            try:
                return self.pe.__data__[start:start+length].hex()
            except AttributeError:
                return ''.join(x.encode('hex') for x in self.pe.__data__[start:start+length])

    def scan_signatures(self, sigfile):
        """
        Scan the PE file using a PEiD Signature file.
        :param sigfile: The path to the PEiD signature file
        :return:
        """
        sigs = peutils.SignatureDatabase(sigfile)
        matches = sigs.match_all(self.pe, ep_only=True)
        return matches

    def detect_overlay(self):
        return self.pe.get_overlay_data_start_offset()

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

        importwl = ['terminateprocess']

        # Standard section names.
        predef_sections = ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.idata', '.pdata', '.debug',
                           '.reloc', '.sxdata', '.tls']

        # Default section names for common free/commercial packers.
        # From http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/
        common_packer_names = {
            "aspack": "Aspack Packer",
            ".adata": "Aspack Packer/Armadillo packer",
            "ASPack": "Aspack packer",
            ".ASPack": "ASPAck Protector",
            ".MPRESS1": "MPRESS Packer",
            ".MPRESS2": "MPRESS Packer",
            "pebundle": "PEBundle Packer",
            "PEBundle": "PEBundle Packer",
            "PEC2TO": "PECompact Packer",
            "PEC2": "PECompact Packer",
            "pec1": "PECompact Packer",
            "pec2": "PECompact Packer",
            "PEC2MO": "PECompact Packer",
            "PELOCKnt": "PELock Protector",
            "PESHiELD": "PEShield Packer",
            "Themida": "Themida Packer",
            ".Themida": "Themida Packer",
            "UPX0": "UPX packer",
            "UPX1": "UPX packer",
            "UPX2": "UPX packer",
            "UPX!": "UPX packer",
            ".UPX0": "UPX Packer",
            ".UPX1": "UPX Packer",
            ".UPX2": "UPX Packer",
            ".vmp0": "VMProtect packer",
            ".vmp1": "VMProtect packer",
            ".vmp2": "VMProtect packer",
            "VProtect": "Vprotect Packer"
        }

        # Get filetype
        results.append(AnalysisResult(2, 'File Type', self.magic_type(self.filename)))

        if not self.pe.verify_checksum():
            # self.OPTIONAL_HEADER.CheckSum == self.generate_checksum()
            results.append(AnalysisResult(0, 'Checksum', "The checksum %x does not match %x " % (self.pe.OPTIONAL_HEADER.CheckSum, self.pe.generate_checksum())))

        if peutils.is_probably_packed(self.pe):
            results.append(AnalysisResult(1, 'Packed', "Likely contains compressed or packed data."))

        if self.detect_overlay() > 0:
            results.append(AnalysisResult(1, 'Overlay', "Detected Overlay [%s]" % hex(self.detect_overlay())))

        modules = self.listimports()
        impcount = len(modules)

        dsd = 0
        dotnet = False
        for modulename in modules:

            if modulename == 'mscoree.dll':
                dotnet = True
                continue

            if modulename.upper() in modbl:
                results.append(AnalysisResult(0, 'Imports', "Suspicious Import [%s]" % modulename))

            if modulename.upper() in modlist:
                for symbol in modules[modulename]:
                    if symbol.name.lower() in dbglist:
                        results.append(AnalysisResult(0, 'AntiDebug', 'Anti-Debug Function import [%s]' % symbol.name))

                    if symbol.name.lower() in importbl:
                        results.append(AnalysisResult(0, 'Imports', 'Suspicious API Call [%s]' % symbol.name))
                    if symbol.name.lower() in importwl:
                        results.append(AnalysisResult(1, 'Imports', 'Suspicious API Call [%s]' % symbol.name))

                    if symbol.name.lower() in dsdcalls:
                        dsd += 1

        # If the sample is dotnet, don't warn on a low import count.
        if impcount < 3 and not dotnet:
            results.append(AnalysisResult(1, 'Imports', "Low import count %d " % impcount))

        if dsd == 2:
            results.append(AnalysisResult(0, 'AntiDebug', 'AntiDebug Function import CreateDesktop/SwitchDestkop'))

        sections = self.pe.sections
        for section in sections:
            name = section.Name.strip('\0')
            if name not in predef_sections:
                if name in common_packer_names.keys():
                    results.append(AnalysisResult(0, 'Sections', 'The section name [%s] is a common name for the %s' % (name, common_packer_names[name])))
                else:
                    results.append(AnalysisResult(1, 'Sections', 'Uncommon Section Name [%s]' % name))
            if section.SizeOfRawData == 0:
                results.append(AnalysisResult(1, 'Sections', 'Raw Section Size is 0 [%s]' % name))

        return results

    def _lookup_build_id(self, prodid, buildid):
        """
        Simple lookup based on the prodid

        :param prodid:
        :param buildid:
        :return:
        """

        try:
            prod = self.rich_prod_ids[prodid]
        except KeyError:
            return "<Unknown>"

        try:
            if "masm" in prod.lower():
                return self.masm_build_map[buildid]
            elif "basic" in prod.lower():
                return self.vb_build_map[buildid]
        except KeyError:
            pass

        try:
            return self.vs_build_map[buildid]
        except KeyError:
            return "<Unknown>"

    # ref: https://gist.github.com/skochinsky/07c8e95e33d9429d81a75622b5d24c8b
    def parse_rich_header(self):

        rh = self.pe.parse_rich_header()

        if not rh:
            return None

        rvals = rh['values']
        entries = []
        for val in xrange(0,len(rvals), 2):
            header = {"Product": "<Unknown>",
                      "Build": "<Unknown>",
                      "ProdId": (rvals[val] >> 16),
                      "BuildId": rvals[val] & 0xFFFF
                      }
            try:
                header["Product"] = self.rich_prod_ids[header["ProdId"]]
                header["Build"] = self._lookup_build_id(header["ProdId"], header["BuildId"])
            except KeyError:
                pass

            header["Count"] = rvals[val + 1]

            entries.append(header)
        parsed_header = {"Checksum": hex(rh['checksum']), "Entries": entries}
        return parsed_header

    def _populate_metadata(self):
        metadata = {}
        metadata['Checksum'] = self.pe.OPTIONAL_HEADER.CheckSum
        metadata['Compile Time'] = '%s UTC' % time.asctime(time.gmtime(self.pe.FILE_HEADER.TimeDateStamp))
        metadata['Signature'] = hex(self.pe.NT_HEADERS.Signature)
        metadata['Packed'] = peutils.is_probably_packed(self.pe)
        metadata['Image Base'] = hex(self.pe.OPTIONAL_HEADER.ImageBase)
        metadata['Sections'] = self.pe.FILE_HEADER.NumberOfSections
        metadata['Entry Point'] = "{0:#0{1}x}".format(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint, 10)
        metadata['Subsystem'] = pefile.subsystem_types[self.pe.OPTIONAL_HEADER.Subsystem][0]

        linker = '{}.{}'.format(self.pe.OPTIONAL_HEADER.MajorLinkerVersion, self.pe.OPTIONAL_HEADER.MinorLinkerVersion)

        try:
            metadata['Linker Version'] = '{} - ({})'.format(linker, self.linker_versions[linker])
        except KeyError:
            metadata['Linker Version'] = '{}'.format(linker)



        metadata['EP Bytes'] = self.get_byte_string(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint, 16, True)

        return metadata

    def _calcHashes(self):
        hashes = {"MD5": self.gethash('md5'), "SHA1":self.gethash('sha1'), "SHA256": self.gethash('sha256'),
                  "Import Hash": self.getimphash(), "SSDeep": self.getfuzzyhash()}
        return hashes

    def __repr__(self):
        fobj = "\n\n"
        fobj += "---- File Summary ----\n"
        fobj += "\n"
        fobj += ' General\n'
        fobj += ' {:4}{:<16} {}\n'.format('', "Filename", self.filename)
        fobj += ' {:4}{:<16} {}\n'.format('', "Magic Type", self.magic_type(self.filename))
        fobj += ' {:4}{:<16} {}\n'.format('', "Size", self.filesize)
        fobj += ' {:4}{:<16} {}\n\n'.format('', "First Bytes", self.get_byte_string(0, 16))
        fobj += ' Hashes\n'
        fobj += ' {:4}{:<16} {}\n'.format('', "MD5", self.gethash('md5'))
        fobj += ' {:4}{:<16} {}\n'.format('', "SHA1", self.gethash('sha1'))
        fobj += ' {:4}{:<16} {}\n'.format('', "SHA256", self.gethash('sha256'))
        fobj += ' {:4}{:<16} {}\n'.format('', "Import Hash", self.getimphash())
        fobj += ' {:4}{:<16} {}\n\n'.format('', "ssdeep", self.getfuzzyhash())
        fobj += ' Headers\n'

        if self.pe is not None:
            for str_key in self.metadata:
                fobj += ' {:4}{:<16} {}\n'.format('', str_key, self.metadata[str_key])

            fobj += ' {:4}{:<16} {}\n'.format('', "PDB Path", self.get_pdb_path())
            iflags = pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')

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
    """
    Print the imports for the passed list of modules

    :param modules:
    :return:
    """
    print(' ---- Imports ----  ')
    print(' Number of imported modules: %s \n ' % len(modules))
    for str_entry in modules:
        print('\n %s ' % str_entry)
        for symbol in modules[str_entry]:
            if symbol.import_by_ordinal is True:
                if symbol.name is not None:
                    print('  |-- %s Ordinal[%s] (Imported by Ordinal)' % (symbol.name, str(symbol.ordinal)))
                else:
                    print('  |-- Ordinal[%s] (Imported by Ordinal)' % (str(symbol.ordinal)))
            else:
                print('  |-- %s' % symbol.name)

    print('\n\n')


def print_exports(exports):
    """

    :param exports:
    :return:
    """
    print('\n ---- Exports ----')
    print(' Total Functions: %d\n' % len(exports))
    print(' {:12}{:10}{:32}'.format("Address", "Ordinal", "Name"))

    if len(exports) > 0:
        for export in exports:
            print(' {:12}{:<10}{:32}'.format("{0:#0{1}x}".format(export[0], 10), export[1], export[2]))


def print_resources(target, dumprva):
    """

    Print resources and optionally dump a resource based on the passed RVA

    :param target:
    :param dumprva:
    :return:
    """
    try:
        dumpaddress = dumprva[0]
    except:
        dumpaddress = 0

    data = "\n ---- Resource Overview ----  \n\n"

    try:
        resdir = target.pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        data += 'Resources not found...\n'
        print(data)
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
                        try:
                            data += '{:16}'.format(pefile.LANG[resentry.data.lang])
                        except KeyError:
                            data += '{:16}'.format('Unknown (%s)' % resentry.data.lang)

                        data += '{:20}'.format(pefile.get_sublang_name_for_lang(resentry.data.lang,
                                                                                resentry.data.sublang).replace('SUBLANG_', ''))
                        data += '{:12}'.format(offset)
                        data += '{:12}'.format("{0:#0{1}x}".format(resentry.data.struct.Size, 10))
                        data += '{:12}'.format("{0:#0{1}x}".format(resentry.data.struct.CodePage, 10))
                        #data += '{:64}'.format(target.magic_type(target.extractdata(resentry.data.struct.OffsetToData,
                                                                                   #resentry.data.struct.Size)[:64], True))
                        if dumpaddress == 'ALL' or dumpaddress == offset:
                            data += '\n\n  Matched offset[%s] -- dumping resource' % dumpaddress
                            tmpdata = target.extractdata(resentry.data.struct.OffsetToData, resentry.data.struct.Size)
                            filename = 'export-%s.bin' % offset
                            f = open(filename, 'wb')
                            f.write(tmpdata)
                            f.close()
                data += '\n'
            data += '\n'
    print(data)


def print_analysis(target):
    """
    Print out the analysis results for the file.

    :param target:
    :return:
    """

    print('[*] Analyzing File...')
    results = target.analyze()
    print('[*] Analysis Complete...\n')

    for analysis_result in results:
        print(analysis_result)


def print_sections(target, dumprva=None):
    """

    :param target:
    :param dumprva:
    :return:
    """

    try:
        dump_address = dumprva[0]
    except:
        dump_address = 0

    # Get overlay start
    overlay = target.detect_overlay()
    if not target.verbose:
        print("\n ---- Section Overview (use -v for detailed section info)  ----  \n\n")
        sdata = " {:12}{:12}{:18}{:20}{:20}{:20}{:20}\n".format("Name",
                                                                 "Raw Size",
                                                                 "Raw Data Pointer",
                                                                 "Virtual Address",
                                                                 "Virtual Size",
                                                                 "Entropy",
                                                                 "Hash")

        for section in target.pe.sections:
            sdata += " {:12}".format(section.Name.strip('\0'))
            sdata += "{:12}".format("{0:#0{1}x}".format(section.SizeOfRawData, 10))
            sdata += "{:18}".format("{0:#0{1}x}".format(section.PointerToRawData, 10))
            sdata += "{:20}".format("{0:#0{1}x}".format(section.VirtualAddress, 10))
            sdata += "{:20}".format("{0:#0{1}x}".format(section.Misc_VirtualSize, 10))
            sdata += "{:<20}".format(section.get_entropy())
            sdata += "{:<20}".format(hashlib.sha1(section.get_data()).hexdigest())
            if dump_address == 'ALL' or dump_address == '{0:#0{1}x}'.format(section.VirtualAddress, 10):
                sdata += "  [Exported]"
                with open('exported-%s-%s' %(section.Name.strip('\0'), '{0:#0{1}x}'.format(section.VirtualAddress, 10)), 'wb') as out:
                    out.write(section.get_data())
            sdata += "\n"

        # Check for overlay
        if overlay > 0:
            overlay_size = target.filesize - overlay
            sdata += " {:12}".format('.overlay')
            sdata += "{:12}".format("{0:#0{1}x}".format(overlay_size, 10))
            sdata += "{:18}".format(hex(overlay))
            sdata += "{:20}".format('0x00000000')
            sdata += "{:20}".format('0x00000000')
            sdata += "{:<20}".format('0')
            sdata += "{:<20}".format('N/A')
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

            if dump_address == 'ALL' or dump_address == '{0:#0{1}x}'.format(section.VirtualAddress, 10):
                sdata += "  |-[Exported]\n"
                with open('exported-%s-%s' %(section.Name.strip('\0'), '{0:#0{1}x}'.format(section.VirtualAddress, 10)), 'wb') as out:
                    out.write(section.get_data())
            sdata += '\n'

        if overlay > 0:
            sdata += " {:10}\n".format(".overlay")
            sdata += "  {:24} {:>10} ({:})\n".format("|-Raw Data Size:", "{0:#0{1}x}".format(target.filesize - overlay, 10),
                                                     target.filesize - overlay)
            sdata += "  {:24} {:>10}\n".format("|-Raw Data Pointer:", "{0:#0{1}x}".format(overlay, 10))

    print(sdata)


def print_versioninfo(versioninfo):
    """

    :param versioninfo:
    :return:
    """
    if not versioninfo:
        print('\n No Version Info Detected...')
        return

    # output the version info blocks.
    print('\n---- Version Info ----  \n')
    if 'StringInfo' in versioninfo:
        sinfo = versioninfo['StringInfo']
        if len(sinfo) == 0:
            print(' No version info block...')
        else:
            for str_entry in sinfo:
                print(' {:<16} {}'.format(str_entry, sinfo[str_entry].encode('utf-8')))

    if 'VarInfo' in versioninfo:
        vinfo = versioninfo['VarInfo']
        if len(vinfo) == 0:
            print(' No language info block...')
        else:
            print('')
            for str_entry in vinfo:
                if str_entry == 'LangID':
                    try:
                        print(' {:<16} {} ({})'.format('LangID', PFTriage.langID[int(vinfo[str_entry], 16)], vinfo[str_entry].encode('utf-8')))
                    except KeyError:
                        print(' {:<16} {} ({})'.format('LangID', 'Invalid Identifier!', vinfo[str_entry].encode('utf-8')))
                elif str_entry == 'charsetID':
                    try:
                        print(' {:<16} {} ({})'.format('charsetID', PFTriage.charsetID[int(vinfo[str_entry])], vinfo[str_entry].encode('utf-8')))
                    except KeyError:
                        print(' {:<16} {} ({})'.format('charsetID', 'Error Invalid Identifier!', vinfo[str_entry].encode('utf-8')))
                else:
                    print(' {:<16} {}'.format(str_entry, vinfo[str_entry].encode('utf-8')))


def remove_overlay(targetfile):
    """

    :param targetfile:
    :return:
    """
    print(' [*] Removing Overlay data...')
    data = targetfile.process_overlay_data(0)
    if len(data) == 0:
        print(' [!] No overlay data detected...skipping')
        return

    print(' [*] Writing cleaned file to %s-cleaned' % targetfile.filename)
    with open('%s-cleaned' % targetfile.filename,'wb') as out:
        out.write(data)

def extract_overlay(targetfile):
    print(' [*] Removing Overlay data...')
    data = targetfile.process_overlay_data(1)
    if len(data) == 0:
        print(' [!] No overlay data')
        return

    print(' [*] Writing extracted data to file to %s-overlay' % targetfile.filename)
    with open('%s-overlay' % targetfile.filename,'wb') as out:
        out.write(data)


def print_rich_headers(headers):
    print("-- Rich Header Details --\n")
    print(" Checksum: %s" % headers["Checksum"])

    result = " {:<4}{:<16}{:<8}{:<10}{:<32}\n".format("Id","Product", "Count", "Build Id","Build")
    result += " {:<4}{:<16}{:<8}{:<10}{:<32}\n".format("-"*2, "-"*7, "-"*5, "-"*8, "-"*5)

    for entry in headers["Entries"]:
        result += " {:<4}{:<16}{:<8}{:<10}{:<32}\n".format(entry["ProdId"],
                                                           entry["Product"],
                                                           entry["Count"],
                                                           entry["BuildId"],
                                                           entry["Build"])

    print(result)

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = """
        ________________________________      .__                       
        \______   \_   _____/\__    ___/______|__|____     ____   ____  
         |     ___/|    __)    |    |  \_  __ \  \__  \   / ___\_/ __ \ 
         |    |    |     \     |    |   |  | \/  |/ __ \_/ /_/  >  ___/ 
         |____|    \___  /     |____|   |__|  |__(____  /\___  / \___  >
                       \/                             \//_____/      \/ 
                                                                        \033[92m %s \033[0m
    """ % __version__
    print(banner)


def main():
    parser = argparse.ArgumentParser(prog='pftriage', usage='%(prog)s [options]',
                                     description="Show information about a file for triage.")
    parser.add_argument("file", help="The file to triage.")
    parser.add_argument('-i', '--imports', dest='imports', action='store_true', help="Display import tree")
    parser.add_argument('-s', '--sections', dest='sections', action='store_true',
                        help="Display overview of sections. For more detailed info pass the -v switch")
    parser.add_argument('--removeoverlay', dest='rol', action='store_true', default=False,
                        help="Remove overlay data.")
    parser.add_argument('--extractoverlay', dest='eol', action='store_true', default=False,
                        help="Extract overlay data.")
    parser.add_argument('-r', '--resources', dest='resources', action='store_true', help="Display resource information")
    parser.add_argument('-R', '--rich', dest='rich', action='store_true', help="Display Rich Header information")
    parser.add_argument('-D', '--dump', nargs=1, dest='dump_offset',
                        help="Dump data using the passed offset or 'ALL'. Currently only works with resources.")
    parser.add_argument('-e', '--exports', dest='exports', action='store_true', help="Display exports")
    parser.add_argument('-a', '--analyze', dest='analyze', action='store_true', help="Analyze the file.")
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False, help="Display version.")
    parser.add_argument('-V', '--version', dest='version', action='store_true', help="Print version and exit.")
    parser.add_argument('--nobanner', dest='nobanner', action='store_true', help="Don't display the banner.")


    try:
        args = parser.parse_args()
    except:
        return -1

    # display banner
    if not args.nobanner:
        banner()

    if args.version:
        print('Version: %s' % __version__)
        return 0

    print('[*] Loading File...')
    targetfile = PFTriage(args.file, verbose=args.verbose)

    if args.analyze:
        print_analysis(targetfile)
        return

    if args.imports:
        print_imports(targetfile.listimports())
        return

    if args.exports:
        print_exports(targetfile.get_exports())
        return

    if args.sections:
        print_sections(targetfile, args.dump_offset)
        return

    if args.resources:
        print_resources(targetfile, args.dump_offset)
        return

    if args.rich:
        headers = targetfile.parse_rich_header()
        if not headers:
            print(' [!] Rich Header not found or corrupt')
            return
        print_rich_headers(headers)
        return

    # Remove Overlay
    if args.rol:
        remove_overlay(targetfile)
        return

    if args.eol:
        extract_overlay(targetfile)
        return

    # if no options are selected print the file details
    print('[*] Processing File details...')
    print('%s' % targetfile)
    print('[*] Loading Version Info')
    print_versioninfo(targetfile.getstringentries())

if __name__ == '__main__':
    main()
