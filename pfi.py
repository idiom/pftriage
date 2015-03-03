#!/usr/bin/env python

__description__ = 'Display info about a file.'
__author__ = 'Sean Wilson'
__version__ = '0.0.7'

"""
 --- History ---

  1.19.2015 - Initial Revision 
  1.20.2015 - Fixed import issues and minor bugs
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


"""


import argparse 
import hashlib 
import os.path
from struct import * 
import time
import sys
import zlib

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
    
class FileInfo:
        
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

    
    def __init__(self, tfile):
        
        if not os.path.isfile(tfile):
            raise Exception('Error! File does not exist...')
            
        self.filename = tfile
        self.pe       = None
        self.filesize = os.path.getsize(self.filename)
        
        try:
            self.pe = pefile.PE(self.filename)
        except Exception as per:
            print 'Warning: %s' % per

    def getfiletype(self, data):

        try:
            mdata = magic.open(magic.MAGIC_NONE)
            mdata.load()
            magictype = mdata.buffer(data)
        except NameError:
            magictype = 'Error - python-magic library required.'
        except Exception:
            magictype = 'Error - processing file.'
        return magictype
            
    def gethash(self, htype):       

        f = open(self.filename, 'rb')
        fdat = f.read()
        f.close()

        if htype == 'md5':
            m = hashlib.md5() 
        elif htype == 'sha1':
            m = hashlib.sha1() 
        elif htype == 'sha256':
            m = hashlib.sha256() 
        m.update(fdat)
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
        if self.pe is not None:
            for module in self.pe.DIRECTORY_ENTRY_IMPORT:
                modules[module.dll] = module.imports
        return modules
                        
                        
    def getheaderinfo(self):
        info = {}
        info['Sections'] = self.pe.FILE_HEADER.NumberOfSections
        info['TimeStamp'] = '%s UTC' % time.asctime(time.gmtime(self.pe.FILE_HEADER.TimeDateStamp))
        info['Signature'] = hex(self.pe.NT_HEADERS.Signature)
    
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
        
    def getbytes(self, start, length):
        f = open(self.filename, 'rb')
        f.seek(start)
        dat = f.read(length)
        
        bstr = ''
        
        for c in dat:
            bstr += format(ord(c), 'x') + ' '
        return bstr
        
    def __repr__(self):        
        fobj = "\n\n"
        fobj += "---- File Summary ----\n"
        fobj += "\n"
        fobj += ' {:<16} {}\n'.format("Filename", self.filename)
        if self.pe is None:
            data = open(self.filename, 'rb').read()
            fobj += ' {:<16} {}\n'.format("Magic Type", self.getfiletype(data))
        else:
            fobj += ' {:<16} {}\n'.format("Magic Type", self.getfiletype(self.pe))
        fobj += ' {:<16} {}\n'.format("Size", self.filesize)
        fobj += ' {:<16} {}\n'.format("First Bytes", self.getbytes(0, 16))
        fobj += ' {:<16} {}\n'.format("MD5", self.gethash('md5'))
        fobj += ' {:<16} {}\n'.format("SHA1", self.gethash('sha1'))
        fobj += ' {:<16} {}\n'.format("SHA256", self.gethash('sha256'))
        fobj += ' {:<16} {}\n'.format("Import Hash", self.getimphash())
        fobj += ' {:<16} {}\n'.format("ssdeep", self.getfuzzyhash())
        if self.pe is not None:
            fobj += ' {:<16} {}\n'.format("Packed", peutils.is_probably_packed(self.pe))

            hinfo = self.getheaderinfo()
            for str_key in hinfo:
                fobj += ' {:<16} {}\n'.format(str_key, hinfo[str_key])
            iflags = pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
            flags = []
            fobj += ' {:<16} \n'.format("Characteristics")
            for flag in iflags:
                if getattr(self.pe.FILE_HEADER, flag[0]):
                    fobj += " {:<16s} {:<20s}\n".format("", str(flag[0]))
                                
        return fobj

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
    print "\n---- Version Info ----  \n\n"            
    if 'StringInfo' in versioninfo:        
        sinfo = versioninfo['StringInfo']
        for str_entry in sinfo:                
            print ' {:<16} {}'.format(str_entry,sinfo[str_entry].encode('utf-8'))
    if 'VarInfo' in versioninfo:      
        print ''
        vinfo = versioninfo['VarInfo']
        for str_entry in vinfo:
            if str_entry == 'LangID':
                print ' {:<16} {} ({})'.format('LangID',FileInfo.langID[int(vinfo[str_entry],16)], vinfo[str_entry].encode('utf-8'))
            elif str_entry == 'charsetID':
                print ' {:<16} {} ({})'.format('charsetID',FileInfo.charsetID[int(vinfo[str_entry])], vinfo[str_entry].encode('utf-8'))
            else:
                print ' {:<16} {}'.format(str_entry,vinfo[str_entry].encode('utf-8'))
    print ''
    

def print_resources(finfo, dumprva):
    try:
        dumpaddress = dumprva[0]
    except:
        dumpaddress = 0
    
    data = "\n ---- Resources ----  \n\n"
    
    try:
        resdir = finfo.pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        data += 'Resources not found...\n'
        print data
        return
        
    for entry in resdir.entries:
        dat = entry.struct 
        rname = ''

        if entry.id is not None:
            rname = FileInfo.resource_type[entry.id]
        else:
            # Identified by name
            rname = str(entry.name)

        data += ' Type: %s\n' % rname
        if hasattr(entry, 'directory'):
            data += "  {:16}{:16}{:20}{:12}{:12}{:64}\n".format("Name",
                                                                "Language",
                                                                "SubLang",
                                                                "Offset",
                                                                "Size",
                                                                "File Type")

            for resname in entry.directory.entries:
                if resname.id is not None:
                    data += '  {:<16}'.format(hex(resname.id))
                else:
                    data += '  {:<16}'.format(resname.name)
                for entry in resname.directory.entries:
                    if hasattr(entry, 'data'):
                        offset = '{0:#0{1}x}'.format(entry.data.struct.OffsetToData, 10)
                        data += '{:16}'.format(pefile.LANG[entry.data.lang])
                        data += '{:20}'.format(pefile.get_sublang_name_for_lang(entry.data.lang, entry.data.sublang).replace('SUBLANG_', ''))
                        data += '{:12}'.format(offset)
                        data += '{:12}'.format("{0:#0{1}x}".format(entry.data.struct.Size, 10))
                        data += '{:64}'.format(finfo.getfiletype(finfo.extractdata(entry.data.struct.OffsetToData, entry.data.struct.Size)[:64]))
                        
                        if dumpaddress == 'ALL' or dumpaddress == offset:
                            data += '\n\n  Matched offset[%s] -- dumping resource' % dumpaddress
                            tmpdata = finfo.extractdata(entry.data.struct.OffsetToData, entry.data.struct.Size)
                            filename = 'export-%s.bin' % offset
                            f = open(filename, 'wb')
                            f.write(tmpdata)
                            f.close()
                data += '\n'
            data += '\n'
    print data

        

def print_sections(sections):
    sdata = "\n ---- Section Info ----  \n\n"
    sdata += " {:10}{:20}{:20}{:20}{:20}\n".format("Name",
                                                        "Virtual Address",
                                                        "Virtual Size",
                                                        "Entropy",
                                                        "Hash")
    
    for section in sections:
        sdata += " {:10}".format(section.Name.strip('\0'))
        sdata += "{:20}".format("{0:#0{1}x}".format(section.VirtualAddress, 10))
        sdata += "{:20}".format("{0:#0{1}x}".format(section.Misc_VirtualSize, 10))
        sdata += "{:<20}".format(section.get_entropy())
        sdata += "{:<20}".format(hashlib.md5(section.get_data()).hexdigest())
        sdata += "\n"        
    print sdata
 
def main():
    parser = argparse.ArgumentParser(description="Show information about a file.")
    parser.add_argument("file", help="The target file+.")    
    parser.add_argument('-i', '--imports', dest='imports', action='store_true', help="Display import tree")
    parser.add_argument('-s', '--sections', dest='sections', action='store_true', help="Display section information")
    parser.add_argument('-v', '--versioninfo', dest='version', action='store_true', help="Display section information")
    parser.add_argument('-r', '--resources', dest='resources', action='store_true', help="Display resource information")
    parser.add_argument('-D', '--Dump', nargs=1, dest='dump_offset', help="Dump data using the passed offset or 'ALL'. \
    \nCurrently only works with resources.")

    args = parser.parse_args()
    print '[*] Loading File...'
    q = FileInfo(args.file)
    
    if not args.version and not args.imports and not args.sections and not args.resources:
        # print file metadata
        print '[*] Processing File details...'
        print q
    
    if args.version:
        print '[*] Loading Version Info'
        print_versioninfo(q.getstringentries())
    
    if args.imports:
        print_imports(q.listimports())
    
    if args.sections:
        print_sections(q.pe.sections)
        
    if args.resources:
        print_resources(q, args.dump_offset)
    

if __name__ == '__main__':
    main()

