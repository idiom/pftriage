#!/usr/bin/env python

__description__ = 'Display info about a file.'
__author__ = 'Sean Wilson'
__version__ = '0.0.3'

"""
 --- History ---

  1.19.2015 - Initial Revision 
  1.20.2014 - Fixed import issues and minor bugs
            - Added sha256 to default output
            - Updated Stringtable info
            - Fixed default display
  

"""


import argparse 
import hashlib 
import os.path
from struct import * 
import time
import sys

try:
    import pefile
    import peutils
except Exception as e:
    print 'Error - Please ensure you install the pefile library %s ' % e
    sys.exit(-1)

class FileInfo:
    
    def __init__(self,tfile):   
        
        if not os.path.isfile(tfile):
            raise Exception('Error! File does not exist...')
            
        self.filename = tfile
        self.pe       = None
        self.filesize = os.path.getsize(self.filename)
        
        try:
            self.pe = pefile.PE(self.filename)
        except Exception as per:
            print 'Warning: %s' % per
        
    def gettype(self):
        try:
            import magic
        except Exception as e:
            return 'Error - Please ensure you install the magic library.'

        mdata = magic.open(magic.MAGIC_NONE)
        mdata.load()
        f = open(self.filename,'rb').read()
        return mdata.buffer(f) 
            
    def gethash(self, htype):       
        f = open(self.filename,'rb')
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
        if self.pe is not None:
            try:                
                for t in self.pe.FileInfo:
                    if t.name == 'VarFileInfo':
                        for vardata in t.Var:
                            for key in vardata.entry:
                                versioninfo[key] = vardata.entry[key]
                    elif t.name == 'StringFileInfo':
                        for vdata in t.StringTable:
                            for key in vdata.entries:
                                versioninfo[key] = vdata.entries[key]
                    else:
                        versioninfo['unknown'] = 'unknown'
            except AttributeError as ae:
                versioninfo['Error'] = ae
        else:
            versioninfo['Error'] = 'Not a PE file.'
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
        
        f = open(self.filename,'rb')
        fdat = f.read()
        f.close()
        return ssdeep.hash(fdat)
        
    def getbytes(self,start,length):
        f = open(self.filename,'rb')
        f.seek(start)
        dat = f.read(length)
        
        bstr = ''
        
        for c in dat:
            bstr += format(ord(c),'x') + ' '
        return bstr
        
    def __repr__(self):
        print self.pe.dump_info()
        print pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        #print hex(self.pe.FILE_HEADER.Characteristics)
        fobj = "\n\n"
        fobj += "---- File Summary ----\n"
        fobj += "\n"
        fobj += ' {:<16} {}\n'.format("Filename",self.filename)
        fobj += ' {:<16} {}\n'.format("Magic Type",self.gettype())
        fobj += ' {:<16} {}\n'.format("Size", self.filesize)
        fobj += ' {:<16} {}\n'.format("First Bytes",self.getbytes(0,16))
        fobj += ' {:<16} {}\n'.format("MD5",self.gethash('md5'))
        fobj += ' {:<16} {}\n'.format("SHA1",self.gethash('sha1'))
        fobj += ' {:<16} {}\n'.format("SHA256",self.gethash('sha256'))
        fobj += ' {:<16} {}\n'.format("Import Hash",self.getimphash())
        fobj += ' {:<16} {}\n'.format("ssdeep",self.getfuzzyhash())
        if self.pe is not None:
            fobj += ' {:<16} {}\n'.format("Packed",peutils.is_probably_packed(self.pe))

            hinfo = self.getheaderinfo()
            for str_key in hinfo:
                fobj += ' {:<16} {}\n'.format(str_key,hinfo[str_key])
            flags = pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
            
            fobj += ' {:<16} '.format("Flags")
            for flag in flags:
                fobj += flag[0] + ' ' 
            
            fobj += "\n\n---- Version Info ----  \n\n"
            versioninfo = self.getstringentries()
            for str_entry in versioninfo:
                fobj += ' {:<16} {}\n'.format(str_entry,versioninfo[str_entry])
        return fobj
        

def print_imports(modules):
    print " ---- Imports ----  "
    imports = None
    print ' Number of imported modules: %s \n ' % len(modules)
    for str_entry in modules:
        print '\n %s ' % str_entry
        imports = modules[str_entry]
        for symbol in imports:
            if symbol.import_by_ordinal is True:
                if symbol.name is not None:
                    print '  |-- %s Ordinal[%s] (Imported by Ordinal)' % (symbol.name, str(symbol.ordinal))
                else:
                    print '  |-- Ordinal[%s] (Imported by Ordinal)' % (str(symbol.ordinal))
            else:
                print '  |-- %s' % symbol.name
    print '\n\n'

def print_sections(sections):
    sdata = "\n ---- Sections ----  \n"
    for section in sections:
        sdata += ' {:<16} {}\n'.format('Name:',section.Name)
        sdata += ' {:<16} {}\n'.format('VirtualAddress:',hex(section.VirtualAddress))
        sdata += ' {:<16} {}\n'.format('SizeOfRawData:',section.SizeOfRawData)
        sdata += ' {:<16} {}\n'.format('MD5:',hashlib.md5(section.get_data()).hexdigest())
        sdata += '\n\n'
        
    print sdata
 
def main():
    parser = argparse.ArgumentParser(description="Show information about a file.")
    parser.add_argument("file", help="The target file+.")    
    parser.add_argument('-i','--imports',dest='imports',action='store_true',help="Display import tree")  
    parser.add_argument('-s','--sections',dest='sections',action='store_true',help="Display section information")  
    
    args = parser.parse_args()
    
    q = FileInfo(args.file)
    
    #print file metadata
    print q
    
    if args.imports:
        print_imports(q.listimports())
    
    if args.sections:
        print_sections(q.pe.sections)
    

if __name__ == '__main__':

    main()

