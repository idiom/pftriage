#!/usr/bin/env python

__description__ = 'Display info about a file.'
__author__ = 'Sean Wilson'
__version__ = '0.0.2'

"""
 --- History ---

  1.19.2015 - Initial Revision 
  1.20.2014 - Fixed import issues and minor bugs
            - Added sha256 to default output
  

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
        if self.pe is not None:
            try:
                return self.pe.FileInfo[1].StringTable[0].entries.items()
            except AttributeError as ae:
                return[('Error','StringTable not found...')]
        else:
            return 'Skipped...'
            
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
        fobj = "\n\n"
        fobj += "---- File Summary ----\n"
        fobj += "\n"
        fobj += " Filename:    %s  \n" % self.filename
        fobj += " Magic Type:  %s  \n" % self.gettype()
        fobj += " Size:        %s  \n" % self.filesize
        fobj += " First Bytes: %s  \n" % self.getbytes(0,16)
        fobj += " MD5:         %s  \n" % self.gethash('md5')
        fobj += " SHA1:        %s  \n" % self.gethash('sha1')
        fobj += " SHA256:        %s  \n" % self.gethash('sha256')
        fobj += " Import Hash: %s  \n" % self.getimphash()
        fobj += " ssdeep:      %s  \n" % self.getfuzzyhash()
        if self.pe is not None:
            fobj += " Packed:      %s  \n" % peutils.is_probably_packed(self.pe)

            hinfo = self.getheaderinfo()
            for str_key in hinfo:
                fobj += " %s: %s \n" %(str_key,hinfo[str_key])
            fobj += "\n ---- Assembly Info ----  \n\n"
            for str_entry in self.getstringentries():
                fobj += "  %s: %s \n" %(str_entry[0],str_entry[1])
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
        sdata += ' Name:            %s \n' % section.Name
        sdata += ' VirtualAddress:  %s \n' % hex(section.VirtualAddress)
        sdata += ' SizeOfRawData:   %s \n' % section.SizeOfRawData
        sdata += ' MD5:             %s \n' % hashlib.md5(section.get_data()).hexdigest()
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

