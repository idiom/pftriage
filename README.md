# pfi
Python File Info - Tool to gather information on PE and other files. 

Dependencies
-----

 * pefile >= 1.2.10-139 - https://code.google.com/p/pefile/ 
 

Usage
-----

pfi.py [-h] [-i] [-s] file

Show information about a file.  
  
positional arguments:  
  file            The target file.  
  
optional arguments: 
  -h, --help            show this help message and exit 
  -i, --imports         Display import tree 
  -s, --sections        Display section information 
  -v, --versioninfo     Display section information 
  -r, --resources       Display resource information 
  -D DUMP_OFFSET, --Dump DUMP_OFFSET 
                        Dump data using the passed offset or 'ALL'. 
                        Currently only works with resources.

  

