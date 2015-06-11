# pftriage

pftriage is a tool to help analyze files during malware triage. It allows an analyst to quickly 
view and extract properties of a file to help during the triage process. The tool also has an
analyze function which can detect common malicious indicators used by malware.

Dependencies
-----

 * pefile >= 1.2.10-139 - https://code.google.com/p/pefile/ 
 

Usage
-----

pftriage.py [-h] [-i] [-s] file

Show information about a file.  
  
positional arguments:  
  file            The target file.  
  
optional arguments:
-h, --help            Show this help message and exit  
-i, --imports         Display import tree  
-a, --analyze         Analyze the file for common malware indicators  
-s, --sections        Display section information  
-r, --resources       Display resource information   
-D DUMP_OFFSET, --Dump DUMP_OFFSET   
                        Dump data using the passed offset or 'ALL'.   
                        Currently only works with resources.  
                        
 
 
 
  
