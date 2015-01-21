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
  file            The target file+.

optional arguments:
  -h, --help      show this help message and exit
  -i, --imports   Display import tree
  -s, --sections  Display section information
  

