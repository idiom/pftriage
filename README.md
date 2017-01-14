# pftriage  [![Build Status](https://travis-ci.org/idiom/pftriage.svg?branch=master)](https://travis-ci.org/idiom/pftriage)

pftriage is a tool to help analyze files during malware triage. It allows an analyst to quickly 
view and extract properties of a file to help during the triage process. The tool also has an
analyze function which can detect common malicious indicators used by malware.

Dependencies
-----

 * pefile >= 1.2.10-139 - https://github.com/erocarrera/pefile
 * python-magic - https://pypi.python.org/pypi/python-magic/
 
Install 
-----

If you want to install the script run 'python setup.py install' 

Usage
-----
```
Usage: pftriage [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  analyze    Perform a basic analysis on the file
  imports    Display library imports
  metadata   Display file metadata
  resources  Display file resource data
  sections   Display section information about the file

 ```




 
 
  
