#Changelog#


##0.1.1##

 - Remove option to run yara and peid during analysis.

##0.1.0##

 **Bug Fixes**
 
 - Fixed bug with invalid Charset identifier throwing index exception
 
 **New Features** 

 - Added import watchlist to analysis.

 **Changes**
 
 - Removed inline changelog and added CHANGELOG.md
 - Code cleanup
 - Added Travis CI integration

# Old Change History #

##8.08.2015##
 - Updated to use python-magic
 - Added setup.py
 - Added yara rule scan in analysis
 - Bug fixes
##6.07.2015## 
 - updates to analysis checks
##5.06.2015##
 - Added analysis option to analzye the file for common indicators of bad
 - removed -v switch for version info this will be output when printing file details
##3.02.2015##
 - Updated to use pefile lang/sublang lookups.
##2.11.2015##
 - Removed type lookup when printing resource names
 - Minor updates
##2.03.2015##
 - Updated resource output
##2.01.2015##
 - Added resources
 - Added option to extract resource data by passing rva_offset or 'ALL'
 - Updated section output
##1.22.2015##
 - Minor updates.
##1.21.2015##
 - Fixed output issue with VarOutputInfo
 - Moved VersionInfo from default output
##1.20.2015##
 - Fixed import issues and minor bugsThis inspection detects situations when dictionary creation could be rewritten with dictionary literal.
 - Added sha256 to default output
 - Updated Stringtable info
 - Fixed default display
##1.19.2015##
 - Initial Revision





