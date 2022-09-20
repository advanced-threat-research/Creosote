# Creosote

Creosote is our solution to searching for the tarfile vulnerability described by CVE-2007-4559. The tool recursively traverses the given directory searching for python files. When the tool finds python files it scans them for the tarfile module and then parses the code into an AST to look for vulnerable code. 

Creosote categorizes all found vulnerabilities under 3 main categories:

- Vuln: 
    - This is the highest confidence level the tool can give, anything marked as a vuln should be analyzed.
- Probable Vuln
    - Anything marked as probably vulnerable had the structure of a vuln but had some sort of indication of potentially being checked by the program. 
- Potential Vuln
    - This is a catch all to make sure nothing gets missed.

In order to run Creosote you just need to pass it the directory:

```
python3 creosote.py <directory to scan>
```

Creosote runs on both Linux, macOS, and Windows. The tool has been tested for Python 3.9 and later. 