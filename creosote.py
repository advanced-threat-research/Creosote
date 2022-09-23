"""
Created on Jul 19 2022

@author: Kasimir Schulz (Abraxus7331)
"""

# imports
from base64 import encode
import sys, glob, ast, os

# global array of all analyzer objects where vulnerabilities were found
files_with_vulns = []

# prints out that the user did not specify a directory
def usage():
    print("python creosote.py <directory to scan> [file encoding]")

# helper function to print out a string prepended with tabs
def tabbed_print(msg, tabs=0):
    tabs = "\t" * tabs
    print(tabs + msg)

# recursively scan the directory for vulnerabilities
def scan(directory, encoding='utf8'):
    global files_with_vulns

    # print that we have started scanning
    tabbed_print("Scanning for Vulnerabilities:", 1)

    # loop through all files, use iglob to save memory
    for filename in glob.iglob(directory + "**" + os.sep + "*.py", recursive=True):

        # glob only uses "/", this breaks for windows so we need to replace with the os sep
        filename = filename.replace("/", os.sep)

        # open the file and try to read, sometimes fails due to illegal characters in the file
        with open(filename, "r", encoding=encoding) as f:
            try:
                text = f.read()

            # if it fails, catch the exception and print out the error message and filename
            except Exception as e:
                tabbed_print("Error reading file:" + filename, 2)
                tabbed_print(str(e), 3)
                continue

            # if tarfile is in the source code then analyze the source
            if "tarfile" in text:
                
                # create an analyzer for the file
                analyzer = Analyzer(filename, text) 

                # if there were any results, add the file to the list
                if analyzer.has_results():
                    files_with_vulns.append(analyzer)

    # give the user an update when the run is complete
    tabbed_print("Scan Completed", 2)


# Analyzer class
class Analyzer(ast.NodeVisitor):

    def __init__(self, filename, source):
        self.filename = filename
        self.vulns = []
        self.probable_vulns = []
        self.potential_vulns = []

        # try to parse the source code
        try:
            root = ast.parse(source)
        except:
            # if the above failed, it is most likely due to bad syntax in the file
            tabbed_print("ERROR: File contains errors", 2)
            return

        # walk through all the nodes and set the parent so that we have access later
        for node in ast.walk(root):
            for child in ast.iter_child_nodes(node):
                child.parent = node

        # start visiting the nodes
        self.visit(root)

    # check to see if there are any results
    def has_results(self):
        return (len(self.vulns) + len(self.probable_vulns) + len(self.potential_vulns)) != 0

    # visit an attribute node
    def visit_Attribute(self, node):

        # check if the node attribute is extractall
        if node.attr == "extractall":

            # if extractall is done right after a with (this is the most common scenario)
            if type(node.parent.parent.parent) == ast.With:
                with_node = node.parent.parent.parent

                # go through the with and check if open is called with the mode being set to r
                for item in with_node.items:
                    if item.context_expr and type(item.context_expr) == ast.Call and type(item.context_expr.func) == ast.Attribute \
                        and item.context_expr.func.attr == "open":
                        args = item.context_expr.args
                        keywords = item.context_expr.keywords

                        if len(args) > 1 and type(args[1]) == ast.Constant and "r" in args[1].value:
                            self.vulns.append(node.parent)
                        elif len(keywords) > 1:
                            check = False
                            for keyword in keywords:
                                if keyword.arg and keyword.arg == "mode" and type(keyword.value) == ast.Constant \
                                    and "r" in keyword.value.value:
                                    self.vulns.append(node.parent)
                                    check = True
                                    break
                            if not check:
                                self.potential_vulns.append(node.parent)
                        elif len(args) == 1:
                            self.vulns.append(node.parent)
                        else:
                            self.potential_vulns.append(node.parent)
            # otherwise just mark as a potential vuln. to add more conditions add an elif here with the new check
            else:
                self.potential_vulns.append(node.parent)

        # check if the node attribute is extract and that the function call does not have 0 arguments or keywords
        if node.attr == "extract" and type(node.parent) == ast.Call and node.parent.args and (len(node.parent.args) != 0 or len(node.parent.keywords) != 0):
            
            # if we have a for loop right before the extract looping over getmembers (most common scenario)
            if type(node.parent.parent.parent) == ast.For:
                for_node = node.parent.parent.parent
                if ".getmembers()" in ast.unparse(for_node.iter) and for_node.parent.body:
                    check = False

                    # check if we have an open with read
                    for item in for_node.parent.body:
                        unparsed = ast.unparse(item)
                        if "open" in unparsed:
                            if "\'r" in unparsed:
                                self.vulns.append(node.parent)
                                check = True
                                break
                            else:
                                self.probable_vulns.append(node.parent)
                                check = True
                                break
                    if not check:
                        self.potential_vulns.append(node.parent)
                else:
                    self.potential_vulns.append(node.parent)

            # otherwise just mark as a potential vuln. to add more conditions add an elif here with the new check
            else:
                self.potential_vulns.append(node.parent)
        # catch all, done just so that we do not miss anything
        elif node.attr == "extract":
            self.potential_vulns.append(node.parent)


    # used to print out data about the analysis
    def process(self, tabs=1):

        # print out the filename
        tabbed_print(self.filename, tabs)
        tabs += 1

        # if there were any vulns, print out the details
        if len(self.vulns) > 0:    
            tabbed_print("Found vulns on lines: " + ', '.join([str(i.lineno) for i in self.vulns]), tabs)

        # if there were any probable vulns, print out the details
        if len(self.probable_vulns) > 0:
            tabbed_print("Found probable vulns on lines: " + ', '.join([str(i.lineno) for i in self.probable_vulns]), tabs)

        # if there were any potential vulns, print out the details
        if len(self.potential_vulns) > 0:
            tabbed_print("Found potential vulns on lines: " + ', '.join([str(i.lineno) for i in self.potential_vulns]), tabs)


def main():

    print(""" ::::::::  :::::::::  :::::::::: ::::::::   ::::::::   :::::::: ::::::::::: :::::::::: 
:+:    :+: :+:    :+: :+:       :+:    :+: :+:    :+: :+:    :+:    :+:     :+:        
+:+        +:+    +:+ +:+       +:+    +:+ +:+        +:+    +:+    +:+     +:+        
+#+        +#++:++#:  +#++:++#  +#+    +:+ +#++:++#++ +#+    +:+    +#+     +#++:++#   
+#+        +#+    +#+ +#+       +#+    +#+        +#+ +#+    +#+    +#+     +#+        
#+#    #+# #+#    #+# #+#       #+#    #+# #+#    #+# #+#    #+#    #+#     #+#        
 ########  ###    ### ########## ########   ########   ########     ###     ########## 
 """)

    # if the user didn't specify a directory, print usage and exit
    if len(sys.argv) not in [2, 3]:
        usage()

    # grab the directory to scan
    directory = sys.argv[1]

    # if the last char isn't / or \, add it, this is needed for glob
    if directory[-1] != os.sep:
        directory += os.sep

    # give user an update
    tabbed_print("Starting scan of:" + directory)

    # scan the directory for vulnerabilities
    if len(sys.argv) == 3:
        scan(directory, sys.argv[2])
    else:
        scan(directory)

    # give the user a status report on findings
    if (len(files_with_vulns) > 0):

        # grab the total count for each confidence levels
        vuln_count = sum([len(i.vulns) for i in files_with_vulns])
        prob_count = sum([len(i.probable_vulns) for i in files_with_vulns])
        poten_count = sum([len(i.potential_vulns) for i in files_with_vulns])

        # print out overall summary
        tabbed_print("\n" + str(len(files_with_vulns)) + " files with vulns:\t" + str(vuln_count) + " vulns, " +
            str(prob_count) + " probable vulns, and " + str(poten_count) + " potential vulns found")

        # loop through all the files with vulnerabilities and print out info
        for f in files_with_vulns:
            f.process()

# call main
if __name__ == "__main__":
    main()