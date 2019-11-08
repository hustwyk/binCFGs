#!/usr/bin/python3
import os
import sys
import re
import pdb

class Code(object):
    
    """
    Read the ASM FILE and extract the information of source FILE 
    Return a STRING of code block
    """
    def readfile(self):
        filepath = self.codefile
        filename = self.sourcefile
        codelist = []
        with open(filepath) as f:
            FIND = False
            linecount = 0
            for line in f:
                #print(line)
                if not FIND:
                    if(".file" in line) and (filename in line) and linecount > 0:
                        FIND = True
                    else:
                        FIND = False
                else:
                    if ".file" in line:
                        break
                    else:
                        codelist.append(line)
                linecount = linecount + 1
        return codelist

    """
    Get source code and asm code pair
    return a CODE EXECUTE LIST [[codeline, source code, asm code]]
    """
    def getpair(self, codelist):
        filename = self.sourcefile
        maplist = []
        sourcecode = ""
        asmcode = ""
        tmplist = []
        lineid = 1
        for codeline in codelist:
            if filename in codeline and '****' in codeline:
                if (asmcode != "") or (asmcode == "" and sourcecode != ""):
                    tmplist = []
                    tmplist.append(lineid)
                    tmplist.append(sourcecode)
                    tmplist.append(asmcode)
                    maplist.append(tmplist)
                    asmcode = ""
                    sourcecode = ""
                    tmplist = []
                tmp = codeline.strip().split(' ****')
                #print(sourcecode)
                if tmp[-1] == '':
                    continue
                else:
                    pass
                from Parser import Rules
                sourcecode = Rules('cpp', tmp[-1].replace('    ', '\t')).pcode
                lineid = int(tmp[0].split(':')[0])
                tmplist.append(lineid)
                tmplist.append(sourcecode)
            else:
                tmp = codeline.strip().split(' \t')[-1].strip()
                if (tmp.startswith('.') and tmp[:2]!='.L')  or tmp == '':
                    pass
                elif '\t' not in tmp:
                    pass
                else:
                    from Parser import Rules
                    tmp1 = Rules('asm', tmp).pcode
                    tmp2 = tmp1.replace(' \t ', ' ')
                    asmcode = asmcode + tmp2 + " ; "
        if asmcode != "":
            tmplist = []
            tmplist.append(lineid)
            tmplist.append(sourcecode)
            tmplist.append(asmcode)
            maplist.append(tmplist)
            asmcode = ""
            sourcecode = ""
            tmplist = []
        # for i in maplist:
        #     print(i)
        return maplist

    def __init__(self, filename):
        self.codefile = filename
        tmp = filename.split('/')[-1]
        self.sourcefile = tmp[:len(tmp)-1] + "cpp"
        self.codemap = self.getpair(self.readfile())

# x=Code("F:/Decompile/ast/testdata/testcode_wordSearch.s")
if __name__ == '__main__':
    fileName = sys.argv[1]
    x = Code(fileName)
    pdb.set_trace()

