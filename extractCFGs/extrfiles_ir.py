import io
import os
import re
import pdb
import sys
import angr
import json
from ruamel import yaml
from optparse import OptionParser
from elftools.elf.elffile import ELFFile
from utils.listdir import list_all_files

def get_funcs(file_path):
    f = open(file_path, 'rb')
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.symtab')
    funcnames = []

    for i in range(symtab.num_symbols()):
        if(symtab.get_symbol(i).entry.st_info.type == 'STT_FUNC'):
            name = symtab.get_symbol(i).name
            if name == "main" or name.startswith("Function"):
                funcnames.append(symtab.get_symbol(i).name)
    f.close()
    return funcnames

def get_proj_all_path(file_path, functions_list):
    proj = angr.Project(file_path, load_options={'auto_load_libs':False})
    cfg_dict = {}
    for function in functions_list:
        # print("func: " + function)
        function_obj = proj.loader.main_object.get_symbol(function)
        start_state = proj.factory.blank_state(addr=function_obj.rebased_addr)
        cfg = proj.analyses.CFGEmulated(keep_state=True,
                                        starts=(function_obj.rebased_addr,),
                                        initial_state=start_state,
                                        call_depth=0)
        cfg = cfg.get_function_subgraph(start=function_obj.rebased_addr, max_call_depth=0)
        cfg_dict[function] = cfg
    return cfg_dict

def get_graph(binfile, functions, quietOp, printOp, saveOp, outputPath):
    CFGs = get_proj_all_path(binfile, functions)
    dict_func_graph = {} # key: 'func_name' -> $(func_nodes_edges)

    objdump = Resol_objdump(binfile)
    binStruc = CFG_Bin_Custom(os.path.split(binfile)[-1])

    for function in CFGs:
        objdump.struc_func(objdump.all_functions[function])
        funcStruc = CFG_Func_Custom(function, objdump.funcMap.address, objdump.funcMap.ccode)
        nodes = CFGs[function].graph.nodes()
        edges = CFGs[function].graph.out_edges()
        # pdb.set_trace()
        dict_graph_nodes = {} # keys: 'nodes' -> $(list_nodes), 'edges' -> $(list_edges)
        dict_nodes_node = {} # key: 'nodename' -> $(nodeInfo)
        for node in nodes:
            # pdb.set_trace()
            node_id = node.addr
            # print(hex(node_id))
            node_pre = node.predecessors
            # print(node_pre)
            node_suc = node.successors
            # print(node_suc)
            # print(type(node))
            if node.block:
                instrs = str(node.block.vex) # TODO: get instrustions
                # extracted_addrs = extract_addrs(instrs)
                # blockCcode = objdump.funcMap.getCcodeFromAddrRange(extracted_addrs[0], extracted_addrs[-1])
                # print(blockCcode)
            else:
                instrs = ""
            if len(instrs):
                nodeStruc = CFG_Node_Custom(node_id, node_pre, node_suc, instrs)
                funcStruc.addNode(nodeStruc)
        list_edges = []
        for edge in edges:
            #pdb.set_trace()
            list_edges.append((edge[0].name, edge[1].name))
        binStruc.addFunc(funcStruc)

        dict_graph_nodes['edges'] = list_edges
        dict_graph_nodes['nodes'] = dict_nodes_node
        dict_func_graph[function] = dict_graph_nodes
    # pdb.set_trace()
    if quietOp:
        if printOp:
            binStruc.printa()
        else:
            binStruc.printc()
    if saveOp:
        binStruc.generate_yaml_file(outputPath)
    # pdb.set_trace()
    return dict_func_graph

class Resol_objdump:
    def __init__(self, file_path):
        self.orig_objdump = self.get_objdump(file_path)
        self.all_functions = self.get_all_func(self.orig_objdump)  # self.all_functions -> dict
        self.funcMap = FuncMapping()

    def get_objdump(self, file_path):
        return os.popen("objdump -j .text -S --no-show-raw-insn -M intel %s"%(file_path)).read()

    def get_all_func(self, objfile_text):
        functions = {}  # key:value  ->  funcName:funcBody
        tmp_funcName = ''
        tmp_function = ''
        in_func = 0  # Is in the function
        objfile_text_buf = io.StringIO(objfile_text)
        nextLine = objfile_text_buf.readline()
        while 1:
            line = nextLine
            if not line:
                if len(tmp_funcName) and len(tmp_function):
                    functions[tmp_funcName] = tmp_function
                break
            nextLine = objfile_text_buf.readline()
            if not in_func:
                tmp_funcName = ''
                tmp_function = ''
                matchObj = re.match(r'[0-9a-f]+ <.+>:', line, re.M|re.I)
                if matchObj and not in_func:
                    in_func = 1
                    tmp_funcName = re.findall(r'[0-9a-f]+ <(.+)>:', line)[0]
                    continue
            if in_func:
                if not line == '\n':
                    tmp_function += line
                else:
                    matchObj = re.match(r'[0-9a-f]+ <.+>:', nextLine, re.M|re.I)
                    if matchObj:
                        in_func = 0
                        functions[tmp_funcName] = tmp_function
                    else:
                        tmp_function += line
        return functions

    def struc_func(self, funcBody):  # funcBody -> str
        self.funcMap.clean()
        funcBody_buf = io.StringIO(funcBody)
        nextLine = funcBody_buf.readline()
        tmpCcode = ''
        tmpCcodeOrder = 0
        while 1:
            line = nextLine
            if not line:
                break
            nextLine = funcBody_buf.readline()
            strip_line = line.strip()
            strip_nextLine = nextLine.strip()
            matchObj = re.match(r'[0-9a-f]+:', strip_line, re.M|re.I)
            if matchObj:
                tmpAddr = re.findall(r'([0-9a-f]+):', strip_line)[0]
                self.funcMap.address[tmpAddr] = tmpCcodeOrder
                matchNextObj = re.match(r'[0-9a-f]+:', strip_nextLine, re.M|re.I)
                if not matchNextObj:
                    tmpCcode = ''
                    tmpCcodeOrder += 1
            else:
                tmpCcode += line
                matchNextObj = re.match(r'[0-9a-f]+:', strip_nextLine, re.M|re.I)
                if matchNextObj:
                    self.funcMap.ccode[tmpCcodeOrder] = tmpCcode
        # pdb.set_trace()

class FuncMapping:
    def __init__(self):
        self.ccode = {}  # key:value  ->  ccode_order:ccode_str
        self.address = {}  # key:value  ->  addr:ccode_order

    def getCcodeFromAddrRange(self, beginAddr, endAddr):  # beginAddr, endAddr -> str
        tmpCcode = ''
        tmpCcodeOrder = []
        if beginAddr in self.address.keys() and endAddr in self.address.keys():
            for addr in range(int(beginAddr, 16), int(endAddr, 16) + 1):
                if hex(addr)[2:] in self.address.keys():
                    tmpOrder = self.address[hex(addr)[2:]]
                    if tmpOrder not in tmpCcodeOrder:
                        tmpCcodeOrder.append(tmpOrder)
                        #pdb.set_trace()
                        tmpCcode += self.ccode[tmpOrder]
            return tmpCcode
        else:
            return 0

    def clean(self):
        self.ccode = {}
        self.address = {}

class CFG_Node_Custom:
    def __init__(self, node_id, node_pre=[], node_suc=[], node_asm_body=''):
        self.node_id = node_id
        self.node_pre = self.trans2NodeId(node_pre)
        self.node_suc = self.trans2NodeId(node_suc)
        self.node_asm_body = node_asm_body
        self.node_c_body = ''
        self.extracted_addrs = self.extract_addrs()

    def extract_addrs(self):
        baseAddr = 0x400000
        asm_block_buf = io.StringIO(self.node_asm_body)
        extracted_addrs = []
        while 1:
            line = asm_block_buf.readline()
            if not line:
                break
            tmp_addr = re.findall(r'IMark\((0x[0-9a-fA-F]+)', line)
            if tmp_addr:
                extracted_addrs.append(hex(int(tmp_addr[0], 16) - baseAddr)[2:])
        return extracted_addrs

    def trans2NodeId(self, node_list):
        node_id_list = []
        for node in node_list:
            node_str = str(node)
            node_id_list.append(re.findall(r'(0x[0-9a-f]+)[>\[]', node_str)[0])
        return node_id_list
    
    def trans2Dic(self):
        node_dict = {}
        node_dict['node_id'] = self.node_id
        node_dict['node_pre'] = self.node_pre
        node_dict['node_suc'] = self.node_suc
        node_dict['node_asm_body'] = self.node_asm_body
        node_dict['node_c_body'] = self.node_c_body
        node_dict['extracted_addrs'] = self.extracted_addrs
        return node_dict

    def loadFromDic(self, node_dict):
        self.node_id = node_dict['node_id']
        self.node_pre = node_dict['node_pre']
        self.node_suc = node_dict['node_suc']
        self.node_asm_body = node_dict['node_asm_body']
        self.node_c_body = node_dict['node_c_body']
        self.extracted_addrs = node_dict['extracted_addrs']

class CFG_Func_Custom:
    def __init__(self, funcName, funcMap_address={}, funcMap_ccode={}):
        self.cfg_nodes = []
        self.funcName = funcName
        self.funcMap = FuncMapping()
        self.funcMap.ccode = funcMap_ccode
        self.funcMap.address = funcMap_address

    def addNode(self, node):
        self.cfg_nodes.append(self.transAsm2C(node))
    
    def transAsm2C(self, node):
        if len(node.extracted_addrs):
            tmpCcode = self.funcMap.getCcodeFromAddrRange(node.extracted_addrs[0], node.extracted_addrs[-1])
            if tmpCcode:
                node.node_c_body = tmpCcode
            else:
                node.node_c_body = 'NULL\n'
        else:
            node.node_c_body = 'NULL\n'
        return node

    def printc(self):
        print('#### FUNCTION: %s\n'%(self.funcName))
        for node in self.cfg_nodes:
            print(hex(node.node_id))
            print(node.node_pre)
            print(node.node_suc)
            print(node.node_c_body)

    def printa(self):
        print('#### FUNCTION: %s\n'%(self.funcName))
        for node in self.cfg_nodes:
            print(hex(node.node_id))
            print(node.node_pre)
            print(node.node_suc)
            print(node.node_asm_body)
            print('')

    def trans2Dic(self):
        cfg_nodes_dict = {}
        for cfgNode in self.cfg_nodes:
            cfg_nodes_dict[cfgNode.node_id] = cfgNode.trans2Dic()
        func_dict = {}
        func_dict['funcName'] = self.funcName
        func_dict['cfg_nodes'] = cfg_nodes_dict
        func_dict['funcMap_ccode'] = self.funcMap.ccode
        func_dict['funcMap_address'] = self.funcMap.address
        return func_dict
        
    def loadFromDic(self, func_dict):
        self.funcMap.ccode = func_dict['funcMap_ccode']
        self.funcMap.address = func_dict['funcMap_address']
        cfg_nodes_dict = func_dict['cfg_nodes']
        for node_id in cfg_nodes_dict.keys():
            cfg_node = CFG_Node_Custom(node_id)
            cfg_node.loadFromDic(cfg_nodes_dict[node_id])
            self.cfg_nodes.append(cfg_node)

class CFG_Bin_Custom:
    def __init__(self, binName=''):
        self.binName = binName
        self.cfg_funcs = []

    def addFunc(self, function):
        self.cfg_funcs.append(function)

    def printc(self):
        print('###### BIN: %s'%(self.binName))
        for func in self.cfg_funcs:
            func.printc()

    def printa(self):
        print('###### BIN: %s'%(self.binName))
        for func in self.cfg_funcs:
            func.printa()

    def generate_yaml_file(self, outputPath):
        cfg_funcs_dict = {}
        for cfg_func in self.cfg_funcs:
            cfg_funcs_dict[cfg_func.funcName] = cfg_func.trans2Dic()
        bin_dic = {}
        bin_dic['binName'] = self.binName
        bin_dic['cfg_funcs'] = cfg_funcs_dict
        with open(outputPath, 'w', encoding='utf-8') as yamlFile:
            yaml.dump(bin_dic, yamlFile, Dumper=yaml.RoundTripDumper)

    def load_yaml_file(self, yamlFile):
        with open(yamlFile, 'r', encoding='utf-8') as importFile:
            bin_dic = yaml.load(importFile.read(), Loader=yaml.Loader)
            self.binName = bin_dic['binName']
            cfg_funcs_dict = bin_dic['cfg_funcs']
            for funcName in cfg_funcs_dict.keys():
                cfg_func = CFG_Func_Custom(funcName)
                cfg_func.loadFromDic(cfg_funcs_dict[funcName])
                self.cfg_funcs.append(cfg_func)

def optionParse():
    parser = OptionParser()
    parser.add_option('-f', '--file', dest='filename', help='Specify the file to extract the CFG.', metavar='FILE')
    parser.add_option('-c', '--clanguage', action='store_true', dest='clanguage', default=False, help='Change the default language \
                        from assembly to c-language')
    parser.add_option('-s', '--save', action='store_true', dest='save', default=False, help='Save the CFG info a yaml file, \
                        default file name is ${BIN_NAME}.yaml, default path is current path. -o can change output \
                        path and file name, and -O can change output directory.')
    parser.add_option('-o', '--output', dest='output', help='Specify the output yaml file name and saving path. \
                        When using -o, -s can be omitted.')
    parser.add_option('-O', '--outputdirectory', dest='outputdirectory', help='Specify the output yaml file saving \
                        path, yaml file name will be ${BIN_NAME}.yaml. When using -O, -s can be omitted.')
    parser.add_option('-d', '--directory', dest='directory', help='Choose the target directory containing the target \
                        binary files.')
    parser.add_option('-q', '--quiet', action='store_false', dest='quiet', default=True, help='Make the script running silently.')
    (options, args) = parser.parse_args()
    #pdb.set_trace()
    if (options.filename and options.directory):
        print('Error: You can only specify -f or -d, not both.')
        sys.exit()
    if (options.output and options.outputdirectory):
        print('Error: You can only specify -o or -O, not both.')
        sys.exit()
    if options.filename:
        if not os.path.exists(options.filename):
            print('Error: The specify file is not exists.')
            sys.exit()
        elif not os.path.isfile(options.filename):
                print('Error: The specify object is not a file.')
                sys.exit()
        else:
            func_list = get_funcs(options.filename)
            fileName = os.path.split(options.filename)[-1]
            outputPath = ''
            saveOp = 0
            if options.output:
                saveOp = 1
                if os.path.exists(options.output):
                    os.remove(options.output)
                else:
                    yamlName = os.path.split(options.output)[-1]
                    yamlPath = os.path.split(options.output)[0]
                    if not os.path.exists(yamlPath):
                        os.makedirs(yamlPath)
                outputPath = options.output
            elif options.outputdirectory:
                saveOp = 1
                if os.path.isfile(options.outputdirectory):
                    print('Error: The specify object is not a directory.')
                    sys.exit()
                else:
                    if not os.path.exists(options.outputdirectory):
                        os.makedirs(options.outputdirectory)
                    tmpYamlName = os.path.splitext(fileName)[0] + '.yaml'
                    outputPath = os.path.join(options.outputdirectory, tmpYamlName)
            elif (not options.output) and (not options.outputdirectory) and options.save:
                saveOp = 1
                outputPath = os.path.splitext(fileName)[0] + '.yaml'
            if options.quiet:
                if options.clanguage:
                    dict_func_graph = get_graph(options.filename, func_list, 1, 0, saveOp, outputPath)
                else:
                    dict_func_graph = get_graph(options.filename, func_list, 1, 1, saveOp, outputPath)
            else:
                dict_func_graph = get_graph(options.filename, func_list, 0, 0, saveOp, outputPath)
            sys.exit()
    if options.directory:
        print('Error: This feature is not implemented in this script.')
        pass # TODO:parallel

if __name__ == "__main__":
    # binCustom = CFG_Bin_Custom()
    # binCustom.load_yaml_file('export_file.yaml')
    # binCustom.printa()

    optionParse()

    # files = list_all_files(sys.argv[1])
    # for filename in files:
    #     # dict_file_func = {}
    #     func_list = get_funcs(filename)
    #     dict_func_graph = get_graph(filename, func_list)
    #     # # print(dict_func_graph)
    #     # basename = os.path.basename(filename)
    #     # dict_file_func[basename] = dict_func_graph # key:'filename'->$(dict_func_graph)
        
    #     #print(get_objdump(filename))
    #     # objdump = Resol_objdump(filename)
    #     # objdump.struc_func(objdump.all_functions['main'])
    #     #print(objdump.orig_objdump)

