import os
import angr
from elftools.elf.elffile import ELFFile
from utils.listdir import list_all_files
from .resol_objdump import Resol_objdump
from .cfg_bin_custom import CFG_Bin_Custom
from .cfg_func_custom import CFG_Func_Custom
from .cfg_node_custom import CFG_Node_Custom

class Bin_CFG_Graph:
    def __init__(self, file_path):
        self.file_path = file_path
        self.func_list = self.get_funcs()
        self.cfg_dict = self.get_proj_all_path()

    def get_funcs(self):
        """
        Get the functions of the ELF file.
        The function extracted is 'main' or startswith 'Function'.
        
        Returns:
            list -- a list of funcnames extracted
        """
        with open(self.file_path, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            funcnames = []
            for i in range(symtab.num_symbols()):
                if(symtab.get_symbol(i).entry.st_info.type == 'STT_FUNC'):
                    name = symtab.get_symbol(i).name
                    if name == "main" or name.startswith("Function"):
                        funcnames.append(symtab.get_symbol(i).name)
        return funcnames

    def get_proj_all_path(self):

        """
        Get all CFG subgraphs of each function in the func_list.
        The subgraph is a file of CFGEmulated type.
        
        Returns:
            dict -- a dict contains of each function name and the subgraph accordingly.
                    key:value => function_name:cfg_subgraph
        """
        proj = angr.Project(self.file_path, load_options={'auto_load_libs':False})
        cfg_dict = {}
        for function in self.func_list:
            function_obj = proj.loader.main_object.get_symbol(function)
            start_state = proj.factory.blank_state(addr=function_obj.rebased_addr)
            cfg = proj.analyses.CFGEmulated(keep_state=True,
                                            starts=(function_obj.rebased_addr,),
                                            initial_state=start_state,
                                            call_depth=0)
            cfg = cfg.get_function_subgraph(start=function_obj.rebased_addr, max_call_depth=0)
            cfg_dict[function] = cfg
        return cfg_dict

    def get_graph(self, quietOp, asmOp, cOp, irOp, saveOp, outputPath):
        """
        Get the CFG graph of the bin file. Print the basic block of each function in the func_list
        in the representation of asm or C. Optional choose to save the CFG info in the yaml format.
        In each basic block (node), the print info is listed as: node_id, node_predecessor, 
        node_successor, node_body.
        
        Arguments:
            quietOp {bool} -- If this value is able (greater than 0 or True), the script will print nothing.
            asmOp {bool} -- When quietOp is disable, if asmOp value is able, the print of node_body will add asm.
            cOp {bool} -- When quietOp is disable, if cOp value is able, the print of node_body will add C.
            irOp {bool} -- When quietOp is disable, if irOp value is able, the print of node_body will add vex IR.
            saveOp {bool} -- If this value is able, the resolving result will be stored in yaml file.
            outputPath {string} -- Specify the yaml stored path.
        
        Returns:
            dict -- Return a dict contains edges and nodes of cfg graph, but not completed....
        """
        dict_func_graph = {} # key: 'func_name' -> $(func_nodes_edges)
        objdump = Resol_objdump(self.file_path)
        binStruc = CFG_Bin_Custom(os.path.split(self.file_path)[-1])
        for function in self.cfg_dict:
            objdump.struc_func(objdump.all_functions[function])
            funcStruc = CFG_Func_Custom(function, objdump.funcMap.address, objdump.funcMap.ccode)
            nodes = self.cfg_dict[function].graph.nodes()
            edges = self.cfg_dict[function].graph.out_edges()
            dict_graph_nodes = {} # keys: 'nodes' -> $(list_nodes), 'edges' -> $(list_edges)
            dict_nodes_node = {} # key: 'nodename' -> $(nodeInfo)
            for node in nodes:
                node_id = node.addr
                node_pre = node.predecessors
                node_suc = node.successors
                if node.block:
                    instrs = node.block.pp() # TODO: get instrustions
                    vexir = str(node.block.vex)
                else:
                    instrs = ''
                    vexir = ''
                if len(instrs):
                    nodeStruc = CFG_Node_Custom(node_id, node_pre, node_suc, instrs, vexir)
                    funcStruc.addNode(nodeStruc)
            list_edges = []
            for edge in edges:
                list_edges.append((edge[0].name, edge[1].name))
            binStruc.addFunc(funcStruc)
            dict_graph_nodes['edges'] = list_edges
            dict_graph_nodes['nodes'] = dict_nodes_node
            dict_func_graph[function] = dict_graph_nodes
        if quietOp:
            binStruc.printF(asmOp, cOp, irOp)
        if saveOp:
            binStruc.generate_yaml_file(outputPath)
        return dict_func_graph