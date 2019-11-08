import angr
import os
import sys
import json
from elftools.elf.elffile import ELFFile
from utils.listdir import list_all_files

def get_funcs(file_path):
    f=open(file_path,'rb')
    elf=ELFFile(f)
    symtab=elf.get_section_by_name('.symtab')
    funcnames=[]

    for i in range(symtab.num_symbols()):
        if(symtab.get_symbol(i).entry.st_info.type=='STT_FUNC'):
            name = symtab.get_symbol(i).name
            if name == "main" or name.startswith("Function"):
                funcnames.append(symtab.get_symbol(i).name)
    f.close()
    return funcnames

def get_proj_all_path(file_path, functions_list):
    proj = angr.Project(file_path, load_options={'auto_load_libs':False})
    cfg_dict = {}
    for function in functions_list:
        print("func:"+function)
        function_obj = proj.loader.main_object.get_symbol(function)
        start_state = proj.factory.blank_state(addr=function_obj.rebased_addr)
        cfg = proj.analyses.CFGEmulated(keep_state=True,
                                        starts=(function_obj.rebased_addr,),
                                        initial_state=start_state,
                                        call_depth=0)
        cfg=cfg.get_function_subgraph(start=function_obj.rebased_addr, max_call_depth=0)
        cfg_dict[function]=cfg
    return cfg_dict

def get_graph(binfile, functions):
    CFGs = get_proj_all_path(binfile,functions)
    dict_func_graph={} # key: 'func_name' -> $(func_nodes_edges)

    for function in CFGs:
        nodes = CFGs[function].graph.nodes()
        edges = CFGs[function].graph.out_edges()
        dict_graph_nodes={} # keys: 'nodes' -> $(list_nodes), 'edges' -> $(list_edges)
        dict_nodes_node={} # key: 'nodename' -> $(nodeInfo)
        for node in nodes:
            node_id = node.addr
            print(hex(node_id))
            node_suc = node.successors
            print(node_suc)
            node_pre = node.predecessors
            print(node_pre)
            print(type(node))
            if node.block.pp():
                instrs = node.block.pp() # TODO: get instrustions
                print(instrs)
            else:
                instrs = ""
        list_edges=[]
        for edge in edges:
            list_edges.append((edge[0].name,edge[1].name))

        dict_graph_nodes['edges']=list_edges
        dict_graph_nodes['nodes']=dict_nodes_node
        dict_func_graph[function]=dict_graph_nodes
    return dict_func_graph

files = list_all_files(sys.argv[1])
for filename in files:
    dict_file_func={}
    func_list=get_funcs(filename)
    dict_func_graph=get_graph(filename,func_list)
    # print(dict_func_graph)
    basename = os.path.basename(filename)
    dict_file_func[basename]=dict_func_graph # key:'filename'->$(dict_func_graph)

