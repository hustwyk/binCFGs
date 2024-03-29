from .funcmapping import FuncMapping
from .cfg_node_custom import CFG_Node_Custom

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
            if len(tmpCcode):
                node.node_c_body = tmpCcode
            else:
                node.node_c_body = 'NULL\n'
        else:
            node.node_c_body = 'NULL\n'
        return node

    def printF(self, asmOp, cOp, irOp):
        print('#### FUNCTION: #### %s'%(self.funcName))
        for node in self.cfg_nodes:
            print('-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-')
            print('## NID: ## %s'%(hex(node.node_id)))
            print('## PRE: ## %s'%(str(node.node_pre)))
            print('## SUC: ## %s'%(str(node.node_suc)))
            if asmOp:
                print('## ASM: ##')
                print(node.node_asm_body)
                print('')
            if cOp:
                print('## C: ##')
                print(node.node_c_body)
            if irOp:
                print('## IR: ##')
                print(node.node_vex_body)
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