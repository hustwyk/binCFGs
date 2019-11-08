import io
import re

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
            tmp_addr = re.findall(r'(0x[0-9a-f]+):', line)[0]
            extracted_addrs.append(hex(int(tmp_addr, 16) - baseAddr)[2:])
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