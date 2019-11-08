from ruamel import yaml
from .cfg_func_custom import CFG_Func_Custom

class CFG_Bin_Custom:
    def __init__(self, binName=''):
        self.binName = binName
        self.cfg_funcs = []

    def addFunc(self, function):
        self.cfg_funcs.append(function)

    def printF(self, asmOp, cOp, irOp):
        print('###### BIN: ###### %s'%(self.binName))
        for func in self.cfg_funcs:
            print('=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=')
            func.printF(asmOp, cOp, irOp)

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