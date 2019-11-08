

class FuncMapping:
    def __init__(self):
        self.ccode = {}  # key:value  ->  ccode_order:ccode_str
        self.address = {}  # key:value  ->  addr:ccode_order

    def getCcodeFromAddrRange(self, beginAddr, endAddr):  # beginAddr, endAddr -> str
        """
        Get the C code lines according to the span of asm code lines from the beginAddr to endAddr.
        
        Returns:
            string -- The processed result.
        """
        tmpCcode = ''
        tmpCcodeOrder = []
        for addr in range(int(beginAddr, 16), int(endAddr, 16) + 1):
            if hex(addr)[2:] in self.address.keys():
                tmpOrder = self.address[hex(addr)[2:]]
                if tmpOrder not in tmpCcodeOrder:
                    tmpCcodeOrder.append(tmpOrder)
                    tmpCcode += self.ccode[tmpOrder]
        return tmpCcode

    def clean(self):
        self.ccode = {}
        self.address = {}