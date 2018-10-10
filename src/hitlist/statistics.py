import json
import ipaddress
import pytricia

class Statistics():
    def __init__(self, jdata, sfile):
        '''
        :param jdata : json data path
        :para sfile: alive ips file
        '''
        with open(jdata, 'r') as d:
            #data is a dictionary type
            self.data = json.load(d)

        self.asn_len= len(self.data)
        ip_file = open(sfile)
        self.ips= [x.strip() for x in ip_file]
        #self.ips =[ipaddress.ip_address(x.strip()) for x in ip_file] 
        self.asns=[]
        self.initAsn()
        self.trie= pytricia.PyTricia()
        self.init_trie()
    
    def initAsn(self):
        '''
        initializes asn list for object statistics
        '''
        for x in self.data:
            self.asns.append(ASN_number(x, self.data[x]))

    def init_trie(self):
        '''
        initialices a pytricia trie with key network: value asn object
        '''
        for Asn in self.asns:
            Asn.insert_nodes(self.trie)

    def asn_partial_coverage(self):
        '''
        :returns the percentage of asns with at least
        1 network alive, over the total of asns
        '''
        asnfound=0
        for x in self.asns:
            for i in x.networks:
                for j in self.ips:
                    if(j in i):
                        asnfound+=1
                        break
                break
            
        return asnfound*100/self.asn_len

class ASN_number():
    def __init__(self, id, netlist):
        # if some ip within this asn is alive, the parameter 
        # will be true
        self.found= False
        self.number= id
        # self.networks= [ipaddress.ip_network(i) for i in netlist]
        self.networks = netlist

    def remove_nodes(self, trie):
        '''
        for every network within this asn number, the node
        in the trie will be removed
        :param: trie of networks
        :returns void
        '''
        for net in self.networks:
            trie.delete(net)

    def insert_nodes(self, trie):
        '''
        for every network within the netoworks of the asn,
         a node will be inserted in the trie
        '''
        #todo
        pass


stat= Statistics("data/asn_prefixes.json", 'archivo2')
stat.asn_partial_coverage()