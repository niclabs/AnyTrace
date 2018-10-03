import json
import ipaddress

class Statistics():
    def __init__(self, jdata, sfile):
        '''
        :param jdata : json data path
        :para sfile: alive ips file
        '''
        with open(jdata, 'r') as d:
            self.data = json.load(d)

        self.asn_len= len(self.data)
        ip_file = open(sfile)
        self.ips =[ipaddress.ip_address(x.strip()) for x in ip_file] 
        self.asns=[]
        self.initAsn()
    
    def initAsn(self):
        '''
        initializes asn list for object statistics
        '''
        for x in self.data:
            self.asns.append(ASN_number(x, self.data[x]))

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
    def __init__(self,ids, netlist):
        self.number= ids
        self.networks= [ipaddress.ip_network(i) for i in netlist]
        

stat= Statistics("data/asn_prefixes.json", 'archivo2')
stat.asn_partial_coverage()