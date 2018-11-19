import json
import ipaddress
import pytricia
import sys

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
        #while(self.trie.length > 0)
        for ip in self.ips:
            node= self.trie.get_key(ip)
            if(node!=None):
                self.trie.get(node).found= True

        alive=0

        for asn in self.asns:
            if asn.found:
                alive+=1
        f=open("results/partialcoverage.txt", "w+")
        coverage=alive*100/self.asn_len
        f.write("asn found/ total asns = " + str(coverage))

    def dead_asn(self):
        '''returns a txt file with the Asn's suposed dead 
        this is a prediction parameter based on responsiveness to ping
        and must be corroborated'''

        f = open("results/dead_Asns.txt", "w+")
        for a in self.asns:
            if not a.found:
                f.write(a.number +"\n")

    def alive_asn(self):
        ''' returns a file with those Asn currently found alive'''
        f = open("results/alive_Asns.txt", "w+")
        for a in self.asns:
            if a.found:
                f.write(a.number+"\n")

    def dead_networks(self):
        f = open("results/dead_Networks.txt", "w+")
        for a in self.asns:
            if not a.found:
                for net in a.networks:
                    f.write(net +"\n")

    def alive_networks(self):
        f = open("results/alive_Networks.txt", "w+")
        for a in self.asns:
            if  a.found:
                for net in a.networks:
                    f.write(net +"\n")
            
    def find_blacklist(self):
        '''
        creates a file with all the networks which should not be pinged
        due to privacy matters, or ping-blocking policy
        '''
        self.trie.delete("0.0.0.0/0")
        for ip in self.ips:
            node= self.trie.get_key(ip)
            if(node!=None):
                self.trie.delete(node)    
                while(self.trie.get_key(node)!=None):
                    #parent=self.trie.get_key(node)
                    #self.trie.delete(parent)
                    #node= parent
                    match=self.trie.get_key(node)
                    self.trie.delete(match)

        #once all the ips are checked, the black list is created
        #iterate over the patricia trie and remove  every leaf nodes
        deleted=0
        length=0
        for prefix in self.trie:
            if self.trie.parent(prefix)==None:
                continue
            else:
                self.trie.delete(prefix)
      
        blacklist= self.trie.keys()
        f = open("data/blacklist.txt", "w+")
        for net in blacklist:
            f.write(net +"\n")

        for ip in self.ips:
            if self.trie.get_key(ip)!= None:
                print("bugg found")
        





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
        for net in self.networks:
            #inserting string(network), Object(Asn)
            trie.insert(net, self)
       
if __name__ == '__main__':
    method =sys.argv[1]
    stat= Statistics("data/asn_prefixes.json", 'archivo_refresh3')
    stat.asn_partial_coverage()
    map ={ 
    "dead_asn":stat.dead_asn(),
    "alive_asn":  stat.alive_asn() ,
    "dead_networks": stat.dead_networks() ,
    "alive_networks":  stat.alive_networks(),
    "blacklist": stat.find_blacklist() }  
    map[method]
