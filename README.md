# AnyTrace
AnyTrace is a tool used to detect the area of service of many anycast servers d$

# Dependencies
for python:
- pytricia
for rust:
- IPAdress
- radix_trie 
other rust dependencies specified in the Cargo.toml file

# Running

# Hitlist
hitlist is a program that generates a file of alive ips.  
To run hitlist a file named **asn_prefixes.json** with the current ASNs registered is required.  
**asn_prefixes.json** must be within a directory named **data** within the root folder.  
The structure of the json file must be the following:  
- {asn1: [network1, netwok2 ...], asn2 :[network1, network2, ...]}  

for example:  
- {"42708": ["0.0.0.0/0", "5.198.248.0/21"]}  

Aditionally in order to avoid pinging Networks that do not support ICMP, it is highlt  
recomended to provide a **blacklist.txt** file of those networks that should not be consulted.  
Not doing so, could derive in congestion, and possible looping.


## Running hitlist
running with debbuging options are recommended. The user must be positioned in root project folder.


- to run hitlist and  refresh the file

```
cargo build && sudo RUST_LOG=DEBUG ./target/debug/refresh data/asn_prefixes.json data/alive_ips local_ip data/blacklist.txt  > refresh

```

where **alive_ips** is a previous file of alive ips that the user wishes to refresh (verify if still alive).  
In the case of no previous ips, an empty file can be passed.  
local_ip is the public ip of the network in use, while black_list is an "optional" parameter.  
Results should appear in the refresh file.

# BlackList and coverage
To generate a blacklist of networks that should not be pinged a python code is provided:

## Running 

- the user must be in the root folder

```
pyhon3 src/hitlist/statistics.py blacklist <path_to_json_file> <path_file_generated_by_hitlist>
```

- by running statistics.py a file named **partial_coverage.txt** will be generated,  with the percentage of ASNs with at least
1 network alive, over the total of ASNs

- other statistcs can be obtained by running

```
pyhon3 src/hitlist/statistics.py <stat name> <path1> <path2>
```
- where stat name:
    - `dead_asn`
    - `alive_asn`
    - `dead_networks`
    - `alive_networks`


## ASSUMPTIONS(IMPORTANT):
- the trie used doesn't support /0 prefixes,
- to ignore every possible ip use both 1.0.0.0/1, 128.0.0.0/1 networks