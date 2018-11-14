# AnyTrace
AnyTrace is a tool used to detect the area of service of many anycast servers d$

## Running
All the executables need root access to create the sockets and listen to the ICMP packets.

To run the example:
```
cargo run --bin example
```
To generate the ip hitlist:
```
cargo run --bin hitlist
```

```
nmap --randomize-hosts -sL -n 0.0.0.0/0 | head | grep 'Nmap scan report for' | cut -f 5 -d ' ' | awk -F',' 'NF {print $1; print $2;}' | sort -u

```

## Setcap
To set the capabilities of the generated binary, and not use root, you have to use the following command

```
sudo setcap CAP_NET_RAW+ep anytrace
```

# Analysis
## Generating bgp.csv

Source: https://bitbucket.org/ripencc/bgpdump/wiki/Home
```
./bgpdump bview.20181017.0000.gz -m | awk 'BEGIN{FS="|";OFS="|"}{print $6", "$7}' | awk 'BEGIN{FS=" ";OFS=" "}{print $1$NF}' | sort | uniq > data/bgp.csv
```
