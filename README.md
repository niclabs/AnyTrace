# AnyTrace
AnyTrace is a tool used to detect the area of service of many anycast servers d$

# Running
All the executables need root access to create the sockets and listen to the ICMP packets.

To run the example:
```
cargo run --bin example
```
To generate the ip hitlist:
```
cargo run --bin hitlist
```
