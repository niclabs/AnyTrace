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

# Hitlist
hitlist is a program that generates a file of alive ips.
To run hitlist a .json file with the current ASNs registered is required.

## Running hitlist
running with debbuging options are recommended. The user must be positioned in the hitlist folder.

- to run hitlist :

```
cargo build && sudo RUST_LOG=DEBUG RUST_BACKTRACE=1 ./target/debug/hitlist > filename

```

- to refresh the file

```
cargo build && sudo RUST_LOG=DEBUG RUST_BACKTRACE=1 ./target/debug/hitlist/refresh > filename

```

# BlackList and coverage
To generate a blacklist of networks that should not be pingged a python code is provided:

## Running 

- the user must be in the root folder
- a folder named data with the asn .json file should be created inside the root folder

```
pyhon3 statistics blacklist
```