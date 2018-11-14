# AnyTrace
AnyTrace is a collection of tools used to detect the area of services of the servers on an anycast cloud.

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

## Setcap
To set the capabilities of the generated binary, and not use root, you have to use the following command

```
sudo setcap CAP_NET_RAW+ep anytrace
```
