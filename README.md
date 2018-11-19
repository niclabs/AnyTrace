# AnyTrace
AnyTrace is a collection of tools used to detect the area of services of the servers on an anycast cloud.

## Running
To run this program, you must have root access or use setcap to add the CAP_NET_RAW capability to the binary

To run anytrace and generate the trace information, you must run:
```
cargo build --release
./target/release/anytrace\
    --ip xxx.xxx.xxx.xxx\
    --pps 20000\
    --method ICMP\
    --duration 2400\
    > resultICMP.csv
```

More detailed instructions can be found (in spanish) at [instructions.spanish.md](instructions.spanish.md)
