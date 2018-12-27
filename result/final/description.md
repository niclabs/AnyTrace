# Experiment result description
## geo
This uses only the area of service data.

### asncount
Sistemas autonomos con los cuales conversa y la cantidad de redes /24 con los cuales habla.

### jumpcount
Cantidad de saltos maxima (hops) desde la entrada hasta la salida de un AS

### country
Cantidad de prefijos por pais (Filtrando por presición < 1000km (¿cual es el maximo?))

### countryas
Cantidad de sistemas autonomos por pais con el que se comunica el nodo

### countryweight
The location normalized by the number of queries received

```
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/arica.icmp.join data/bgp.csv 45.71.8.0 | awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.arica.csv
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/merced.icmp.join data/bgp.csv 200.1.123.0 | awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.merced.csv
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/saopaulo.icmp.join data/bgp.csv 200.160.0.0 | awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.saopaulo.csv
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/tucapel.icmp.join data/bgp.csv 190.153.177.0 | awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.tucapel.csv
```

### asnweight
The locations normalized by the number of autonomous systems
```
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "asnweight") {print $2;}}' > result/final/geo/asnweight.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "asnweight") {print $2;}}' > result/final/geo/asnweight.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "asnweight") {print $2;}}' > result/final/geo/asnweight.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "asnweight") {print $2;}}' > result/final/geo/asnweight.tucapel.csv
```

### assigned
Number of assigned AS for every location in the area of the anycast node
```
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.tucapel.csv
```

### assignedweighted
Weighted number of assigned AS for every location in the area of the anycast node
```
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.tucapel.csv
```

### Generate data
```
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/arica.icmp.join data/bgp.csv 45.71.8.0 > result/final/geo.arica
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/merced.icmp.join data/bgp.csv 200.1.123.0 > result/final/geo.merced
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/saopaulo.icmp.join data/bgp.csv 200.160.0.0 > result/final/geo.saopaulo
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/tucapel.icmp.join data/bgp.csv 190.153.177.0 > result/final/geo.tucapel
```