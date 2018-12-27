#/usr/bin/env bash
set -e

## geo
#This uses only the area of service data.

### Generate data
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/arica.icmp.join data/bgp.csv 45.71.8.0 > result/final/geo.arica
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/merced.icmp.join data/bgp.csv 200.1.123.0 > result/final/geo.merced
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/saopaulo.icmp.join data/bgp.csv 200.160.0.0 > result/final/geo.saopaulo
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/tucapel.icmp.join data/bgp.csv 190.153.177.0 > result/final/geo.tucapel


### asncount
#Sistemas autonomos con los cuales conversa Vs la cantidad de redes /24 con los cuales habla.
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.tucapel.csv

### jumpcount
#Cantidad de saltos maxima (hops) desde la entrada hasta la salida de un AS.
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "jumpcount") {print $2;}}' > result/final/geo/jumpcount.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "jumpcount") {print $2;}}' > result/final/geo/jumpcount.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "jumpcount") {print $2;}}' > result/final/geo/jumpcount.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "jumpcount") {print $2;}}' > result/final/geo/jumpcount.tucapel.csv

### country
#Cantidad de prefijos por pais (Filtrando por presición < 1000km (¿cual es el maximo?))
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "country") {print $2;}}' > result/final/geo/country.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "country") {print $2;}}' > result/final/geo/country.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "country") {print $2;}}' > result/final/geo/country.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "country") {print $2;}}' > result/final/geo/country.tucapel.csv

### countryas
#Cantidad de sistemas autonomos por pais con el que se comunica el nodo.
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "countryas") {print $2;}}' > result/final/geo/countryas.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "countryas") {print $2;}}' > result/final/geo/countryas.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "countryas") {print $2;}}' > result/final/geo/countryas.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "countryas") {print $2;}}' > result/final/geo/countryas.tucapel.csv

### countryweight
#The location with the weight applied. (number of queries)
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "countryweight") {print $2;}}' > result/final/geo/countryweight.tucapel.csv

### assigned
#Number of assigned (by geodistance) AS for every location in the area of the anycast node
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "assigned") {print $2;}}' > result/final/geo/assigned.tucapel.csv

### assignedweighted
#Weighted number of assigned AS for every location in the area of the anycast node
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "assignedweighted") {print $2;}}' > result/final/geo/assignedweighted.tucapel.csv

### Generate graphs
# asncount
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/asncount.$a.csv ./result/final/graph/geo/asncount.$a.png 10 "/24 Network Count Vs ASN" "ASN" "/24 Network Count"
done
# jumpcount
# Distance (TODO: Better graph)
#for a in "arica" "merced" "saopaulo" "tucapel"; do
#    python result/final/plot.py ./result/final/geo/jumpcount.$a.csv ./result/final/graph/geo/jumpcount.$a.png 10 "/24 Network Count Vs ASN" "ASN" "/24 Network Count"
#done
# country
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/country.$a.csv ./result/final/graph/geo/country.$a.png 10 "/24 Network Count Vs Country Code" "Country Code" "/24 Network Count"
done
# countryweight
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/countryweight.$a.csv ./result/final/graph/geo/countryweight.$a.png 10 "Weighted /24 Network Count Vs Country Code" "Country Code" "Weighted /24 Network Count"
done
# countryas
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/countryas.$a.csv ./result/final/graph/geo/countryas.$a.png 10 "AS Count Vs Country Code" "Country Code" "AS Count"
done
# assigned
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/assigned.$a.csv ./result/final/graph/geo/assigned.$a.png 10 "$a: AS Count Vs Country Code" "Country Code" "AS Count"
done
# assignedweighted
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/assignedweighted.$a.csv ./result/final/graph/geo/assignedweighted.$a.png 10 "$a: AS Count Vs Country Code" "Country Code" "AS Count"
done
