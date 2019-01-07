#/usr/bin/env bash
set -e

###################################
########### Geolocation ###########
###################################
#This uses only the area of service data.

### Generate data
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/arica.icmp.join data/bgp.csv arica > result/final/geo.arica
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/merced.icmp.join data/bgp.csv merced > result/final/geo.merced
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/saopaulo.icmp.join data/bgp.csv saopaulo > result/final/geo.saopaulo
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze testing result/tucapel.icmp.join data/bgp.csv tucapel > result/final/geo.tucapel

### asncount
#Sistemas autonomos con los cuales conversa Vs la cantidad de redes /24 con los cuales habla.
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "asncount") {print $2;}}' > result/final/geo/asncount.tucapel.csv

### hopcount
#Cantidad de saltos maxima (hops) desde la entrada hasta la salida de un AS.
cat result/final/geo.arica |  awk 'BEGIN {FS=":"} {if ($1 == "hopcount") {print $2;}}' > result/final/geo/hopcount.arica.csv
cat result/final/geo.merced |  awk 'BEGIN {FS=":"} {if ($1 == "hopcount") {print $2;}}' > result/final/geo/hopcount.merced.csv
cat result/final/geo.saopaulo |  awk 'BEGIN {FS=":"} {if ($1 == "hopcount") {print $2;}}' > result/final/geo/hopcount.saopaulo.csv
cat result/final/geo.tucapel |  awk 'BEGIN {FS=":"} {if ($1 == "hopcount") {print $2;}}' > result/final/geo/hopcount.tucapel.csv

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

### assignednorm
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
    python result/final/plot.py ./result/final/geo/asncount.$a.csv ./result/final/graph/geo/asncount.$a.png 10 "$a: Numero de Redes /24 por Sistema Autonomo" "Sistema Autonomo" "Numero de Redes"
done
# hopcount
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/hopcount.$a.csv ./result/final/graph/geo/hopcount.$a.png 10 "$a: Numero de Sistemas Autonomos por Salto" "Saltos" "Numero de Sistemas Autonomos" 0
done
# country
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/country.$a.csv ./result/final/graph/geo/country.$a.png 10 "$a: Numero de Redes por País" "Codigo País" "Numero de Redes"
done
# countryweight
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/countryweight.$a.csv ./result/final/graph/geo/countryweight.$a.png 10 "$a: Media Ponderada de Redes por País" "Codigo País" "Media Ponderada de Redes"
done
# countryas
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/countryas.$a.csv ./result/final/graph/geo/countryas.$a.png 10 "$a: Numero de Sistemas Autonomos por País" "Codigo País" "Numero de Sistemas Autonomos"
done
# assigned
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/assigned.$a.csv ./result/final/graph/geo/assigned.$a.png 10 "$a: Asignación de Sistemas Autonomos Segun Distancia" "Nodo" "Numero de Sistemas Autonomos"
done
# assignedweighted
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/geo/assignedweighted.$a.csv ./result/final/graph/geo/assignedweighted.$a.png 10 "$a: Asignación Ponderada de Sistemas Autonomos Segun Distancia" "Nodo" "Media Ponderada de Sistemas Autonomos"
done



###################################
########### Latency ###############
###################################

RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze latency result/arica.icmp.join data/bgp.csv > result/final/latency.arica
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze latency result/merced.icmp.join data/bgp.csv > result/final/latency.merced
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze latency result/saopaulo.icmp.join data/bgp.csv > result/final/latency.saopaulo
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze latency result/tucapel.icmp.join data/bgp.csv > result/final/latency.tucapel

# networklatency
cat result/final/latency.arica | awk 'BEGIN {FS=":"} {if ($1 == "networklatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/networklatency.arica.csv
cat result/final/latency.merced | awk 'BEGIN {FS=":"} {if ($1 == "networklatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/networklatency.merced.csv
cat result/final/latency.saopaulo | awk 'BEGIN {FS=":"} {if ($1 == "networklatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/networklatency.saopaulo.csv
cat result/final/latency.tucapel | awk 'BEGIN {FS=":"} {if ($1 == "networklatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/networklatency.tucapel.csv

# aslatency
cat result/final/latency.arica | awk 'BEGIN {FS=":"} {if ($1 == "aslatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/aslatency.arica.csv
cat result/final/latency.merced | awk 'BEGIN {FS=":"} {if ($1 == "aslatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/aslatency.merced.csv
cat result/final/latency.saopaulo | awk 'BEGIN {FS=":"} {if ($1 == "aslatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/aslatency.saopaulo.csv
cat result/final/latency.tucapel | awk 'BEGIN {FS=":"} {if ($1 == "aslatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/aslatency.tucapel.csv

# weightedlatency
cat result/final/latency.arica | awk 'BEGIN {FS=":"} {if ($1 == "weightedlatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/weightedlatency.arica.csv
cat result/final/latency.merced | awk 'BEGIN {FS=":"} {if ($1 == "weightedlatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/weightedlatency.merced.csv
cat result/final/latency.saopaulo | awk 'BEGIN {FS=":"} {if ($1 == "weightedlatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/weightedlatency.saopaulo.csv
cat result/final/latency.tucapel | awk 'BEGIN {FS=":"} {if ($1 == "weightedlatency") {if ($3 != "") {print $2"\\,"$3;} else {print $2}}}' > result/final/latency/weightedlatency.tucapel.csv

# Generate graphs (TODO: Change axis when using weights)
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/latency/networklatency.$a.csv ./result/final/graph/latency/networklatency.$a.png 50 "$a: Tiempo de Retorno por Red /24" "Round Trip Time" "/24 Network Count" 0
done
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/latency/aslatency.$a.csv ./result/final/graph/latency/aslatency.$a.png 50 "$a:Tiempo de Retorno por Cantidad de Sistemas Autonomos" "Tiempo de Retorno" "Cantidad de Sistemas Autonomos" 0
done
for a in "arica" "merced" "saopaulo" "tucapel"; do
    python result/final/plot.py ./result/final/latency/weightedlatency.$a.csv ./result/final/graph/latency/weightedlatency.$a.png 50 "$a: Tiempo de Retorno segun Media Ponderada de Clientes" "Tiempo de Retorno" "Media Ponderada de Clientes" 0
done


###################################
########### Verification ##########
###################################

RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze verify data/bgp.csv ./data/ripe/capture.json


###################################
############ Topologic ############
###################################

RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze estimator run data/bgp.csv > result/final/estimator.raw
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze estimator runweight data/bgp.csv > result/final/estimator.weighted
RUSTFLAGS='-C target-cpu=native' RUST_LOG=anytrace=debug RUST_BACKTRACE=1 CARGO_TARGET_DIR=~/tmp cargo run --release --bin analyze estimator runhop data/bgp.csv > result/final/estimator.hop

# Raw and Weighted
cat result/final/estimator.raw | awk 'BEGIN {FS=":"} {if ($1 == "rawminimalcompare") {print $2;}}' > result/final/estimator/raw.min.csv
cat result/final/estimator.raw | awk 'BEGIN {FS=":"} {if ($1 == "rawareamaximal") {print $2;}}' > result/final/estimator/raw.count.csv
cat result/final/estimator.weighted | awk 'BEGIN {FS=":"} {if ($1 == "rawminimalcompare") {print $2;}}' > result/final/estimator/weighted.min.csv

python result/final/plotmultibar.py ./result/final/estimator/raw.min.csv ./result/final/graph/estimator/raw.min.png 10 "Minimización de Latencia" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Latencia Inicial Cliente,Latencia Final Cliente,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/raw.count.csv ./result/final/graph/estimator/raw.count.png 10 "Minimización de Latencia segun Sistemas Afectados" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Latencia Inicial Cliente,Latencia Final Cliente,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/weighted.min.csv ./result/final/graph/estimator/weighted.min.png 10 "Minimización de Latencia Ponderada" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Latencia Inicial Cliente,Latencia Final Cliente,Sistemas Autonomos Afectados"

# Latency limited weighted
cat result/final/estimator.weighted | awk 'BEGIN {FS=":"} {if ($1 == "rawminimallimcompare1") {print $2;}}' > result/final/estimator/raw.wgt.lim1.csv
cat result/final/estimator.weighted | awk 'BEGIN {FS=":"} {if ($1 == "rawminimallimcompare2") {print $2;}}' > result/final/estimator/raw.wgt.lim2.csv
cat result/final/estimator.weighted | awk 'BEGIN {FS=":"} {if ($1 == "rawminimallimcompare3") {print $2;}}' > result/final/estimator/raw.wgt.lim3.csv
cat result/final/estimator.weighted | awk 'BEGIN {FS=":"} {if ($1 == "rawminimallimcompare4") {print $2;}}' > result/final/estimator/raw.wgt.lim4.csv

python result/final/plotmultibar.py ./result/final/estimator/raw.wgt.lim1.csv ./result/final/graph/estimator/raw.wgt.lim1.png 10 "Minimización de Latencia Limitada a 1 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/raw.wgt.lim2.csv ./result/final/graph/estimator/raw.wgt.lim2.png 10 "Minimización de Latencia Limitada a 2 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/raw.wgt.lim3.csv ./result/final/graph/estimator/raw.wgt.lim3.png 10 "Minimización de Latencia Limitada a 3 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/raw.wgt.lim4.csv ./result/final/graph/estimator/raw.wgt.lim4.png 10 "Minimización de Latencia Limitada a 4 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"


# Hop
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "hoprawcompare") {print $2;}}' > result/final/estimator/hop.raw.csv
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "hopweightcompare") {print $2;}}' > result/final/estimator/hop.wgt.csv
python result/final/plotmultibar.py ./result/final/estimator/hop.raw.csv ./result/final/graph/estimator/hop.raw.png 10 "Minimización de Saltos" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Latencia Inicial Cliente,Latencia Final Cliente,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/hop.wgt.csv ./result/final/graph/estimator/hop.wgt.png 10 "Minimización de Saltos Ponderado" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Latencia Inicial Cliente,Latencia Final Cliente,Sistemas Autonomos Afectados"

# Limited raw
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "limitedrawcompare1") {print $2;}}' > result/final/estimator/raw.cmp1.csv
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "limitedrawcompare2") {print $2;}}' > result/final/estimator/raw.cmp2.csv
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "limitedrawcompare3") {print $2;}}' > result/final/estimator/raw.cmp3.csv
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "limitedrawcompare4") {print $2;}}' > result/final/estimator/raw.cmp4.csv

python result/final/plotmultibar.py ./result/final/estimator/raw.cmp1.csv ./result/final/graph/estimator/raw.cmp1.png 10 "Minimización Global Limitada a 1 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/raw.cmp2.csv ./result/final/graph/estimator/raw.cmp2.png 10 "Minimización Global Limitada a 2 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/raw.cmp3.csv ./result/final/graph/estimator/raw.cmp3.png 10 "Minimización Global Limitada a 3 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/raw.cmp4.csv ./result/final/graph/estimator/raw.cmp4.png 10 "Minimización Global Limitada a 4 Salto" "Sistema Autonomo" "Latencia" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"

# Limited weighted
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "hopweightcompare1") {print $2;}}' > result/final/estimator/hop.wgtcmp1.csv
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "hopweightcompare2") {print $2;}}' > result/final/estimator/hop.wgtcmp2.csv
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "hopweightcompare3") {print $2;}}' > result/final/estimator/hop.wgtcmp3.csv
cat result/final/estimator.hop | awk 'BEGIN {FS=":"} {if ($1 == "hopweightcompare4") {print $2;}}' > result/final/estimator/hop.wgtcmp4.csv

python result/final/plotmultibar.py ./result/final/estimator/hop.wgtcmp1.csv ./result/final/graph/estimator/hop.wgtcmp1.png 10 "Minimización de Saltos Limitada a 1 Salto" "Sistema Autonomo" "Saltos" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/hop.wgtcmp2.csv ./result/final/graph/estimator/hop.wgtcmp2.png 10 "Minimización de Saltos Limitada a 2 Salto" "Sistema Autonomo" "Saltos" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/hop.wgtcmp3.csv ./result/final/graph/estimator/hop.wgtcmp3.png 10 "Minimización de Saltos Limitada a 3 Salto" "Sistema Autonomo" "Saltos" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
python result/final/plotmultibar.py ./result/final/estimator/hop.wgtcmp4.csv ./result/final/graph/estimator/hop.wgtcmp4.png 10 "Minimización de Saltos Limitada a 4 Salto" "Sistema Autonomo" "Saltos" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"



python result/final/plotmultibar.py ./result/final/estimator/hop.wgtcmp4.csv ./result/final/graph/estimator/invalid.png 10 "Minimización de Saltos Limitada a 4 Salto" "Sistema Autonomo" "Saltos" "Sistemas Autonomos Afectados" "Saltos Iniciales,Saltos Finales,Sistemas Autonomos Afectados"
