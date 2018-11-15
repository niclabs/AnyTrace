#!/usr/bin/env bash
set -e

IP="$1"
PPS="$2"
METHOD="$3"
DURATION=$((20000/20000*1800+1200))

RUST_LOG=INFO target/release/anytrace --ip $IP --pps $PPS --duration $DURATION --method $METHOD > result$METHOD.csv
