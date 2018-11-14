#!/usr/bin/env bash

IP="$1"
PPS="$2"
METHOD="$3"

RUST_LOG=INFO ./anytrace --ip $IP --pps $PPS --method $METHOD --hitlist hitlist.txt --master > result$METHOD.csv
