set -e
CARGO_TARGET_DIR=~/tmp cargo build
sudo RUST_BACKTRACE=1 ~/tmp/debug/anytrace --ip 10.0.2.15
