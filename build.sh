set -e
CARGO_TARGET_DIR=~/tmp cargo build
sudo RUST_BACKTRACE=1 ~/tmp/debug/globaltrace
