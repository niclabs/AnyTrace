set -e
CARGO_TARGET_DIR=~/tmp cargo build
sudo ~/tmp/debug/globaltrace
