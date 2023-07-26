#/bin/sh
set -ex

current="$(realpath "$(dirname "$0")")"

export GOPATH=$PWD
(cd "${current}/generator" && cat "${current}/public_suffix_list.dat" | \
    go run main.go --output-path "${current}/src/" --base-name tld_list
)
cargo fmt
