#!/bin/bash

LOG_LEVEL="info"
CARGO_ARGS=()

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --log-level|-l)
            LOG_LEVEL="$2"
            shift 2
            ;;
        *)
            CARGO_ARGS+=("$1")
            shift
            ;;
    esac
done

RUST_LOG="warn,praeco_relay_server=${LOG_LEVEL}" cargo run -p praeco-relay-server --release -- "${CARGO_ARGS[@]}"
