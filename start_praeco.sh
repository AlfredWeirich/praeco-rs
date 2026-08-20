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

LOG_LEVEL_UPPER=$(echo "$LOG_LEVEL" | tr '[:lower:]' '[:upper:]')

echo RUST_LOG="warn,praeco_rs=${LOG_LEVEL},praeco_rs::middleware::logger=${LOG_LEVEL_UPPER}" cargo run -p praeco-rs --release -- "${CARGO_ARGS[@]}"
RUST_LOG="warn,praeco_rs=${LOG_LEVEL},praeco_rs::middleware::logger=${LOG_LEVEL_UPPER}" cargo run -p praeco-rs --release -- "${CARGO_ARGS[@]}"