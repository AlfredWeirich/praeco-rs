#!/usr/bin/env bash
# ==============================================================================
# Praeco Relay Server — Start Script
# ==============================================================================
set -eo pipefail

SCRIPT_NAME="$(basename "$0")"
LOG_LEVEL="info"
BUILD_MODE="release"
CONFIG_FILE=""
EXTRA_ARGS=()

show_help() {
    cat << EOF
Praeco Relay Server — Start Script

USAGE:
    ./${SCRIPT_NAME} [OPTIONS] [CONFIG_FILE] [-- EXTRA_CARGO_ARGS...]

OPTIONS:
    -l, --log-level <LEVEL>    Set log level (error, warn, info, debug, trace) [default: info]
    -r, --release              Run in optimized release mode [default]
    -d, --debug                Run in unoptimized debug mode (faster compilation)
    -h, --help                 Print this help message and exit

ARGUMENTS:
    [CONFIG_FILE]              Optional path to configuration file (default: RelayConfig.toml)

EXAMPLES:
    ./${SCRIPT_NAME}
    ./${SCRIPT_NAME} -l trace
    ./${SCRIPT_NAME} -l trace ./relay-server/RelayConfig.toml
    ./${SCRIPT_NAME} --debug -l debug
    ./${SCRIPT_NAME} --help

EOF
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--log-level)
            if [[ -n "$2" && "$2" != -* ]]; then
                LOG_LEVEL="$2"
                shift 2
            else
                echo "❌ Fehler: Option $1 erfordert einen Wert (z.B. info, debug, trace)." >&2
                exit 1
            fi
            ;;
        --log-level=*)
            LOG_LEVEL="${1#*=}"
            shift
            ;;
        -r|--release|release)
            BUILD_MODE="release"
            shift
            ;;
        -d|--debug|debug)
            BUILD_MODE="debug"
            shift
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                EXTRA_ARGS+=("$1")
                shift
            done
            break
            ;;
        -*)
            echo "❌ Fehler: Unbekannte Option '$1'. Nutze './${SCRIPT_NAME} --help' für Hilfe." >&2
            exit 1
            ;;
        *)
            if [[ -z "$CONFIG_FILE" ]]; then
                CONFIG_FILE="$1"
            else
                EXTRA_ARGS+=("$1")
            fi
            shift
            ;;
    esac
done

CARGO_FLAGS=()
if [[ "$BUILD_MODE" == "release" ]]; then
    CARGO_FLAGS+=("--release")
fi

RUN_ARGS=()
if [[ -n "$CONFIG_FILE" ]]; then
    RUN_ARGS+=("$CONFIG_FILE")
fi
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    RUN_ARGS+=("${EXTRA_ARGS[@]}")
fi

export RUST_LOG="warn,praeco_relay_server=${LOG_LEVEL}"

echo "🚀 Starte Praeco Relay Server (Modus: ${BUILD_MODE}, Log-Level: ${LOG_LEVEL})..."
if [[ -n "$CONFIG_FILE" ]]; then
    echo "📄 Konfiguration: ${CONFIG_FILE}"
fi

exec cargo run -p praeco-relay-server "${CARGO_FLAGS[@]}" -- "${RUN_ARGS[@]}"
