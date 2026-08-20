#!/usr/bin/env bash
# ==============================================================================
# Praeco API Gateway — Start Script
# ==============================================================================
set -eo pipefail

SCRIPT_NAME="$(basename "$0")"
LOG_LEVEL="info"
BUILD_MODE="release"
CONFIG_FILE=""
EXTRA_ARGS=()

show_help() {
    cat << EOF
Praeco API Gateway — Start Script

USAGE:
    ./${SCRIPT_NAME} [OPTIONS] [CONFIG_FILE] [-- EXTRA_CARGO_ARGS...]

OPTIONS:
    -l, --log-level <LEVEL>    Set log level (error, warn, info, debug, trace) [default: info]
    -r, --release              Run in optimized release mode [default]
    -d, --debug                Run in unoptimized debug mode (faster compilation)
    -h, --help                 Print this help message and exit

ARGUMENTS:
    [CONFIG_FILE]              Optional path to configuration file (default: Config.toml)

EXAMPLES:
    ./${SCRIPT_NAME}
    ./${SCRIPT_NAME} -l debug
    ./${SCRIPT_NAME} -l trace Config.dev.toml
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

LOG_LEVEL_UPPER=$(echo "$LOG_LEVEL" | tr '[:lower:]' '[:upper:]')
export RUST_LOG="warn,praeco_rs=${LOG_LEVEL},praeco_rs::middleware::logger=${LOG_LEVEL_UPPER}"

echo "🚀 Starte Praeco Gateway (Modus: ${BUILD_MODE}, Log-Level: ${LOG_LEVEL})..."
if [[ -n "$CONFIG_FILE" ]]; then
    echo "📄 Konfiguration: ${CONFIG_FILE}"
fi

exec cargo run -p praeco-rs "${CARGO_FLAGS[@]}" -- "${RUN_ARGS[@]}"