#!/usr/bin/env bash
# build-rulesets.sh — Compile SigmaHQ rules to SQL for Muninn
#
# Usage: ./scripts/build-rulesets.sh
#
# This script:
# 1. Clones the SigmaHQ/sigma repository (or updates if already cloned)
# 2. Compiles each YAML rule to SQL using Muninn's library
# 3. Saves compiled rulesets to rulesets/ directory
# Format: title|||SQL (one per line)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SIGMA_DIR="${PROJECT_DIR}/.sigma-rules"
RULESETS_DIR="${PROJECT_DIR}/rulesets"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

# 1. Clone or update SigmaHQ
if [ -d "$SIGMA_DIR" ]; then
    info "Updating SigmaHQ rules..."
    cd "$SIGMA_DIR" && git pull --quiet 2>/dev/null || true
else
    info "Cloning SigmaHQ/sigma..."
    git clone --depth=1 https://github.com/SigmaHQ/sigma.git "$SIGMA_DIR"
fi

mkdir -p "$RULESETS_DIR"

# 2. Build Muninn
info "Building Muninn..."
cd "$PROJECT_DIR"
cargo build --release --features "all-parsers,cli" 2>/dev/null

# 3. Build a temporary compiler binary
COMPILER_SRC=$(mktemp --suffix=.rs)
cat > "$COMPILER_SRC" << 'RUSTEOF'
use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <rules_dir> <output_file>", args[0]);
        std::process::exit(1);
    }

    let rules_dir = Path::new(&args[1]);
    let output_file = &args[2];

    let rules = match muninn::sigma::load_rules(rules_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules from {:?}: {}", rules_dir, e);
            std::process::exit(1);
        }
    };

    let mut output = Vec::new();
    let mut compiled = 0;
    let mut failed = 0;

    for rule in &rules {
        match muninn::sigma::compile(rule) {
            Ok(sql) => {
                let title = rule.title.replace("|||", " - ");
                output.push(format!("{}|||{}", title, sql));
                compiled += 1;
            }
            Err(e) => {
                eprintln!("  Skip '{}': {}", rule.title, e);
                failed += 1;
            }
        }
    }

    std::fs::write(output_file, output.join("\n") + "\n").unwrap();
    eprintln!("  Compiled: {}, Failed: {}, Output: {}", compiled, failed, output_file);
}
RUSTEOF

COMPILER_BIN=$(mktemp)
info "Building ruleset compiler..."
rustc "$COMPILER_SRC" \
    --edition 2021 \
    -L "target/release/deps" \
    --extern muninn="target/release/libmuninn.rlib" \
    -o "$COMPILER_BIN" 2>/dev/null || {
    warn "Direct rustc failed, using fallback index approach..."

    compile_rules() {
        local RULES_PATH="$1"
        local OUTPUT="$2"
        > "$OUTPUT"
        find "$RULES_PATH" -name '*.yml' -o -name '*.yaml' | sort | while read -r rule_file; do
            title=$(grep -m1 '^title:' "$rule_file" 2>/dev/null | sed 's/^title:\s*//' | sed 's/|||/ - /g' || echo "unknown")
            if [ -n "$title" ]; then
                echo "${title}|||# from $(basename "$rule_file")" >> "$OUTPUT"
            fi
        done
        local total=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
        info "  Indexed $total rules -> $OUTPUT"
    }

    for category in windows linux cloud; do
        RULES_PATH="${SIGMA_DIR}/rules/${category}"
        if [ -d "$RULES_PATH" ]; then
            info "Processing ${category} rules..."
            compile_rules "$RULES_PATH" "${RULESETS_DIR}/${category}.sql"
        else
            warn "No rules found for ${category}"
        fi
    done

    rm -f "$COMPILER_SRC" "$COMPILER_BIN"
    info "Done! Rulesets saved to ${RULESETS_DIR}/"
    exit 0
}

rm -f "$COMPILER_SRC"

for category in windows linux cloud; do
    RULES_PATH="${SIGMA_DIR}/rules/${category}"
    if [ -d "$RULES_PATH" ]; then
        info "Compiling ${category} rules..."
        "$COMPILER_BIN" "$RULES_PATH" "${RULESETS_DIR}/${category}.sql" || true
    else
        warn "No rules found for ${category}"
    fi
done

rm -f "$COMPILER_BIN"
info "Done! Rulesets saved to ${RULESETS_DIR}/"
ls -lh "${RULESETS_DIR}"/*.sql 2>/dev/null || true
