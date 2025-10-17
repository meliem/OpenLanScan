#!/bin/bash

echo "🔍 OpenLanScan Project Verification"
echo "===================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "${RED}✗${NC} $1 (missing)"
        return 1
    fi
}

check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} $1/"
        return 0
    else
        echo -e "${RED}✗${NC} $1/ (missing)"
        return 1
    fi
}

echo "📁 Project Structure:"
echo "-------------------"
check_dir "src"
check_dir "src/lib"
check_dir "src-tauri"
check_dir "src-tauri/src"
check_dir "node_modules"
echo ""

echo "📄 Configuration Files:"
echo "----------------------"
check_file "package.json"
check_file "vite.config.ts"
check_file "tailwind.config.js"
check_file "tsconfig.json"
check_file "src-tauri/Cargo.toml"
check_file "src-tauri/tauri.conf.json"
check_file "src-tauri/build.rs"
echo ""

echo "🦀 Rust Source Files:"
echo "--------------------"
check_file "src-tauri/src/main.rs"
check_file "src-tauri/src/types.rs"
check_file "src-tauri/src/scanner.rs"
check_file "src-tauri/src/resolver.rs"
check_file "src-tauri/src/port_scanner.rs"
echo ""

echo "💻 Frontend Files:"
echo "-----------------"
check_file "index.html"
check_file "src/main.ts"
check_file "src/App.svelte"
check_file "src/styles.css"
check_file "src/lib/tauri.ts"
check_file "src/lib/HostTable.svelte"
check_file "src/lib/HostDetails.svelte"
check_file "src/lib/ConfigDialog.svelte"
check_file "src/lib/ProgressBar.svelte"
echo ""

echo "📚 Documentation:"
echo "----------------"
check_file "README.md"
check_file "LICENSE"
check_file "QUICKSTART.md"
check_file "IMPLEMENTATION_NOTES.md"
check_file ".gitignore"
echo ""

echo "🔧 Build Status:"
echo "---------------"
if [ -f "src-tauri/Cargo.lock" ]; then
    echo -e "${GREEN}✓${NC} Rust dependencies fetched"
else
    echo -e "${YELLOW}⚠${NC} Rust dependencies not yet fetched (run: cargo check)"
fi

if [ -f "package-lock.json" ]; then
    echo -e "${GREEN}✓${NC} npm dependencies installed"
else
    echo -e "${RED}✗${NC} npm dependencies not installed (run: npm install)"
fi

if [ -d "src-tauri/target" ]; then
    echo -e "${GREEN}✓${NC} Rust build directory exists"
else
    echo -e "${YELLOW}⚠${NC} No build artifacts yet (run: cargo build)"
fi
echo ""

echo "⚡ Quick Commands:"
echo "-----------------"
echo "  Development:  npm run tauri:dev"
echo "  Build:        npm run tauri:build"
echo "  Format Rust:  cargo fmt"
echo "  Check Rust:   cargo clippy"
echo ""

echo "📊 Project Stats:"
echo "----------------"
echo "  Rust files:    $(find src-tauri/src -name '*.rs' 2>/dev/null | wc -l | tr -d ' ')"
echo "  Svelte files:  $(find src -name '*.svelte' 2>/dev/null | wc -l | tr -d ' ')"
echo "  TS files:      $(find src -name '*.ts' 2>/dev/null | wc -l | tr -d ' ')"
echo "  Total lines:   $(find src src-tauri/src -type f \( -name '*.rs' -o -name '*.ts' -o -name '*.svelte' \) -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')"
echo ""

echo "✅ Verification complete!"
