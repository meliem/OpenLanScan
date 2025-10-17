#!/bin/bash
# Fix permissions for OpenLanScan

echo "🔧 Fixing permissions..."

# Get the script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Fix node_modules ownership
echo "Fixing node_modules ownership..."
sudo chown -R $USER node_modules 2>/dev/null || true

# Clean caches
echo "Cleaning Vite cache..."
rm -rf node_modules/.vite* dist 2>/dev/null || true

# Fix all file permissions
echo "Fixing file permissions..."
sudo chmod -R u+rwX node_modules 2>/dev/null || true

echo "✅ Done! Now run: npm run tauri:dev"
