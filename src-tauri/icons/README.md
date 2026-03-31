# Tauri App Icons

Generate all required icon sizes with the Tauri CLI:

```bash
# Install Tauri CLI
cargo install tauri-cli --version "^2"

# Generate all icon sizes from a single 1024x1024 PNG
cargo tauri icon path/to/your-icon-1024.png
```

This generates:
- `32x32.png`
- `128x128.png`  
- `128x128@2x.png`
- `icon.icns` (macOS)
- `icon.ico` (Windows)
- `icon.png` (Linux)

Place your source icon (1024×1024px, square, PNG) in this directory and run the command above.
