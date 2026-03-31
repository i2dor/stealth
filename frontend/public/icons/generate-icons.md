# Generating PWA Icons

Run this script to generate the required icon sizes from a source SVG:

```bash
# Install sharp-cli once
npm install -g sharp-cli

# Generate from source SVG (place your icon at frontend/public/icons/icon.svg)
sharp -i icon.svg -o icon-192.png resize 192 192
sharp -i icon.svg -o icon-512.png resize 512 512
```

Or use any online tool (e.g. https://maskable.app) to create maskable icons.

## Required files
- `icon-192.png` — 192×192px, used on Android home screen
- `icon-512.png` — 512×512px, used on splash screen and desktop

## Current placeholder
Until real icons are generated, the app will use the browser default icon.
The manifest references `/icons/icon-192.png` and `/icons/icon-512.png`.
