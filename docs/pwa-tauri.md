# Running Stealth as PWA or Desktop App

## PWA (Mobile + Desktop via browser)

Stealth is a fully installable PWA. No app store required.

### Install on Android
1. Open https://stealth.vercel.app in Chrome
2. Tap the menu (⋮) → **Add to Home Screen**
3. Tap **Install** — Stealth appears as a standalone app

### Install on iOS (Safari)
1. Open https://stealth.vercel.app in Safari
2. Tap the Share button (↑)
3. Scroll down → **Add to Home Screen**
4. Tap **Add**

### Install on Desktop (Chrome/Edge)
1. Open https://stealth.vercel.app
2. Click the install icon (⊕) in the address bar
3. Click **Install**

---

## Tauri Desktop App (Windows / macOS / Linux)

Builds a native desktop binary (~5–10 MB) that embeds the frontend.
The backend Python API runs locally — your descriptor never leaves your machine.

### Prerequisites
```bash
# macOS
brew install rustup
rustup-init

# Windows
# Install Rust from https://rustup.rs
# Install WebView2 (usually pre-installed on Windows 11)

# Linux (Debian/Ubuntu)
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget \
  libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

### Install Tauri CLI
```bash
cargo install tauri-cli --version "^2"
```

### Development
```bash
# From repo root — starts both Vite (port 5173) and Tauri window
cargo tauri dev
```

### Build release binary
```bash
cargo tauri build
# Output: src-tauri/target/release/bundle/
# - macOS: Stealth.app + Stealth.dmg
# - Windows: Stealth_x64-setup.exe
# - Linux: stealth.deb + stealth.AppImage
```

### Running backend locally with Tauri

For full local privacy (no Vercel API), run the Python backend alongside Tauri:

```bash
# Terminal 1 — Python backend
cd api && pip install -r requirements.txt
uvicorn main:app --port 8000

# Terminal 2 — Tauri dev
cargo tauri dev
```

Then in Stealth Settings → set **Backend API base URL** to `http://localhost:8000`.
