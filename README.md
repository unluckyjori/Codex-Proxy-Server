# Codex Proxy Server

## Overview

The Codex Proxy Server is a secure, modular, and ergonomic proxy server built in Rust using the [Axum](https://github.com/tokio-rs/axum) framework. It provides a local API proxy for Codex/ChatGPT-like models, with robust authentication, logging, and server management features. It is designed to integrate seamlessly with Opencode and other compatible tools.

**Note:** Codex Proxy Server uses code from the OpenAI Codex CLI and leverages OpenAI's authentication flow to access models and determine plan eligibility. This ensures compatibility with OpenAI's model access and plan system.

## Features
- Secure authentication using local `auth.json` tokens
- CLI menu for server management (start, stop, list servers, login, refresh token)
- Health check and model listing endpoints
- Safe Rust (no unsafe code)
- Structured logging to `./logs/codex-proxy.log`
- Cross-platform server management (Unix/macOS/Windows)
- No hardcoded secrets, usernames, or tokens in source code

## Requirements
- Rust (latest stable recommended)
- Cargo (comes with Rust)

## Quick Start

### 1. Download/Clone the Repository
```sh
git clone https://github.com/unluckyjori/Codex-Proxy-Server.git
cd "Code"
```

### 2. Build the Project (Required Once)
```sh
cargo build --release
```

### 3. Run the Server
```sh
cargo run --release
```

### 4. Use the CLI Menu
- **Run server**: Starts the proxy server on port 5011
- **Close all servers**: Terminates all running proxy servers on ports 5011–5020
- **Login**: Authenticates and stores your token in `~/.codex/auth.json`
- **Refresh token**: Refreshes your authentication token
- **List running servers**: Shows which ports are active
- **Exit**: Quits the CLI

## Authentication

Authentication and model access are handled using the same mechanisms as the OpenAI Codex CLI. Your plan type and model access are determined by your OpenAI account and authentication tokens. The server supports three locations for your authentication token (`auth.json`). It will search and create the token in the following order:

1. **`~/.codex/auth.json`** — Primary location (Codex CLI compatible)
2. **`~/.opencode/auth.json`** — Secondary location (Opencode integration default)
3. **`./local_auth/auth.json`** — Fallback location in the current working directory

**How it works:**
- On first run, the server checks for `auth.json` in `~/.codex/`.
- If not found or not writable, it tries `~/.opencode/`.
- If both fail, it creates `auth.json` in a local folder called `local_auth` in your current directory.
- The CLI will notify you where your token is stored. If using the fallback, you will see a warning and should move the file to `~/.codex/` or `~/.opencode/` for best compatibility.
- The server will not start without valid authentication in one of these locations.

## Important: OpenAI/Opencode Auth Reset

If you have previously logged in to Opencode using OpenAI authentication, you must: (This is required for Opencode integration with Codex Proxy Server)

1. Run the following command to log out of Opencode:
   ```sh
   opencode auth logout
   ```
2. Select OpenAI.
3. After logging out, add the following provider configuration to your Opencode settings (in your `opencode.json` config):

```json
  "openai": {
    "npm": "@ai-sdk/openai-compatible",
    "name": "openai",
    "options": {
      "baseURL": "http://127.0.0.1:5011",
      "apiKey": "auto"
    },
    "models": {
      "gpt-5": {
        "name": "gpt-5"
      },
      "gpt-5-mini": {
        "name": "gpt-5-mini"
      },
      "gpt-5-nano": {
        "name": "gpt-5-nano"
      }
    }
  },
```

This ensures Opencode will use your local Codex Proxy Server for OpenAI-compatible requests.

## Logging
- All logs are written to the `logs` folder in the project directory (next to the executable): `Codex Proxy Server Rust/logs/codex-proxy.log` (created automatically).
- You can find daily log files in this folder for troubleshooting and auditing, regardless of where you run the server from.

## Security
- No hardcoded secrets, usernames, or tokens in source code
- All sensitive data is loaded from external files
- CORS and secure headers are enforced (customize as needed)

## Server Endpoints
- `POST /chat/completions` — Chat completions API
- `GET /v1/models` — List available models
- `GET /health` — Health check

## Notes
- You must build the project once before running it (`cargo build --release`).
- The server runs locally on port 5011 by default.
- For production, run behind a TLS proxy (e.g., Nginx, Caddy) for HTTPS support.

## License
MIT

## Contributing
Pull requests and issues are welcome!
