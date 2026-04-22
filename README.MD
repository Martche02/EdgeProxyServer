# EdgeProxyServer

`EdgeProxyServer` is a local C++ proxy that protects proprietary identifiers before traffic is sent to cloud LLM endpoints.

It masks sensitive terms in outgoing requests, forwards the request to the configured upstream service, then restores original terms in returned responses.

## What it does

1. Loads a local vault map (`real -> masked` and reverse lookup).
2. Starts an HTTP proxy server.
3. Intercepts request payloads and sanitizes sensitive values.
4. Forwards traffic to upstream endpoints.
5. Restores original values in response payloads before returning them to clients.

## Main routes handled

- `POST /v1/chat/completions`
- `POST /chat/completions`
- `GET /models`
- `POST /responses`
- `POST /mcp/readonly`
- `GET /agents/swe/internal/memory/v0/user/enabled`
- `GET /ping` (health check)
- Catch-all fallback forwards unmapped routes (except `CONNECT`, which is rejected with `405`)

## Environment variables

- `OPENAI_API_KEY` (**required**) - bearer token used for upstream calls
- `PROXY_PORT` (optional, default: `8080`) - local listen port
- `TARGET_MODEL` (optional, no default) - if set, forcibly injects/overrides the model in chat completion payloads; if unset, proxy keeps the model chosen by the Copilot client

Vault path:

- `%TEMP%\ip_vault_map.json` (fallback: `C:\Temp\ip_vault_map.json`)

## Vault file format

Example `ip_vault_map.json`:

```json
{
  "CustomerA": "ENTITY_001",
  "InternalServiceX": "ENTITY_002",
  "10.20.30.40": "IP_001"
}
```

## Build requirements

- Windows
- Visual Studio 2022 (C++ toolset)
- OpenSSL package referenced by the project (`openssl-vc140-vc141-x86_64`, via NuGet `packages.config`)

## Build and run

Using Visual Studio:

1. Open `EdgeProxyServer.slnx`
2. Restore NuGet packages
3. Build `x64` (`Debug` or `Release`)
4. Run the generated executable

PowerShell example (runtime variables):

```powershell
$env:OPENAI_API_KEY = "your_token_here"
$env:PROXY_PORT = "8080"
# Optional: uncomment to force all requests to one model
# $env:TARGET_MODEL = "gpt-4o"
```

Then verify:

```powershell
Invoke-WebRequest http://localhost:8080/ping
```

Expected body: `Proxy vivo!`

## Notes

- The proxy performs regex-based masking/restoration using vault keys.
- For transparent forwarding paths, request and response bodies are sanitized/restored as raw payload text.
- Upstream targets in current implementation include:
  - `api.githubcopilot.com`
  - `models.inference.ai.azure.com`
