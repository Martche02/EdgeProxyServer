Guia de Execução: EdgeProxyServer

## Execução em 1 comando

No terminal (CMD), na pasta do executável:

```bat
EdgeProxyServer.exe --api-Key <SUA_API_KEY>
```

Com isso, o app:

1. Sobe o proxy local.
2. Sobe o proxy em **background oculto** (sem abrir janela extra).
3. Configura `HTTPS_PROXY` para o Copilot automaticamente.
4. Inicia o Copilot CLI no **mesmo terminal** em que você executou o comando.
5. Aplica `NO_PROXY` para hosts de autenticação GitHub (evita erros de auth por `CONNECT`), mantendo o tráfego de conteúdo no proxy.

## Opções úteis

```bat
EdgeProxyServer.exe --api-Key <SUA_API_KEY> --model gpt-5.4-mini
EdgeProxyServer.exe --api-Key <SUA_API_KEY> --port 8090
EdgeProxyServer.exe --api-Key <SUA_API_KEY> --no-copilot
EdgeProxyServer.exe --help
```

## Observações

- O log do proxy fica em `%TEMP%\copilot_proxy_traffic.log`.
- O log de inicialização automática do Copilot fica em:
  - `%TEMP%\copilot_autostart_out.txt`
  - `%TEMP%\copilot_autostart_err.txt`
