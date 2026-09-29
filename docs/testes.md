# Testes

A suíte é feita de scripts independentes, sem framework externo. Cada um sobe as
partes que precisa, roda as verificações e termina com código de saída `0` em
caso de sucesso.

```bash
python tests/selftest.py   # motor
python tests/webtest.py    # console web / Intercept Web
python tests/guitest.py    # GUI <-> Intercept Web
python tests/realtest.py   # HTTPS real (precisa de internet)
```

## `selftest.py` — motor

Testa o proxy sem depender de internet, falando com servidores locais:

- HTTP simples, incluindo corpo com `Content-Length` e `chunked`;
- MITM de HTTPS com a CA local;
- fila de interceptação: segurar, editar, encaminhar e descartar;
- Repeater com requisição crua;
- aplicação de escopo (dentro e fora);
- filtro de telemetria.

## `webtest.py` — console web

Testes ponta a ponta do Intercept Web: rotas da API, exigência de token, HTML
servido, flags, agrupamento do histórico, fluxo de interceptação, Repeater e
filtro de telemetria.

## `guitest.py` — integração GUI

Verifica a ponte entre a janela Tkinter e o console: carregamento e gravação de
configuração, subida/parada do proxy pelo console, e as rotas `/api/flags` e
`/api/proxy` refletindo na GUI.

## `realtest.py` — HTTPS real

Faz requisições HTTPS de verdade através do proxy (`example.com`,
`api.github.com`) mais uma requisição HTTP. É o único que precisa de internet e
serve para confirmar que o MITM funciona com servidores reais (Cloudflare, etc.).

## Captura de tela

As imagens em [`screenshots/`](../screenshots) são capturas reais do aplicativo
rodando, com tráfego real passando pelo proxy: domínios mantidos para
documentação pela IANA (`example.com`, `example.org`,
`www.iana.org/help/example-domains`) e um serviço local (`127.0.0.1`).
