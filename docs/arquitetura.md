# Arquitetura

O DerpSec é um proxy de interceptação HTTP/HTTPS escrito em Python, com interface
desktop em Tkinter e uma bancada web embutida (o *Intercept Web*). Não há
dependências de rede externas: tudo roda em `127.0.0.1`.

## Visão geral

```
                    +--------------------------------------------+
                    |                 DerpSec                    |
                    |                                            |
  navegador  ---->  |  ProxyEngine  ----  CertAuthority          |
  (Edge/Chrome      |   (engine.py)        (certs.py)           |
   modo app)        |        |                                   |
                    |        |  Transaction / Held               |
                    |        v                                   |
                    |   HttpMsg (httpmsg.py)  ->  parse/serialize|
                    |        |                                   |
                    |        +--> GUI Tkinter   (gui.py)         |
                    |        +--> WebConsole    (webconsole.py)  |
                    +--------------------------------------------+
                              ^                    ^
                              |                    |
                     janela do app          API + HTML do console
```

Todos os componentes conversam por estruturas em memória (`Transaction`,
`Held`) protegidas por um `threading.Lock` no motor. A GUI e o console web
apenas **leem** esse estado e enviam comandos (iniciar/parar proxy, definir
escopo, encaminhar item segurado, reenviar via repeater).

## Módulos

| Arquivo | Responsabilidade |
|---|---|
| `main.py` | Ponto de entrada. Cria o diretório de dados e abre a `App`. |
| `intercepta/gui.py` | Interface Tkinter: abas Proxy/Histórico, Interceptar, Repeater, Escopo, CA & Config e Log. Também guarda a configuração em `config.json`. |
| `intercepta/engine.py` | Motor do proxy: aceita conexões, detecta `CONNECT` para HTTPS, faz o MITM, aplica escopo e filtro de telemetria, mantém histórico e a fila de itens segurados. |
| `intercepta/certs.py` | Autoridade certificadora local (`CertAuthority`): cria a CA na primeira execução e gera/assina certificados folha por host, com cache em disco. |
| `intercepta/httpmsg.py` | Leitura e escrita de HTTP cru: cabeçalhos, corpo, `Content-Length`, `Transfer-Encoding: chunked`, decodificação de gzip/deflate/br e formatação “bonita”. |
| `intercepta/webconsole.py` | Servidor HTTP local que serve a bancada web (HTML/CSS/JS) e a API JSON consumida por ela. |
| `intercepta/browser.py` | Navegador virtual: localiza Edge/Chrome, cria perfil dedicado, limpa instâncias antigas (`_kill_stale`), abre em modo app apontando para o proxy e encerra ao fechar. |
| `intercepta/__init__.py` | Metadados do pacote (versão). |

## Fluxo de uma requisição

1. `ProxyEngine._accept_loop` aceita a conexão e entrega para `_handle_client`.
2. Se o método é `CONNECT`, o motor responde `200 Connection Established`, faz o
   handshake TLS com o cliente usando um certificado folha da CA local e passa a
   falar HTTP em claro com ele.
3. `HttpMsg` lê o cabeçalho de requisição, resolve o corpo (inclusive chunked) e
   monta um objeto `Transaction` com método, host, porta, caminho e cabeçalhos.
4. Escopo e filtro de telemetria decidem se a transação é processada normalmente.
5. Se **Interceptar requisições** estiver ligado e a transação não for ruído, ela
   vira um `Held` e fica parada até `decide(...)` (encaminhar / editar /
   descartar) ou `release_all()`.
6. A requisição (possivelmente editada) é enviada ao servidor de destino em uma
   conexão TCP/TLS nova, e a resposta é lida por `httpmsg.read_response`.
7. Se **Interceptar respostas** estiver ligado, a resposta também pode ser
   segurada.
8. A transação é publicada no histórico e um evento é emitido; a GUI e o console
   web atualizam as suas listas.

## Intercept Web (bancada web)

O `WebConsole` sobe um `ThreadingHTTPServer` em uma porta efêmera de `127.0.0.1`
e gera um **token aleatório por sessão** (`secrets.token_urlsafe`). Todas as
rotas exigem esse token e o cabeçalho `Host` é validado, o que evita sequestro
de sessão local e *DNS rebinding*.

A página é um HTML único com CSS e JS embutidos, dividida em dois painéis
separados por uma divisória arrastável:

- **Esquerda**: barra de endereço, botões voltar/avançar/recarregar/início, abas
  de navegação e o site carregado dentro de um `iframe` (que passa pelo proxy).
- **Direita**: abas Histórico, Interceptar, Repeater, Escopo e Log.

A API exposta ao front-end:

| Rota | Método | Função |
|---|---|---|
| `/api/state` | GET | Estado atual (proxy ligado, porta, flags, contadores) |
| `/api/history` | GET | Histórico, opcionalmente filtrado por `?q=` |
| `/api/tx` | GET | Requisição e resposta cruas de uma transação (`?id=`) |
| `/api/clear` | POST | Limpa o histórico |
| `/api/held` | GET/POST | Lista a fila / encaminha, edita, descarta ou encaminha tudo |
| `/api/flags` | POST | Liga/desliga interceptação, escopo, embutir sites e filtro de telemetria |
| `/api/repeater` | POST | Envia uma requisição bruta |
| `/api/scope` | GET/POST | Lê e grava os padrões de escopo |
| `/api/log` | GET/POST | Lê e limpa o log do motor |
| `/api/proxy` | POST | Inicia ou para o proxy |

Detalhes de cada aba e das opções estão em [intercept-web.md](intercept-web.md).

## Persistência e isolamento

Nada sai da máquina. O estado vive em `%APPDATA%\DerpSec`:

- `config.json` — porta, opções e flags.
- `ca/` — chave e certificado da CA e o cache de certificados folha.
- `webprofile/` — perfil do navegador virtual, separado do navegador pessoal.

Na primeira execução o aplicativo migra automaticamente os dados do diretório
antigo `%APPDATA%\Intercepta`, se existir.

## Por que threads e não assíncrono

O motor precisa lidar com conexões que ficam **paradas de propósito** (itens
segurados na fila de interceptação) sem travar o resto. Uma thread por conexão,
com bloqueio em `threading.Event` para os itens segurados, mantém o código
simples e deixa a GUI responsiva — a GUI usa `App._ui(fn)` para marshalar
qualquer atualização de widget para a thread principal do Tkinter.
