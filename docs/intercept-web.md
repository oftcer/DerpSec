# Intercept Web

O **Intercept Web** é o painel de trabalho do DerpSec: uma página servida
localmente, aberta dentro de uma janela de navegador dedicada em **modo app**
(sem barra de endereço e sem abas do navegador). O navegador já sobe apontando
para o proxy, com um perfil isolado (`%APPDATA%\DerpSec\webprofile`), então você
não precisa mexer no proxy do Windows nem no seu navegador pessoal.

![Histórico do console](../screenshots/02-console-historico.png)

## Como abrir

1. No aplicativo, clique em **Intercept Web**.
2. O motor sobe o proxy e o console, e o navegador virtual abre na bancada.
3. No topo, a barra de status mostra `proxy ON : <porta>`, o contador de
   transações e a fila de interceptação.

Se preferir usar o seu próprio navegador, configure o proxy manualmente em
`127.0.0.1:<porta>` e abra a URL do console exibida no log do aplicativo.

## Layout

A bancada é dividida em dois painéis com uma **divisória arrastável**:

| Painel | Conteúdo |
|---|---|
| Esquerda | Navegador real embutido (`iframe`) que passa pelo proxy: barra de endereço, voltar/avançar/recarregar/início e abas de navegação |
| Direita | Ferramentas: **Histórico**, **Interceptar**, **Repeater**, **Escopo** e **Log** |

A barra de endereço acompanha a navegação dentro do `iframe` (via `postMessage`),
sem recarregar a página nem entrar em loop de navegação.

## Abas

### Histórico

![Histórico e detalhe da transação](../screenshots/03-console-detalhe.png)

Lista todas as transações passadas pelo proxy. Por padrão as linhas vêm
**agrupadas por `host:porta`** em grupos que abrem e fecham; desmarque o
agrupamento para ver a lista corrida em ordem cronológica.

- O campo de filtro aceita um trecho de **host** ou **caminho** (por exemplo
  `example-domains`) e age enquanto você digita.
- Clicar em uma linha abre o painel de detalhe com a **requisição** e a
  **resposta** cruas lado a lado; corpos comprimidos aparecem decodificados.
- O detalhe não fecha sozinho quando novas transações chegam — você pode ler
  com calma enquanto o histórico continua atualizando.

### Interceptar

![Fila de interceptação](../screenshots/04-console-interceptar.png)

Segura requisições (e, se você ligar, respostas) na fila para inspeção antes de
irem para o servidor. Para cada item dá para **Encaminhar**, **Editar** ou
**Descartar**, além de **Encaminhar tudo**.

Um detalhe importante: se você estiver editando um item e uma nova mensagem
chegar na fila, **a sua edição em andamento é preservada** — a lista não
sobrescreve o texto que você está mexendo.

### Repeater

![Repeater](../screenshots/05-console-repeater.png)

Monta uma requisição HTTP crua e reenvia quantas vezes quiser. O campo *Host*
pode ficar vazio para usar o cabeçalho `Host` da própria requisição; a porta
fica em `auto` para deduzir 80/443 pelo esquema.

Use o Repeater para testar variações de método, cabeçalhos e corpo sem depender
do navegador.

### Escopo

![Escopo](../screenshots/06-console-escopo.png)

Um padrão por linha (`host`, domínio ou parte do caminho). Com *Interceptar
somente o escopo* ligado, apenas as requisições que casarem com algum padrão são
processadas; curingas como `*.exemplo.com` são aceitos.

### Log

Eventos do motor em tempo real (subida/parada do proxy, erros de TLS, conexões
recusadas). Útil para diagnosticar um site que não carrega.

## Opções do painel

- **Filtrar telemetria** (ligado por padrão) — o tráfego de fundo do Windows e do
  Edge (telemetria, atualizações, anúncios) continua aparecendo no histórico,
  mas **nunca é segurado** na fila de interceptação. Sem isso, a fila enche de
  ruído e a navegação trava.
- **Embutir sites** (ligado por padrão) — remove `X-Frame-Options` e a diretiva
  `frame-ancestors` do CSP das respostas HTML, para que o site apareça dentro do
  painel esquerdo. Desligue para ver as respostas exatamente como o servidor
  enviou; muitos sites vão recusar aparecer no `iframe`.
- **Interceptar requisições** / **Interceptar respostas** — controlam o que é
  segurado.
- **Interceptar somente o escopo** — aplica os padrões da aba Escopo.
- **Iniciar** / **Parar** o proxy — as mudanças refletem na janela do
  aplicativo e são salvas em `config.json`.

## Segurança do console

O console só escuta em `127.0.0.1`, em uma porta efêmera, e exige um **token
aleatório por sessão** em cada chamada de API. O cabeçalho `Host` também é
validado. Isso impede que outra página aberta no mesmo computador converse com o
console e reduz o risco de *DNS rebinding*.

## Encerrando

Feche a janela do navegador virtual ou clique em **Parar** no console. O
aplicativo encerra o navegador e o proxy; a CA pode ser removida com:

```
certutil -delstore Root derpsec
```
