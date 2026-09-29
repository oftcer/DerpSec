# Changelog

## 1.4.0

Versão publicada no GitHub. O foco foi deixar o **Intercept Web** estável no dia
a dia: abrir, navegar e fechar sem travar, sem deixar processo pendurado e sem
perder o trabalho em andamento.

**Correções**

- **Intercept Web abria e fechava sozinho.** O navegador virtual agora espera o
  perfil ficar livre antes de subir (`_wait_profile_free`) e encerra instâncias
  antigas do mesmo perfil (`_kill_stale`) em vez de abrir uma segunda janela
  sobre um perfil travado.
- **O navegador ficava aberto depois de parar o proxy.** Ao parar o motor, o
  navegador virtual é fechado junto (`VirtualBrowser.close`), sem sobrar processo
  consumindo o perfil.
- **Navegação não seguia o mouse / janela não respondia.** O estado do proxy na
  barra de status da GUI passou a ser atualizado pela thread principal do
  Tkinter (`App._ui`), e o motor publica os eventos de forma serializada — a
  janela continua respondendo enquanto há tráfego.
- **Divisória do console não arrastava.** O cálculo do arrasto foi corrigido
  para não brigar com a atualização automática da lista.
- Ajustes de robustez no encerramento: sockets e conexões seguradas são
  liberados ao parar o proxy, evitando threads presas.

**Outros**

- Versão do pacote (`intercepta.__version__`) alinhada com a versão exibida pelo
  aplicativo.
- Documentação: README com capturas reais, `docs/arquitetura.md`,
  `docs/intercept-web.md` e `docs/testes.md`.

## Histórico anterior

As versões até 1.3.0 foram desenvolvimento interno, sem registro de changelog.
O que existia antes desta versão: proxy HTTP/HTTPS com MITM por CA local,
interceptação de requisições e respostas, histórico, Repeater, escopo, filtro de
telemetria e a bancada web do Intercept Web.
