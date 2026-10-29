# Agente Getping 0.0.4

Coleta de hostname, usuário, IP IPv4, sistema operacional, identidade e ping LAN/WAN.
O arquivo principal mantém o nome `PyAgent_stable_v0.2.py` para facilitar a substituição
em instalações existentes. O servidor não foi alterado.

## Instalação e execução

Requer Python 3.9 ou superior e as dependências de `requirements.txt`.
Windows: PowerShell com os comandos `Get-CimInstance` e `Find-NetRoute` disponíveis.
Linux: utilitários `ip` (iproute2) e `ping` (iputils), e `/etc/machine-id` válido.
Outros sistemas operacionais não têm política de identidade implementada.

```bash
python -m venv .venv
# Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Se já houver `config.ini`, preserve-o. Para uma instalação nova, copie
`config.ini.example` para `config.ini` e preencha URL e token. Execute:

```bash
python PyAgent_stable_v0.2.py
```

O arquivo de configuração é localizado ao lado do script ou do executável congelado,
independentemente do diretório de trabalho. Configuração inválida encerra com código 2;
não existe fallback para um servidor embutido. O intervalo permitido é de 5 a 86400
segundos. `ip_teste_wan` deve ser um endereço IPv4 unicast, não um hostname.

HTTP continua permitido para compatibilidade com o Getping atual, com aviso no log.
Quando HTTPS estiver disponível no servidor, altere somente a URL. A verificação do
certificado permanece habilitada. Para uma autoridade certificadora interna, configure
`REQUESTS_CA_BUNDLE` no ambiente do processo. Não desabilite a validação TLS.

## Identidade e atualização de instalações

Na primeira coleta válida, o agente grava `machine_identity.json` ao lado do script.
Windows usa o UUID obtido por `Win32_ComputerSystemProduct`; Linux usa o conteúdo de
`/etc/machine-id`. O formato e a caixa do valor são preservados para manter os IDs
usados pelo agente anterior. O arquivo passa a ser a fonte de identidade nos reinícios.
Uma falha temporária no WMI não provoca troca para MAC. Um UUID inválido ou falha na
persistência impede o envio daquela amostra, com novas tentativas e log.

**Antes de atualizar uma máquina já cadastrada, confira o `machine_uuid` no Getping.**
Se a versão anterior usou o fallback de MAC, o UUID de hardware pode ser diferente.
Para preservar aquele cadastro, crie `machine_identity.json` com o ID exato já registrado:

```json
{"machine_uuid": "UUID_VALIDO_JA_CADASTRADO"}
```

A aplicação exige UUID válido, diferente de todos zeros ou todos `f`. Caso o cadastro
antigo tenha um ID inválido, a regularização depende do servidor. Não apague nem altere
a identidade persistida durante atualizações comuns. Em imagens clonadas, não distribua
esse arquivo e garanta que UUID/machine-id dos clones sejam distintos. A solução ainda
não implementa matrícula no servidor nem corrige colisões de identidade em clones.
Use somente uma instância do agente por diretório de instalação.

O usuário de execução precisa de permissão de escrita no diretório para persistir a
identidade e os logs. Restrinja a escrita nesse diretório e a leitura do token às contas
responsáveis. Para instalação em `Program Files`, conceda as permissões necessárias à
conta do agente ou use um diretório de aplicação apropriado.

## Compatibilidade e comportamento

Os nove campos originais e a autenticação são preservados. Para o servidor atualizado,
são enviados também três campos de controle:

- `hostname`, `user_logon`, `ip_local`, `system_operacional`, `machine_uuid`: strings.
- `status_lan`, `status_wan`: booleanos.
- `time_ms_lan`, `time_ms_wan`: inteiros ou `null`.
- `medido_em`: instante de coleta em UTC (ISO 8601 com fuso).
- `boot_id`: UUID novo por execução do processo; `sequencia`: inteiro crescente por amostra.
- Cabeçalho `Authorization: Bearer <token>`; endpoint definido no `config.ini`.

Respostas HTTP 2xx são consideradas aceitas, exceto quando o JSON indica `aceito=false`.
Nesse caso, a amostra foi descartada e o agente registra o diagnóstico. Servidores
antigos que não retornam `aceito` continuam compatíveis; o HTTP isoladamente não
comprova persistência no banco. Redirecionamentos são recusados.
401/403 geram espera de pelo menos 5 minutos; demais falhas usam espera progressiva
com variação aleatória. 429/503 respeitam `Retry-After` em segundos ou data HTTP,
limitado a 24 horas para evitar suspensões indefinidas por cabeçalhos incorretos.
Não há repetição imediata do mesmo POST. Não há fila persistente: cada tentativa coleta
uma amostra atual, com nova sequência e horário de medição.

IP e gateway são obtidos da mesma rota IPv4 até `ip_teste_wan`, inclusive quando uma
VPN assume essa rota. Não se interpreta a saída localizada do `ipconfig`, eliminando
a corrupção de gateways IPv6. O diagnóstico continua sendo IPv4; conectividade IPv6
nativa não é enviada. Rota direta sem gateway deixa o teste LAN falso.
Falha de coleta de rota retorna IP `Desconhecido` e LAN falsa; WAN é testada separadamente.
ICMP bloqueado pode produzir falso mesmo com acesso HTTP disponível. Os booleanos
atuais não distinguem falha de rede de falha de coleta; novos estados dependem do servidor.

O ping reconhece `time`/`tempo` e exige resposta de latência válida. Mantém inteiros para
compatibilidade: frações são arredondadas, com mínimo de 1 ms, e `<1 ms` é reportado como
1 ms. Outros idiomas podem produzir diagnóstico indisponível/falso.

No Windows, prefere-se a sessão ativa do console; sem ela, a primeira sessão RDP ativa
por ID. Só um usuário é enviado. Sessões desconectadas não são escolhidas. Sem sessões
ativas retorna `Nenhum usuário logado`. Tela bloqueada não implica ausência de usuário.
No Linux, `user_logon` continua sendo o usuário do processo, inclusive a conta do serviço.

Identidade é armazenada em memória; sistema operacional é atualizado a cada hora.
A rota é consultada em todos os ciclos para detectar mudanças de VPN/interface.
Os pings permanecem sequenciais, cada um com limite de 3 segundos; comandos comuns têm
limite de 5 segundos e PowerShell de 10 segundos. Requisições usam timeout de conexão
3,05 s e leitura 5 s. Esses limites HTTP não são um prazo total para toda a requisição.

O agendamento usa relógio monotônico. Em sucesso, desconta o tempo de execução do
intervalo; em falha, espera o período de recuperação após concluir o ciclo. Ciclos
atrasados não são compensados com rajadas. Há atraso inicial aleatório de até 10 segundos.

## Logs e execução contínua

Logs vão para o console e `agent.log`, com rotação de aproximadamente 2 MB e três backups.
Se não for possível abrir o arquivo, o console continua disponível. Token, payload,
corpo da resposta e texto bruto das exceções de rede não são registrados.
Para encerrar no terminal, use Ctrl+C.

O script não é um serviço nativo do Windows. Para execução contínua, configure uma tarefa
no Agendador de Tarefas ao iniciar o computador, usando o caminho absoluto do Python da
venv e o caminho absoluto do script como argumento. Configure reinício após falha,
desative limite de duração e escolha não iniciar nova instância se já estiver rodando.
Valide o acesso a WMI, WTS, rede e diretório com a conta escolhida. Não é necessário
usar administrador apenas para executar o agente; permissões dependem do ambiente.

No Linux, use um gerenciador como systemd com `ExecStart` apontando para o Python da
venv e o script, `Restart=on-failure` e `RestartSec=10`. Configure `RestartPreventExitStatus=2`
para não reiniciar continuamente com configuração inválida. Use uma conta dedicada
com acesso ao diretório e permissão de executar ping. Interrupção SIGTERM usa o
encerramento padrão do processo; Ctrl+C fecha explicitamente a sessão HTTP.

## Validação

```bash
python -m unittest discover -s tests -v
```

Os testes não chamam o Getping nem executam comandos reais do sistema. Cobrem
configuração, identidade persistente, timeouts, rotas estruturadas, ping, payload,
autenticação, respostas HTTP e recuperação. O transporte Requests também é exercitado
com adaptador em memória. O ambiente de desenvolvimento original tinha Requests 2.31;
para implantação instale o requisito atualizado do projeto.

Antes de distribuir, faça uma homologação Windows com console/RDP, execução pela conta
da tarefa, VPN, mudança de interface, perda de rede e reinício do servidor. Confirme que
o mesmo cadastro é atualizado. APIs Windows e integração com servidor real precisam
dessa validação; testes simulados não as substituem.

Documentação das APIs utilizadas:
- [Find-NetRoute](https://learn.microsoft.com/powershell/module/nettcpip/find-netroute)
- [WTSEnumerateSessionsW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsw)
- [Requests: sessões](https://requests.readthedocs.io/en/stable/user/advanced/)

## Dependências do trabalho futuro no servidor

HTTPS no endpoint; matrícula/credenciais por agente; migração de identidade quando
necessária; versão no payload; estados de coleta detalhados; confirmação
de persistência; fila de histórico e deduplicação. Nenhuma dessas mudanças foi exigida
pela versão atual do agente.


## Getping atualizado: vinculação obrigatória

A análise do projeto `getping_v0.0.4` confirmou que um token só pode pertencer a um
equipamento. Um host existente sem vínculo não pode se vincular automaticamente.
O agente não tenta contornar esse controle nem alterar o cadastro remotamente.

Para o erro `Host legado exige vinculação administrativa.`, o administrador deve:

1. Confirmar o UUID exato do cadastro e de `machine_identity.json` nesta máquina.
2. Criar/escolher uma credencial exclusiva para a máquina em Configurações.
3. No ambiente do servidor, com o banco operacional correto configurado, executar:

   ```bash
   python manage.py bind-agent UUID_DO_HOST ID_NUMERICO_DO_TOKEN
   ```

4. Colocar o **valor secreto do token**, não seu ID nem o texto mascarado da tela,
   em `config.ini` do agente e reiniciar o agente.

Esse comando não foi executado pela correção do agente. Ele pode substituir um vínculo
anterior do host; confira UUID e ID antes de executá-lo e use a configuração de banco
correta da instalação. Se aparecer `Token vinculado a outro dispositivo.`, use outra
credencial exclusiva. Não troque o UUID da máquina para tentar evitar a restrição.

Após um host enviar `boot_id`/`sequencia`, o servidor exige esses campos nas próximas
amostras. Voltar a um agente antigo sem esses campos passará a produzir HTTP 400.
Mantenha relógios sincronizados: `medido_em` é validado contra a janela do servidor.

Os logs reconhecem os motivos conhecidos de recusa sem registrar o corpo bruto da
resposta. Para validar as regras reais da função de persistência do servidor com
SQLite em memória (licença e aplicação de métricas simuladas), use no Linux:

```bash
GETPING_SERVER_SOURCE=/caminho/getping_v0.0.4 python -m unittest discover -s tests -v
```

Isso não inicia Flask, não lê o banco operacional e não substitui uma integração
completa. Sem essa variável, os testes opcionais do servidor são ignorados.

## ConnectionError / SSLError após ativar HTTPS no servidor

O instalador HTTPS do Getping publica Nginx na porta 443 e restringe o backend HTTP
à interface `127.0.0.1:5000`. Nos agentes remotos use:

```ini
[servidor]
url = https://IP_DO_SERVIDOR/informacoes_agent
certificado_ca = getping-server.crt
token = TOKEN_REAL_DESTE_DISPOSITIVO
intervalo = 20

[rede]
ip_teste_wan = 8.8.8.8
```

Para a CA local criada pelo instalador, copie somente o certificado público
`/etc/getping/getping-server.crt` do servidor para junto do `config.ini` do agente.
`certificado_ca` também aceita caminho absoluto. Essa opção fornece explicitamente
a confiança ao Requests, inclusive quando o Python não usa o repositório de certificados
do Windows. Alternativamente, sem essa opção, use `REQUESTS_CA_BUNDLE`.
Para certificado público confiável, normalmente não é preciso definir a opção.
O caminho da CA é validado na inicialização; o conteúdo/cadeia são validados na conexão.

Não use `https://IP:5000`: essa é a porta HTTP do backend. O IP ou nome usado na URL
precisa corresponder ao SAN do certificado. `SSLError` também pode indicar cadeia
inválida, certificado expirado ou protocolo/porta incompatível; o tipo de erro isolado
não identifica a causa exata. `ConnectionError` pede verificar serviço, resolução,
porta e firewall. Os diagnósticos não imprimem o texto bruto dessas exceções.
