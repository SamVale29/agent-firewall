[English](README.md) | Português do Brasil

# Agent Firewall

**Uma camada de segurança entre agentes de programação com IA e sua máquina.**

Execute agentes de programação com regras explícitas para acesso ao sistema de arquivos, rede, segredos do ambiente e comandos perigosos.

> O Agent Firewall é uma ferramenta experimental de segurança. Leia o [modelo de segurança](docs/security-model.md) e as [limitações](docs/limitations.md) antes de depender dele em trabalhos sensíveis.

## Por quê?

Agentes de programação podem executar comandos, editar arquivos, acessar variáveis de ambiente, instalar dependências e se comunicar com serviços externos. O Agent Firewall adiciona uma camada local de política e contenção ao redor dessas operações.

O objetivo é gerar confiança por meio de capacidades informadas com precisão:

- o backend Docker/Podman monta explicitamente o repositório e pode desabilitar a rede do contêiner;
- o backend local filtra o ambiente do processo filho e oferece visibilidade, mas não afirma isolar o sistema de arquivos ou a rede do host;
- a avaliação de políticas é determinística, local e independente de qualquer API de IA;
- os registros de auditoria são JSON Lines locais, com redação de segredos e sem telemetria.

## Início rápido

### Instalar a partir do código-fonte

Requer Go 1.22 ou mais recente:

```bash
go install github.com/SamVale29/agent-firewall/cmd/afw@latest
```

### Inicializar e inspecionar uma política

```bash
afw init
afw validate
afw status
```

### Executar um agente

```bash
afw run -- codex
afw run -- claude
```

Use `--mode monitor` quando quiser executar o agente instalado no host com visibilidade e filtragem de variáveis de ambiente. Use `--mode enforce` somente depois de configurar um runtime compatível com Docker e uma imagem de contêiner que contenha o comando a ser executado.

```bash
afw run --mode monitor -- codex
afw run --dry-run -- codex
afw run --non-interactive --ask-policy deny -- npm test
```

## O que ele protege

| Camada | Backend local | Backend de contêiner |
| --- | --- | --- |
| Montagem do repositório | Apenas observado | Bind mount explícito em `/workspace` |
| Sistema de arquivos do host | Não é imposto | Caminhos fora do repositório não são montados por padrão |
| Rede | Não é imposta | Imposta quando `network.default: deny` não possui exceções de domínio |
| Ambiente | Allowlist explícita e padrões de segredos | Allowlist explícita e padrões de segredos |
| Política de comandos perigosos | Análise antes da execução | Análise antes da execução |
| Auditoria | JSONL local | JSONL local |

A análise de comandos é uma camada de visibilidade e aprovação. Ela não é um firewall de syscalls.

## Demonstração

O demo determinístico usa um diretório temporário descartável e nunca toca em credenciais reais:

```bash
bash scripts/demo.sh
```

## Como funciona

```text
Desenvolvedor
    │
    ▼
afw run
    │
    ├── precedência de configuração
    ├── mecanismo de políticas determinístico
    ├── análise de risco e aprovação de shell
    ├── filtragem de ambiente e redação
    ├── seleção de capacidades do backend
    └── sessão de auditoria JSONL local
    │
    ▼
Processo local ou contêiner Docker/Podman
```

Veja [architecture.md](docs/architecture.md) e [backends.md](docs/backends.md) para os detalhes de implementação.

## Configuração

A configuração do repositório fica em `.agent-firewall.yaml`. Uma política global pode ser colocada no caminho de configuração do usuário mostrado por `afw config path`.

A precedência é:

```text
padrões embutidos → política global → política do repositório → flags da CLI
```

Comandos úteis:

```bash
afw config show
afw config path
afw explain path ~/.ssh/id_ed25519
afw explain command -- git clean -fdx
afw logs --last 20
afw logs --session <session-id>
```

## Modelo de segurança

O Agent Firewall reduz o risco de ações destrutivas acidentais, exposição acidental de credenciais e o raio de impacto do repositório quando o backend de contêiner está configurado corretamente. Ele não torna código hostil seguro e não pode criar uma fronteira de sistema de arquivos ou rede no modo local de monitoramento.

Leia:

- [Modelo de segurança](docs/security-model.md)
- [Modelo de ameaças](docs/threat-model.md)
- [Limitações](docs/limitations.md)
- [Reporte de segurança](SECURITY.md)

## Suporte de plataforma

A CLI em Go compila em Linux, macOS e Windows. O backend local é destinado a desenvolvimento e monitoramento nos três sistemas. O isolamento imposto atualmente depende de um runtime compatível com Docker e deve ser testado no sistema operacional de destino; backends nativos para Linux, macOS e Windows estão no roadmap.

## Privacidade

Não existe telemetria. O Agent Firewall não envia histórico de comandos, conteúdo do repositório, valores de ambiente ou logs de auditoria para um serviço. Qualquer telemetria futura deverá ser opt-in explícito.

## Roadmap

- [x] Mecanismo de políticas determinístico com decisões `allow`, `ask` e `deny`
- [x] Filtragem de ambiente e redação de segredos
- [x] Auditoria JSONL local e IDs de sessão
- [x] Fronteira de repositório com Docker/Podman
- [x] Dry run, explain, status, doctor e completions
- [ ] Sandbox nativo de Linux com namespaces/Landlock
- [ ] Backend nativo de sandbox para macOS
- [ ] Backend de isolamento nativo para Windows
- [ ] Proxy MCP de comandos/sistema de arquivos
- [ ] Adaptadores específicos de agentes
- [ ] Imposição de rede por domínio

## Contribuição

Leia [CONTRIBUTING.md](CONTRIBUTING.md) antes de abrir um pull request. Mudanças sensíveis de segurança devem incluir testes de política e uma atualização da documentação de segurança quando as garantias ou limitações mudarem.

## Licença

Apache License 2.0. Veja [LICENSE](LICENSE).
