# enumServices

Coletor forense e de seguranca de servicos do Windows escrito em C.

O programa enumera o Service Control Manager (SCM), correlaciona processos,
analisa executaveis e DLLs, verifica hashes SHA-256 e assinaturas digitais,
e identifica configuracoes que podem permitir DLL hijacking ou escalacao de
privilegios.

Todas as saidas sao gravadas em UTF-8 e podem ser exibidas como tabela, CSV
ou JSON.

## Recursos

### Inventario

- Nome, estado, PID e tipo do servico
- Tipo de inicializacao e conta configurada
- Status da consulta de configuracao

### Modo forense

Ativado com `--forense`:

- Correlacao entre processos e servicos
- Configuracao completa dos servicos
- Caminho do executavel e `ServiceDll` usado por svchost
- SHA-256 dos binarios
- Verificacao de assinatura embutida e por catalogo
- Caminhos de servico sem aspas
- Executaveis e DLLs ausentes, nao assinados ou suspeitos

### Modo de vulnerabilidades

Ativado com `--vuln-scan`:

- Hardening de DLL/MSI no registro
- Entradas Run e RunOnce
- Diretorios gravaveis ou ausentes no `PATH`
- Permissoes de tarefas agendadas
- ACLs permissivas em servicos e chaves de registro
- Binarios e DLLs gravaveis
- Possibilidade de DLL hijacking

Os modos `--forense` e `--vuln-scan` podem ser combinados.

## Requisitos

- Windows Vista ou superior
- Microsoft Visual C++ Developer Command Prompt
- Ambiente x64 recomendado
- Privilégios administrativos recomendados
- Coleta remota: acesso ao SCM, registro e compartilhamentos administrativos

## Compilacao

Execute no Developer Command Prompt for Visual Studio:

```bat
cl /nologo /W3 /O2 /DUNICODE /D_UNICODE enumServices.c /link /OUT:enumServices.exe
```

O codigo vincula `advapi32`, `bcrypt`, `crypt32` e `wintrust`.

## Uso

```text
enumServices.exe [opcoes]
```

| Opcao | Descricao |
|---|---|
| `-f`, `--format <table\|csv\|json>` | Formato da saida; padrao `table` |
| `-o`, `--out <arquivo>` | Grava a saida em arquivo UTF-8 |
| `-t`, `--target <host\|ip>` | Executa coleta remota |
| `-u`, `--user <[DOMINIO\]usuario>` | Usuario para acesso remoto |
| `-p`, `--password <senha>` | Senha remota |
| `--no-hash` | Nao calcula SHA-256 |
| `--no-sig` | Nao verifica assinaturas digitais |
| `--forense` | Ativa a coleta forense |
| `--vuln-scan` | Ativa verificacoes de vulnerabilidade |
| `-h`, `--help` | Exibe a ajuda |

Sem `--forense` ou `--vuln-scan`, o programa retorna somente o inventario.

## Exemplos

Inventario local:

```bat
enumServices.exe
```

Coleta forense:

```bat
enumServices.exe --forense
```

Coleta forense e vulnerabilidade em JSON:

```bat
enumServices.exe --forense --vuln-scan --format json --out resultado.json
```

Coleta CSV sem hash ou verificacao de assinatura:

```bat
enumServices.exe --forense --no-hash --no-sig --format csv --out resultado.csv
```

Coleta remota:

```bat
enumServices.exe --target server01 --user DOMINIO\analista --password "senha"
```

Para solicitar a senha interativamente:

```bat
enumServices.exe --target 192.168.1.10 --user DOMINIO\analista --forense
```

## Formatos de saida

### Tabela

Formato padrao para leitura no terminal.

### CSV

Use `--format csv`. Os registros sao separados por secoes e os campos sao
delimitados por aspas.

### JSON

Use `--format json`. A saida inclui metadados da coleta e os conjuntos de dados
dos modos selecionados.

Mensagens de progresso sao escritas em `stderr`. Use `--out` para gravar somente
o resultado em um arquivo.

## Coleta remota

- Os processos remotos sao correlacionados pela configuracao dos servicos, nao
  por um enumerador live de processos.
- Catalogos de assinatura nao sao consultados no modo remoto.
- Entradas HKCU nao sao examinadas pelo scan de vulnerabilidades.
- Acesso a ACLs e arquivos pode ficar parcial sem permissoes ou
  compartilhamentos administrativos.

## Codigos de saida

- `0`: enumeracao concluida
- `1`: falha de acesso, memoria, arquivo ou enumeracao incompleta
- `2`: argumento invalido ou combinacao incorreta

## Consideracoes

Os resultados sao indicativos e devem ser validados antes de conclusoes.
As verificacoes de ACL consideram permissões concedidas a `Everyone`,
`Authenticated Users`, `BUILTIN\Users` e `INTERACTIVE`.

Execute a ferramenta apenas em sistemas autorizados e revise os dados antes de
exportar nomes de contas, caminhos ou detalhes da infraestrutura.
