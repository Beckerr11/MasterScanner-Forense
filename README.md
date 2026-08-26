# MasterScanner Forense

Ferramenta experimental de **análise defensiva e triagem forense para Windows**, escrita em Python, que reúne inspeção de processos, regiões de memória e drivers carregados em uma interface de scanner única.

> **Escopo importante:** este projeto usa técnicas e heurísticas de **user mode**. Ele não substitui um EDR/antivírus, uma suíte forense profissional nem um driver de kernel. Um achado significa **“merece investigação”**, não “malware confirmado”.

## Objetivos do projeto

- praticar integração com APIs do Windows via Python/`ctypes`;
- investigar processos e regiões de memória de forma defensiva;
- produzir evidências que possam ser revisadas posteriormente;
- estudar limitações de detecção em user mode;
- separar **heurística**, **placeholder de pesquisa** e **evidência observada**.

## Componentes

| Arquivo | Responsabilidade |
| --- | --- |
| `master_scanner.py` | Orquestra as etapas do scanner |
| `deep_memory_scanner.py` | Inspeciona memória de processos e sinaliza regiões com características suspeitas |
| `memory_dumper.py` | Auxilia na coleta de regiões de memória para análise posterior |
| `kernel_rootkit_detector.py` | Enumera drivers e reúne verificações experimentais relacionadas a rootkits |

## Modelo de evidência

O projeto evita tratar toda anomalia como comprometimento confirmado.

Exemplos:

- uma região de memória com permissões incomuns pode ser legítima;
- um driver de terceiro fora de caminhos esperados pode ser legítimo;
- verificar SSDT/DKOM de forma confiável **não é possível apenas com as APIs de user mode usadas aqui**;
- as rotinas de SSDT e processos ocultos presentes no projeto são explicitamente **placeholders de pesquisa**, não detectores de kernel completos.

## Requisitos

- Windows
- Python 3
- dependências de `requirements.txt`
- alguns recursos podem exigir execução com privilégios elevados para obter visibilidade suficiente do sistema

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python master_scanner.py
```

## Dependências

O projeto utiliza principalmente:

- `psutil`
- `python-evtx`
- biblioteca padrão do Python (`ctypes`, `json`, `os`, entre outras)

## Limitações conhecidas

- análise de kernel feita a partir de user mode possui visibilidade limitada;
- a classificação de drivers usa heurísticas e não equivale a uma validação completa via `WinVerifyTrust`;
- SSDT hooking e DKOM exigem técnicas de kernel/forense mais robustas para confirmação;
- falsos positivos são possíveis;
- resultados devem ser correlacionados com outras fontes antes de qualquer conclusão.

## Uso responsável

Use somente em sistemas que você possui ou tem autorização para analisar. O projeto é voltado a **aprendizado, defesa e investigação local autorizada**.

## Próximos passos

- adicionar testes automatizados para parsers e classificadores;
- separar coleta de evidência da classificação heurística;
- gerar relatório JSON estruturado com níveis de confiança;
- validar assinatura digital de drivers de forma apropriada;
- adicionar fixtures reproduzíveis para testes sem depender de uma máquina comprometida;
- documentar cadeia de custódia e integridade dos dumps.

---

**Status:** projeto experimental de pesquisa defensiva. As limitações acima fazem parte explícita do modelo de confiança da ferramenta.
