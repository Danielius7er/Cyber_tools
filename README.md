# 🛡 CyberSec Toolkit

> Toolkit de cibersegurança para linha de comando — detecção de malware, monitoramento de integridade, análise de rede e processos suspeitos.

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![License](https://img.shields.io/badge/Licença-MIT-green)
![Uso](https://img.shields.io/badge/Uso-Ético%20%26%20Educacional-yellow)

---

## ⚠️ Aviso Legal

> Este toolkit foi desenvolvido **exclusivamente para fins educacionais e de defesa cibernética**.  
> Use apenas em sistemas que você possui ou tem autorização explícita para analisar.  
> O uso não autorizado pode violar leis locais e internacionais (Angola — Lei n.º 7/17, RGPD, CFAA, etc.).

---

## 📋 Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| `scan` | Varredura de arquivos com detecção por hashes, strings suspeitas e entropia |
| `integrity` | Baseline + diff de integridade (SHA-256) com modo watch em tempo real |
| `netcheck` | Análise de conexões ativas, portas abertas e indicadores de C2 |
| `processes` | Monitoramento de processos, detecção de mascaramento e PIDs ocultos |
| `audit` | Auditoria completa do sistema (todos os módulos + relatório HTML) |
| `hash` | Cálculo de hash de arquivo com verificação opcional no VirusTotal |
| `db` | Gerenciamento da base de assinaturas de malware |

---

## 🗂️ Estrutura do Projeto

```
cybersec-toolkit/
├── main.py                    # Ponto de entrada CLI (Click)
├── requirements.txt           # Dependências Python
├── config/
│   └── config.yaml            # Configuração principal
├── core/
│   ├── __init__.py
│   ├── utils.py               # Utilitários (hash, config, logging)
│   ├── scanner.py             # Varredura de arquivos (multi-thread)
│   ├── malware_detector.py    # Detecção de malware (hashes + strings + entropia)
│   ├── integrity.py           # Monitoramento de integridade
│   ├── network_analyzer.py    # Análise de conexões de rede
│   ├── process_monitor.py     # Monitoramento de processos
│   └── reporter.py            # Geração de relatórios (JSON/HTML/TXT)
├── scripts/
│   ├── setup.sh               # Instalação e configuração do ambiente
│   ├── quick_scan.sh          # Varredura rápida via bash
│   ├── check_network.sh       # Análise de rede + toolkit
│   ├── monitor_processes.sh   # Monitoramento contínuo de processos
│   ├── baseline.sh            # Gestão de baselines de integridade
│   └── full_audit.sh          # Auditoria completa automatizada
├── data/
│   ├── signatures/
│   │   └── malware_hashes.json   # Base de hashes conhecidos
│   └── baselines/                # Baselines de integridade salvas
├── reports/                       # Relatórios gerados automaticamente
└── logs/                          # Logs de execução
```

---

## 🚀 Instalação

### Requisitos
- Python **3.9+**
- Linux / macOS (Windows com WSL)
- Algumas funcionalidades requerem `sudo` (ex: ver todos os processos)

### Via Script (Recomendado)

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/cybersec-toolkit.git
cd cybersec-toolkit

# Execute o setup
chmod +x scripts/setup.sh
./scripts/setup.sh

# Ative o ambiente virtual
source .venv/bin/activate

# Verifique a instalação
python main.py --help
```

### Manual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py --help
```

---

## 🔍 Exemplos de Uso

### Varredura de Arquivos

```bash
# Varredura rápida no diretório atual
python main.py scan .

# Varredura profunda com relatório HTML salvo
python main.py scan /home/user --deep --output html --save

# Via bash script
./scripts/quick_scan.sh /var/www --save
```

### Monitoramento de Integridade

```bash
# Criar baseline de referência
python main.py integrity baseline /etc --name sistema

# Verificar alterações desde a baseline
python main.py integrity check /etc --name sistema --save

# Modo watch (monitoramento em tempo real)
python main.py integrity watch /var/www --interval 10

# Via bash script
./scripts/baseline.sh create /etc sistema
./scripts/baseline.sh check  /etc sistema
./scripts/baseline.sh watch  /var/www 10
```

### Análise de Rede

```bash
# Análise completa de rede
python main.py netcheck -c -p -s --save

# Apenas conexões suspeitas
python main.py netcheck --suspicious

# Via bash script
./scripts/check_network.sh --save
```

### Monitoramento de Processos

```bash
# Top 20 processos + detecção de suspeitos
python main.py processes --suspicious

# Com detecção de processos ocultos (requer root)
sudo python main.py processes -s --hidden --top 50

# Monitoramento contínuo a cada 60s
./scripts/monitor_processes.sh 60
```

### Auditoria Completa

```bash
# Auditoria completa do sistema
sudo python main.py audit /

# Auditoria rápida
python main.py audit /home --quick -o html

# Via bash script (com log automático)
sudo ./scripts/full_audit.sh
```

### Hash e VirusTotal

```bash
# Calcular hash de arquivo
python main.py hash arquivo_suspeito.bin

# Com verificação no VirusTotal (configure API key em config/config.yaml)
python main.py hash malware.exe --check-vt

# Algoritmo específico
python main.py hash documento.pdf --algo md5
```

### Base de Assinaturas

```bash
# Atualizar base de hashes (requer internet)
python main.py db update

# Ver estatísticas da base atual
python main.py db stats
```

---

## ⚙️ Configuração

Edite `config/config.yaml` para personalizar o comportamento:

```yaml
# Diretórios a ignorar na varredura
scanner:
  skip_dirs: [".cache", "snap"]
  max_file_size_mb: 50

# VirusTotal (opcional — API gratuita em virustotal.com)
virustotal:
  api_key: "SUA_API_KEY_AQUI"

# Portas adicionais a considerar suspeitas
network:
  extra_suspicious_ports: [8888, 9999]
```

---

## 📊 Técnicas de Detecção

### Scanner de Malware
| Técnica | Descrição |
|---------|-----------|
| Hash matching | Compara SHA-256/MD5 com base de malware conhecidos |
| String analysis | Detecta 20+ padrões suspeitos (reverse shells, keyloggers, etc.) |
| Entropy analysis | Entropia > 7.2 indica código cifrado/empacotado |
| Double extension | Detecta `documento.pdf.exe` e similares |
| High-risk extension | Alerta para `.exe`, `.dll`, `.ps1`, `.vbs`, etc. |
| Permission check | Detecta arquivos com permissão 777 |

### Detecção de Rede
| Indicador | Portas Monitoradas |
|-----------|-------------------|
| Metasploit defaults | 4444, 5555, 6666 |
| Backdoors clássicos | 31337, 12345, 54321 |
| Proxies / Tor | 1080, 3128, 9050 |
| IRC (C2 antigo) | 6667-6669 |

### Análise de Processos
- Processos executando de `/tmp`, `/dev/shm`, `C:\Temp`
- Nomes mascarados (svchos7, l5ass, systemd0, etc.)
- Processos root com comandos suspeitos na cmdline
- PIDs em `/proc` ausentes no psutil (rootkits básicos)

---

## 🧪 Técnicas de Evasão Detectadas (Educacional)

```
Reverse Shells      → nc -e /bin/bash, bash -i >& /dev/tcp
Persistência        → crontab -e, run registry keys
Download remoto     → wget/curl em scripts, urllib em Python
Ofuscação           → base64 decode + eval, exec(compile(...))
Keyloggers          → GetAsyncKeyState, pynput, keyboard hooks
Ransomware          → Fernet/AES em massa, encrypt() loops
```

---

## 🔒 Boas Práticas de Segurança

1. **Execute como usuário limitado** sempre que possível
2. **Use `sudo` apenas** para módulos que exigem acesso root
3. **Atualize a base de assinaturas** regularmente (`python main.py db update`)
4. **Crie baselines** antes de instalar novos softwares
5. **Revise os relatórios** em `reports/` após cada auditoria
6. **Monitore logs** em `logs/cybersec_YYYYMMDD.log`

---

## 📦 Dependências

| Pacote | Uso |
|--------|-----|
| `click` | Interface CLI |
| `rich` | Output colorido e tabelas |
| `psutil` | Processos e conexões de rede |
| `requests` | Integração com VirusTotal e downloads |
| `PyYAML` | Leitura de configuração |
| `watchdog` | Monitoramento de sistema de arquivos |

---

## 📄 Licença

MIT License — livre para uso educacional e pessoal.  
Consulte o arquivo [LICENSE](LICENSE) para detalhes.

---

## 🤝 Contribuição

1. Fork o repositório
2. Crie uma branch (`git checkout -b feat/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'feat: adiciona nova detecção'`)
4. Push para a branch (`git push origin feat/nova-funcionalidade`)
5. Abra um Pull Request

---

> **Desenvolvido para fins educacionais.** Sempre obtenha autorização antes de executar análises em sistemas de terceiros.
