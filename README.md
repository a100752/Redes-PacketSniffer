# Network Packet Sniffer & Traffic Analyzer (Python / Scapy)

Ferramenta interativa de captura, dissecação e análise de pacotes de rede em tempo real desenvolvida em **Python**, com recurso à biblioteca **Scapy** para processamento de baixo nível e à biblioteca **Rich** para renderização visual e tabulação no terminal.

Projeto desenvolvido no âmbito da unidade curricular de Redes de Computadores (LEI) da **Universidade do Minho**.

---

## 🔍 Funcionalidades Principais

- **Dissecação Multi-Camadas**:
  - **Camada 2 (Enlace)**: Análise de tramas Ethernet II, endereços MAC de origem e destino, tipos EtherType e tráfego ARP.
  - **Camada 3 (Rede)**: Descodificação de cabeçalhos IPv4 e IPv6, TTL, campos de fragmentação e mensagens ICMP.
  - **Camada 4 (Transporte)**: Análise de segmentos TCP (flags SYN, ACK, FIN, RST, portas, números de sequência e janelas) e datagramas UDP.
  - **Camadas Superiores (Aplicação)**: Identificação e inspeção de payloads DNS, HTTP, DHCP, entre outros.
- **Filtragem com Sintaxe BPF (Berkeley Packet Filter)**:
  - Aplicação de filtros avançados em tempo real (ex: `icmp`, `tcp port 80`, `src host 192.168.1.1`).
- **Interface Terminal Interativa (Rich)**:
  - Menu interativo com deteção automática de interfaces de rede ativas (`eth0`, `lo`, `wlan0`).
  - Apresentação formatada com tabelas coloridas, métricas de volume e contadores de tráfego.
- **Registo e Exportação de Logs**:
  - Opção dinâmica de persistência das capturas em ficheiro de log (`log.txt`).
- **Simulação em Ambientes Virtuais (CORE)**:
  - Cenário de rede e topologia virtual testada com o emulador *Common Open Research Emulator (CORE)* (`testTP2Core.xml`).

---

## 📁 Estrutura do Projeto

```text
├── src/
│   ├── main.py          # Ponto de entrada e controlador do menu interativo
│   ├── sniffer.py       # Loop de captura de pacotes com Scapy
│   ├── protocol.py      # Lógica de dissecação e parsing dos protocolos
│   ├── interface.py     # Gestão e listagem de interfaces de rede disponíveis
│   └── gerador.py       # Gerador auxiliar de pacotes para testes de tráfego
├── testes/
│   └── testTP2Core.xml  # Topologia de rede para emulação no CORE
└── Relatorio_Final_PacketSniffer.pdf # Relatório técnico formal (2.5 MB)
```

---

## 🚀 Instalação e Execução

### Pré-requisitos
- Python 3.9 ou superior.
- Privilégios de superutilizador (`sudo`), necessários para colocar as interfaces de rede em modo promíscuo.

### Instalar Dependências
```bash
pip install scapy rich
```

*(Ou através do gestor de pacotes do sistema: `sudo apt install python3-scapy python3-rich`)*.

### Executar a Ferramenta
A partir da pasta raiz do projeto:

```bash
sudo python3 src/main.py
```

### Menu de Opções
1. **[1] Configure and Start Sniffer**: Inicia a captura interativa (especificação de interface, limite de pacotes e filtro BPF opcional).
2. **[2] List of Available Interfaces**: Lista todas as interfaces de rede ativas na máquina.
3. **[3] Show Capture logs**: Visualiza os registos de tráfego gravados.
4. **[4] Clean Capture logs**: Limpa o ficheiro de histórico `log.txt`.
5. **[5] Clean Screen**: Limpa o terminal.
6. **[6] Allow/Disallow saving**: Alterna a gravação automática em disco.
7. **[7] Exit**: Termina a aplicação em segurança.

---

## 📄 Relatório Técnico Completo

Para uma análise aprofundada dos diagramas de fluxo, metodologia de teste no simulador CORE e discussão teórica dos protocolos:
- [Relatório Técnico Final (PDF)](Relatorio_Final_PacketSniffer.pdf)
