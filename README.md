# VulkAnalyzer

Autor Hygark 

## Funcionalidades

Varredura de Portas: Escaneia portas TCP/UDP em um intervalo configurável com suporte a múltiplas threads.
Testes Web: Verifica vulnerabilidades como SQL Injection, XSS, CSRF, SSRF, LFI/RFI.
Detecção de CMS: Identifica sistemas como WordPress, Joomla e Drupal.
Fingerprinting de SO: Estima o sistema operacional com base no TTL.
Varredura de Subdomínios: Descobre subdomínios via DNS.
Testes de APIs: Suporta varreduras em APIs REST, GraphQL e WebSockets, incluindo autenticação fraca e injeções.
Cloud Misconfigurations: Verifica buckets públicos (AWS S3, Azure Blob, Google Cloud Storage).
Integrações: Suporta XSStrike, Nikto, Burp Suite, Wfuzz, OWASP ZAP, Metasploit e Nuclei.
Exportação de Relatórios: Gera relatórios em JSON, PDF, CSV e HTML interativo com gráficos.
Logs: Suporta logs em arquivo, webhook, email e Syslog (Splunk/ELK).
GUI: Interface Tkinter com abas para Configurações, Dashboard (gráficos), Resultados e Relatórios interativos.

## Requisitos

Python: 3.11 ou superior.
Dependências Python:pip install requests beautifulsoup4 scapy reportlab matplotlib msfrpc websocket-client tkinterweb dnspython


## Ferramentas Externas:
XSStrike: git clone https://github.com/s0md3v/XSStrike.git
Nikto: sudo apt install nikto (Linux) ou equivalente.
Wfuzz: pip install wfuzz
Nuclei: go install -v github.com/projectdiscovery/nuclei/v3@latest
OWASP ZAP: Instale e configure a API.
Burp Suite: Configure a API REST.
Metasploit: Instale e configure o RPC.


## Sistema Operacional:
Compatível com Windows e Linux.
Permissões: Algumas funcionalidades (como varredura de portas) podem requerer privilégios de administrador.

## Instalação

Clone o repositório:
git clone https://github.com/hygark/VulkAnalyzer.git
cd VulkAnalyzer

Instale as dependências Python:
pip install -r requirements.txt

Instale as ferramentas externas conforme as instruções acima.
Configure os caminhos e chaves de API no script (em Settings ou via GUI).

## Crie um diretório para logs e relatórios:
mkdir logs reports



## Uso

Execute o script:
python3 VulnerabilityAnalyzer.py


## Na GUI:

Configurações: Insira alvos (URLs ou IPs), intervalo de portas, caminhos das ferramentas, chaves de API, etc.
Dashboard: Visualize gráficos de vulnerabilidades em tempo real.
Resultados: Veja os resultados detalhados das varreduras.
Relatórios: Exporte relatórios em JSON, PDF, CSV ou HTML interativo.
Botões: Inicie/parar varreduras, salve configurações, visualize gráficos ou exporte relatórios.


Configure logs (arquivo, webhook, email, Syslog) e exportações conforme necessário.


Exemplo de Configuração
Settings = {
    'Targets': ['http://testphp.vulnweb.com', '127.0.0.1'],
    'PortRange': (1, 1000),
    'Threads': 200,
    'XSStrikePath': './XSStrike/xsstrike.py',
    'NiktoPath': 'nikto',
    'SyslogServer': 'localhost',
    'SyslogPort': 514,
    'ExportJSON': True,
    'ExportPDF': True,
    'ExportCSV': True,
    'ExportHTML': True
}

## Conformidade Legal

Aviso: Esta ferramenta é destinada exclusivamente para testes éticos com autorização explícita dos proprietários dos sistemas-alvo. O uso não autorizado pode violar leis locais, como a LGPD (Lei Geral de Proteção de Dados) no Brasil ou outras regulamentações internacionais (ex.: GDPR).
Responsabilidade: O autor (Hygark) não se responsabiliza por qualquer uso indevido da ferramenta. Certifique-se de obter permissões antes de realizar varreduras.

## Contribuições
Contribuições são bem-vindas! Envie pull requests ou abra issues no repositório GitHub.
## Licença
MIT License. Veja o arquivo LICENSE para mais detalhes.

Contato
Para dúvidas ou sugestões, contate Hygark via GitHub.
