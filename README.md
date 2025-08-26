# VulkAnalyzer

## Aviso Importante:
O script é voltado para testes autorizados em ambientes controlados.
Este script é para uso educacional e em sistemas com permissão explícita. Varredura não autorizada pode violar leis como o Código Penal Brasileiro (art. 154-A), LGPD, ou regulamentos internacionais.
nem useK

## Funcionalidades:

Varredura de Portas: Escaneia portas TCP/UDP em múltiplos alvos com socket e scapy.
Testes Web: Verifica SQL Injection, XSS, CSRF e SSRF com payloads avançados e integração com sqlmap.
Análise de Cabeçalhos: Detecta ausência de cabeçalhos de segurança (ex.: Content-Security-Policy, HSTS).
Detecção de CMS: Identifica CMS como WordPress, Joomla, Drupal via padrões HTML.
Fingerprinting de SO: Estima sistemas operacionais com base em TTL via scapy.
Suporte a Múltiplos Alvos: Varre intervalos de IPs e URLs em paralelo com threading.
Relatórios: Exporta resultados em JSON e PDF com reportlab.
GUI Interativa: Interface Tkinter com configuração, visualização de resultados e gráficos via matplotlib.
Logging Avançado: Registra detalhes em arquivo (logs/vulnerability_analyzer.log) e webhook (ex.: Discord).
Segurança: Timeout configurável, tratamento de erros robusto e threading otimizado (máximo 200 threads).

## Requisitos:

Python: Versão 3.11 (padrão em 2025, baixe em python.org).
Dependências: Instale via pip:
requests: Para chamadas HTTP.
beautifulsoup4: Para parsing HTML.
scapy: Para fingerprinting de SO.
reportlab: Para relatórios PDF.
matplotlib: Para gráficos na GUI.
tkinter: Nativo no Python para GUI.
sqlmap (opcional): Para testes avançados de SQL Injection.


Sistema Operacional: Windows ou Linux.
Estrutura do Ambiente: Rede local ou URLs autorizadas (ex.: http://testphp.vulnweb.com, 127.0.0.1).
Bibliotecas: Rode pip install requests beautifulsoup4 scapy reportlab matplotlib no diretório do script. Instale sqlmap separadamente se necessário (pip install sqlmap ou via repositório GitHub).

## Instalação:

Crie um Repositório no GitHub (opcional para versionamento):
Vá para github.com e crie um novo repositório chamado "VulnerabilityAnalyzer".
Clone o repo para o seu PC: git clone https://github.com/hygark/VulnerabilityAnalyzer.git.


Adicione o Script:
Copie o conteúdo de VulnerabilityAnalyzer.py para um arquivo Python no seu diretório.


Instale Dependências:
No terminal: pip install requests beautifulsoup4 scapy reportlab matplotlib.
(Opcional) Instale sqlmap: pip install sqlmap ou siga as instruções em sqlmap.org.



## Configuração no Python:

Abra o script e edite a tabela Settings:
Targets: Lista de URLs ou IPs (padrão: ['http://testphp.vulnweb.com', '127.0.0.1']).
PortRange: Intervalo de portas (padrão: 1-1000).
Timeout: Timeout por porta (padrão: 0.5 segundos).
Threads: Número de threads (padrão: 200).
LogFile: Caminho do arquivo de log (padrão: logs/vulnerability_analyzer.log).
LogWebhook: URL de um webhook Discord (crie em Discord > Server Settings > Integrations).
ReportDir: Diretório para relatórios (padrão: reports/).
CheckSQLi, CheckXSS, CheckCSRF, CheckSSRF, CheckHeaders, CheckCMS, FingerprintOS, ExportJSON, ExportPDF: Habilitar/desabilitar testes/exportações (padrão: True).

Ajuste as Configurações:
Edite Settings ou use a GUI para configurar alvos, portas e testes.


Execute o Script:
No terminal: python VulnerabilityAnalyzer.py.
Uma janela Tkinter abrirá. Insira alvos (ex.: http://testphp.vulnweb.com,127.0.0.1), intervalo de portas (ex.: 1-1000), selecione testes e clique em "Iniciar Varredura".


Teste:
Varra alvos autorizados (ex.: http://testphp.vulnweb.com para web, 127.0.0.1 para portas).
O script lista portas abertas, vulnerabilidades (SQLi, XSS, etc.), CMS e SO no console, arquivo de log, GUI e relatórios.
Monitore logs (ex.: "Potencial XSS em http://testphp.vulnweb.com?q=alert('XSS')").
Visualize gráficos clicando em "Visualizar Gráficos".

Relatórios:
Relatórios JSON/PDF são salvos em reports/ com detalhes das vulnerabilidades.

Parar o Script:
Clique em "Parar Varredura" na GUI ou feche a janela.



## Exemplos de Uso:

Teste Web: Varra http://testphp.vulnweb.com para detectar SQLi, XSS, CSRF, SSRF e cabeçalhos ausentes.
Teste de Rede: Varra 127.0.0.1 nas portas 1-1000 para encontrar serviços e estimar o SO.
Relatórios: Gere relatórios JSON/PDF para documentar vulnerabilidades em um servidor autorizado.
Gráficos: Visualize a distribuição de vulnerabilidades (ex.: SQLi vs. XSS) na GUI.
Expansão: Adicione testes para vulnerabilidades como LFI/RFI ou integração com outras ferramentas.

Aviso Legal e Ético:

Este script é para fins educativos e testes em sistemas com permissão explícita. Varredura não autorizada pode violar leis como o Código Penal Brasileiro (art. 154-A), LGPD, ou regulamentos internacionais.
Sempre obtenha autorização por escrito antes de testar redes/URLs.
Use em ambientes controlados (ex.: http://testphp.vulnweb.com, redes locais) para pentest ético.
