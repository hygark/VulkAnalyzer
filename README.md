# VulkAnalyzer

## Aviso Importante:
O script é voltado para testes autorizados em ambientes controlados.
Este script é para uso educacional e em sistemas com permissão explícita. Varredura não autorizada pode violar leis de cibersegurança, como o Código Penal Brasileiro (art. 154-A) ou regulamentos internacionais ().
nem use KKKKKKKKKKKK

## Funcionalidades:

Varredura de Portas: Escaneia portas TCP em um host ou intervalo de IPs.
Análise de Cabeçalhos: Verifica cabeçalhos de segurança HTTP (ex.: Content-Security-Policy, X-Frame-Options).
Teste de SQL Injection: Detecta potenciais vulnerabilidades SQLi com payloads simples.
Teste de XSS: Verifica vulnerabilidades de Cross-Site Scripting com payloads básicos.
GUI de Configuração: Interface Tkinter para configurar alvos, portas e tipos de teste.
Logging: Registra resultados em arquivo (vulnerability_analyzer.log) e suporta webhook (ex.: Discord).
Varredura Paralela: Usa threads para acelerar varreduras (máximo 50 threads por padrão).
Limites de Segurança: Timeout configurável e tratamento de erros robusto.

## Requisitos:

Python: Versão 3.11 (padrão em 2025, baixe em python.org).
Dependências: Instale via pip:
requests: Para chamadas HTTP.
beautifulsoup4: Para parsing HTML.
tkinter: Nativo no Python para GUI.
socket, threading: Nativos para varredura.


## Sistema Operacional: Windows ou Linux.
Estrutura do Ambiente: Rede local ou URL autorizada para testes (ex.: http://testphp.vulnweb.com).
Bibliotecas: Rode pip install requests beautifulsoup4 no diretório do script.

## Instalação:

Crie um Repositório no GitHub (opcional para versionamento):
Vá para github.com e crie um novo repositório chamado "VulnerabilityAnalyzer".
Clone o repo para o seu PC: git clone https://github.com/hygark/VulnerabilityAnalyzer.git.

Adicione o Script:
Copie o conteúdo de VulnerabilityAnalyzer.py para um arquivo Python no seu diretório.

Instale Dependências:
No terminal: pip install requests beautifulsoup4.

Configuração no Python:

Abra o script e edite a tabela Settings:
Target: URL ou IP para teste (padrão: http://testphp.vulnweb.com).
PortRange: Intervalo de portas (padrão: 1-100).
Timeout: Timeout por porta (padrão: 1.0 segundos).
Threads: Número de threads (padrão: 50).
LogFile: Nome do arquivo de log (padrão: vulnerability_analyzer.log).
LogWebhook: URL de um webhook Discord (crie em Discord > Server Settings > Integrations).
CheckSQLi: Habilitar teste de SQL Injection (padrão: True).
CheckXSS: Habilitar teste de XSS (padrão: True).
CheckHeaders: Habilitar verificação de cabeçalhos (padrão: True).

Ajuste as Configurações:
Edite Settings ou use a GUI para configurar alvo, portas e testes.

Execute o Script:
No terminal: python VulnerabilityAnalyzer.py.
Uma janela Tkinter abrirá. Insira o alvo (ex.: http://testphp.vulnweb.com), intervalo de portas (ex.: 1-100), selecione os testes e clique em "Iniciar Varredura".


Teste:
Varra um host/URL autorizado (ex.: 127.0.0.1 ou http://testphp.vulnweb.com).
O script lista portas abertas, vulnerabilidades de cabeçalhos, SQLi ou XSS no console, arquivo de log ou GUI.
Monitore logs (ex.: "Potencial SQL Injection em http://testphp.vulnweb.com?id=' OR '1'='1").


Parar o Script:
Clique em "Parar Varredura" na GUI ou feche a janela.



Exemplos de Uso:

Teste em Site de Teste: Varra http://testphp.vulnweb.com para detectar SQLi ou XSS em formulários.
Teste de Portas: Varra 127.0.0.1 nas portas 1-100 para encontrar serviços como HTTP (80).
Logging Avançado: Configure um webhook Discord para receber notificações de vulnerabilidades encontradas.
Expansão: Adicione testes para outras vulnerabilidades (ex.: CSRF, SSRF) ou integração com scapy.

Aviso Legal e Ético:

Este script é para fins educativos e testes em sistemas com permissão explícita. Varredura não autorizada pode violar leis como o Código Penal Brasileiro (art. 154-A) ou regulamentos internacionais ().
Sempre obtenha autorização por escrito antes de testar redes/URLs.
Para pentest ético, use em ambientes controlados com permissão (ex.: sites de teste como testphp.vulnweb.com).
