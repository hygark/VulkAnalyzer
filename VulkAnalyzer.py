# VulnerabilityAnalyzer.py - Analisador de vulnerabilidades para pentest ético (2025)
# Criado por hygark (2025)
# Descrição: Script Python para análise de vulnerabilidades em hosts/URLs, com varredura de portas, testes web (SQLi, XSS, CSRF, SSRF), detecção de CMS, fingerprinting, relatórios em JSON/PDF e GUI Tkinter com gráficos.
# Nota: Use apenas em sistemas com permissão explícita. Varredura não autorizada pode violar leis de cibersegurança.
# eu n7n sei de nada
import socket
import threading
import time
import requests
from bs4 import BeautifulSoup
from scapy.all import sr1, IP, TCP, ICMP
from urllib.parse import urljoin
import re
import json
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Configurações personalizáveis
Settings = {
    'Targets': ['http://testphp.vulnweb.com', '127.0.0.1'],  # Lista de alvos (URLs ou IPs)
    'PortRange': (1, 1000),  # Intervalo de portas
    'Timeout': 0.5,  # Timeout por porta (segundos)
    'Threads': 200,  # Número de threads
    'LogFile': 'logs/vulnerability_analyzer.log',  # Arquivo de log
    'LogWebhook': '',  # URL de webhook (ex.: Discord)
    'ReportDir': 'reports/',  # Diretório para relatórios
    'CheckSQLi': True,  # Testar SQL Injection
    'CheckXSS': True,  # Testar XSS
    'CheckCSRF': True,  # Testar CSRF
    'CheckSSRF': True,  # Testar SSRF
    'CheckHeaders': True,  # Verificar cabeçalhos
    'CheckCMS': True,  # Detectar CMS
    'FingerprintOS': True,  # Fingerprinting de SO
    'ExportJSON': True,  # Exportar relatório em JSON
    'ExportPDF': True,  # Exportar relatório em PDF
}

# Estado do script
ScriptState = {
    'IsRunning': False,
    'Vulnerabilities': [],
    'TotalScans': 0,
    'TotalVulnsFound': 0,
    'Results': {},  # Resultados por alvo
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
            requests.post(Settings['LogWebhook'], json={'content': log_entry})
        except Exception as e:
            print(f"[ERROR] Falha ao enviar log para webhook: {e}")

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

# Função para fingerprinting de SO com Scapy
def fingerprint_os(host):
    try:
        packet = IP(dst=host)/ICMP()
        response = sr1(packet, timeout=2, verbose=0)
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

# Função para testar SQL Injection (básico + integração com sqlmap)
def test_sql_injection(url):
    payloads = ["' OR '1'='1", "1; DROP TABLE users --"]
    try:
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=5)
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax error']):
                ScriptState['Vulnerabilities'].append(('SQL Injection', f'Potencial SQLi com payload {payload}', test_url))
                ScriptState['TotalVulnsFound'] += 1
                log_message('CRITICAL', f'Potencial SQL Injection em {test_url}')
        
        # Integração com sqlmap (simulada, requer sqlmap instalado)
        try:
            import subprocess
            result = subprocess.run(['sqlmap', '-u', url, '--batch', '--level=1'], capture_output=True, text=True)
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
    payloads = ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>']
    try:
        for payload in payloads:
            test_url = f"{url}?q={payload}"
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
    payload = 'http://169.254.169.254/latest/meta-data/'  # Exemplo de endpoint SSRF
    try:
        test_url = f"{url}?url={payload}"
        response = requests.get(test_url, timeout=5)
        if 'instance-id' in response.text.lower() or 'metadata' in response.text.lower():
            ScriptState['Vulnerabilities'].append(('SSRF', f'Potencial SSRF com payload {payload}', test_url))
            ScriptState['TotalVulnsFound'] += 1
            log_message('CRITICAL', f'Potencial SSRF em {test_url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar SSRF em {url}: {e}')

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
    else:
        if Settings['FingerprintOS']:
            fingerprint_os(target)
        scan_ports(target, Settings['PortRange'], 'TCP', lambda x, y: None)

# Função para exportar relatório em JSON
def export_json_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.json')
    with open(report_path, 'w') as f:
        json.dump(ScriptState['Results'], f, indent=2)
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
    
    for target, data in ScriptState['Results'].items():
        story.append(Paragraph(f'Target: {target}', styles['Heading2']))
        story.append(Spacer(1, 12))
        
        table_data = [['Type', 'Description', 'Details']]
        for vuln in data['vulns'] + ScriptState['Vulnerabilities']:
            if vuln[2] == target:
                table_data.append(vuln)
        
        table = Table(table_data)
        story.append(table)
        story.append(Spacer(1, 12))
    
    doc.build(story)
    log_message('INFO', f'Relatório PDF salvo em {report_path}')

# GUI com Tkinter
class VulnerabilityAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('VulnerabilityAnalyzer - Inflavelle')
        self.root.geometry('800x600')

        # Labels e inputs
        tk.Label(root, text='VulnerabilityAnalyzer', font=('Arial', 16, 'bold')).pack(pady=10)
        
        tk.Label(root, text='Targets (URLs ou IPs, separados por vírgula):').pack()
        self.target_entry = tk.Entry(root, width=50)
        self.target_entry.insert(0, ','.join(Settings['Targets']))
        self.target_entry.pack()

        tk.Label(root, text='Intervalo de Portas (ex.: 1-1000):').pack()
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, f"{Settings['PortRange'][0]}-{Settings['PortRange'][1]}")
        self.port_entry.pack()

        tk.Label(root, text='Threads:').pack()
        self.threads_entry = tk.Entry(root)
        self.threads_entry.insert(0, str(Settings['Threads']))
        self.threads_entry.pack()

        tk.Label(root, text='Testes:').pack()
        self.check_vars = {
            'SQLi': tk.BooleanVar(value=Settings['CheckSQLi']),
            'XSS': tk.BooleanVar(value=Settings['CheckXSS']),
            'CSRF': tk.BooleanVar(value=Settings['CheckCSRF']),
            'SSRF': tk.BooleanVar(value=Settings['CheckSSRF']),
            'Headers': tk.BooleanVar(value=Settings['CheckHeaders']),
            'CMS': tk.BooleanVar(value=Settings['CheckCMS']),
            'OS': tk.BooleanVar(value=Settings['FingerprintOS']),
            'JSON': tk.BooleanVar(value=Settings['ExportJSON']),
            'PDF': tk.BooleanVar(value=Settings['ExportPDF'])
        }
        for name, var in self.check_vars.items():
            tk.Checkbutton(root, text=name, variable=var).pack()

        # Progresso
        self.progress_var = tk.StringVar(value='Progresso: 0 vulnerabilidades encontradas')
        tk.Label(root, textvariable=self.progress_var).pack(pady=5)

        # Botões
        tk.Button(root, text='Iniciar Varredura', command=self.start_scan).pack(pady=5)
        tk.Button(root, text='Parar Varredura', command=self.stop_scan).pack(pady=5)
        tk.Button(root, text='Salvar Configurações', command=self.save_settings).pack(pady=5)
        tk.Button(root, text='Visualizar Gráficos', command=self.show_graphs).pack(pady=5)

        # Resultados
        self.result_text = tk.Text(root, height=10, width=70)
        self.result_text.pack(pady=10)

    def log(self, message):
        self.result_text.insert(tk.END, f"{message}\n")
        self.result_text.see(tk.END)

    def update_progress(self, vulns_found, scanned_items):
        total_items = Settings['PortRange'][1] - Settings['PortRange'][0] + 1
        self.progress_var.set(f'Progresso: {vulns_found} vulnerabilidades, {scanned_items}/{total_items} portas')

    def show_graphs(self):
        fig, ax = plt.subplots()
        vuln_types = {}
        for vuln in ScriptState['Vulnerabilities']:
            vuln_type = vuln[0]
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        if vuln_types:
            ax.bar(vuln_types.keys(), vuln_types.values())
            ax.set_title('Distribuição de Vulnerabilidades')
            ax.set_xlabel('Tipo de Vulnerabilidade')
            ax.set_ylabel('Quantidade')
            plt.xticks(rotation=45)
            
            window = tk.Toplevel(self.root)
            canvas = FigureCanvasTkAgg(fig, master=window)
            canvas.draw()
            canvas.get_tk_widget().pack()

    def start_scan(self):
        if ScriptState['IsRunning']:
            messagebox.showerror('Erro', 'Varredura já em andamento!')
            return
        ScriptState['IsRunning'] = True
        ScriptState['Vulnerabilities'] = []
        ScriptState['Results'] = {}
        self.save_settings()

        try:
            targets = [t.strip() for t in self.target_entry.get().split(',')]
            for target in targets:
                ScriptState['Results'][target] = {'ports': [], 'vulns': []}
                threading.Thread(target=scan_target, args=(target,), daemon=True).start()
                self.log(f'Varredura iniciada em {target}')
            
            if self.check_vars['JSON'].get():
                threading.Thread(target=export_json_report, daemon=True).start()
            if self.check_vars['PDF'].get():
                threading.Thread(target=export_pdf_report, daemon=True).start()
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao iniciar varredura: {e}')
            ScriptState['IsRunning'] = False

    def stop_scan(self):
        ScriptState['IsRunning'] = False
        self.log('Varredura parada.')

    def save_settings(self):
        try:
            Settings['Targets'] = [t.strip() for t in self.target_entry.get().split(',')]
            Settings['PortRange'] = tuple(map(int, self.port_entry.get().split('-')))
            Settings['Threads'] = int(self.threads_entry.get())
            for name, var in self.check_vars.items():
                Settings[f'Check{name}'] = var.get()
            self.log('Configurações salvas.')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao salvar configurações: {e}')

# Iniciar GUI
if __name__ == '__main__':
    root = tk.Tk()
    app = VulnerabilityAnalyzerGUI(root)
    root.mainloop()