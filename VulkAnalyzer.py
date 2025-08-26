# VulkAnalyzer.py - Analisador de vulnerabilidades para pentest ético (2025)
# Criado por hygark (2025)
# Descrição: Script Python para varredura de vulnerabilidades em hosts/URLs, verificando portas abertas, cabeçalhos HTTP, SQL Injection e XSS. Inclui GUI Tkinter e logging.
# Nota: Use apenas em sistemas com permissão explícita. Varredura não autorizada pode violar leis de cibersegurança.

import socket
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os
from urllib.parse import urljoin
import re

# Configurações personalizáveis
Settings = {
    'Target': 'http://testphp.vulnweb.com',  # URL ou IP para teste (padrão: site de teste)
    'PortRange': (1, 100),  # Intervalo de portas para varredura
    'Timeout': 1.0,  # Timeout por porta (segundos)
    'Threads': 50,  # Número de threads para varredura
    'LogFile': 'vulnerability_analyzer.log',  # Arquivo de log
    'LogWebhook': '',  # URL de webhook para logging (ex.: Discord)
    'CheckSQLi': True,  # Verificar SQL Injection
    'CheckXSS': True,  # Verificar XSS
    'CheckHeaders': True,  # Verificar cabeçalhos de segurança
}

# Estado do script
ScriptState = {
    'IsRunning': False,
    'Vulnerabilities': [],
    'TotalScans': 0,
    'TotalVulnsFound': 0,
}

# Função para enviar logs (arquivo e webhook)
def log_message(level, message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{level}] [{timestamp}] {message}"
    print(log_entry)
    
    # Log em arquivo
    with open(Settings['LogFile'], 'a') as f:
        f.write(log_entry + '\n')
    
    # Log via webhook
    if Settings['LogWebhook']:
        try:
            requests.post(Settings['LogWebhook'], json={'content': log_entry})
        except Exception as e:
            print(f"[ERROR] Falha ao enviar log para webhook: {e}")

# Função para verificar portas abertas
def scan_port(host, port, result_queue):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(Settings['Timeout'])
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            result_queue.put((port, 'TCP', 'Open'))
            log_message('INFO', f'Porta {port}/TCP aberta em {host}')
        ScriptState['TotalScans'] += 1
    except Exception as e:
        log_message('ERROR', f'Erro ao verificar porta {port}: {e}')

# Função para varredura de portas
def scan_ports(host, port_range, progress_callback):
    result_queue = Queue()
    threads = []

    for port in range(port_range[0], port_range[1] + 1):
        t = threading.Thread(target=scan_port, args=(host, port, result_queue))
        threads.append(t)
        t.start()
        
        if len(threads) >= Settings['Threads']:
            for t in threads:
                t.join()
            threads = []
            progress_callback(len(ScriptState['Vulnerabilities']), port - port_range[0] + 1)

    for t in threads:
        t.join()

    while not result_queue.empty():
        ScriptState['Vulnerabilities'].append(result_queue.get())
    
    progress_callback(len(ScriptState['Vulnerabilities']), port_range[1] - port_range[0] + 1)

# Função para verificar cabeçalhos de segurança
def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        issues = []
        
        if 'Content-Security-Policy' not in headers:
            issues.append('Falta Content-Security-Policy')
        if 'X-Content-Type-Options' not in headers or headers['X-Content-Type-Options'] != 'nosniff':
            issues.append('Falta ou inválido X-Content-Type-Options')
        if 'X-Frame-Options' not in headers or headers['X-Frame-Options'] not in ['DENY', 'SAMEORIGIN']:
            issues.append('Falta ou inválido X-Frame-Options')
        
        if issues:
            ScriptState['TotalVulnsFound'] += len(issues)
            for issue in issues:
                ScriptState['Vulnerabilities'].append(('Headers', issue, url))
                log_message('WARNING', f'Vulnerabilidade de cabeçalho: {issue} em {url}')
        else:
            log_message('INFO', f'Nenhum problema de cabeçalho em {url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao verificar cabeçalhos em {url}: {e}')

# Função para testar SQL Injection
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
    except Exception as e:
        log_message('ERROR', f'Erro ao testar SQLi em {url}: {e}')

# Função para testar XSS
def test_xss(url):
    payload = '<script>alert("XSS")</script>'
    try:
        test_url = f"{url}?q={payload}"
        response = requests.get(test_url, timeout=5)
        if payload in response.text:
            ScriptState['Vulnerabilities'].append(('XSS', f'Potencial XSS com payload {payload}', test_url))
            ScriptState['TotalVulnsFound'] += 1
            log_message('CRITICAL', f'Potencial XSS em {test_url}')
    except Exception as e:
        log_message('ERROR', f'Erro ao testar XSS em {url}: {e}')

# Função para varrer URLs em busca de formulários vulneráveis
def scan_web(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            form_url = urljoin(url, action) if action else url
            if Settings['CheckSQLi']:
                test_sql_injection(form_url)
            if Settings['CheckXSS']:
                test_xss(form_url)
        
        if Settings['CheckHeaders']:
            check_security_headers(url)
    except Exception as e:
        log_message('ERROR', f'Erro ao varrer URL {url}: {e}')

# GUI com Tkinter
class VulnerabilityAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('VulnerabilityAnalyzer - Inflavelle')
        self.root.geometry('600x500')

        # Labels e inputs
        tk.Label(root, text='VulnerabilityAnalyzer', font=('Arial', 16, 'bold')).pack(pady=10)
        
        tk.Label(root, text='Target (URL ou IP):').pack()
        self.target_entry = tk.Entry(root)
        self.target_entry.insert(0, Settings['Target'])
        self.target_entry.pack()

        tk.Label(root, text='Intervalo de Portas (ex.: 1-100):').pack()
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, f"{Settings['PortRange'][0]}-{Settings['PortRange'][1]}")
        self.port_entry.pack()

        tk.Label(root, text='Threads:').pack()
        self.threads_entry = tk.Entry(root)
        self.threads_entry.insert(0, str(Settings['Threads']))
        self.threads_entry.pack()

        tk.Label(root, text='Testes:').pack()
        self.check_sqli_var = tk.BooleanVar(value=Settings['CheckSQLi'])
        tk.Checkbutton(root, text='SQL Injection', variable=self.check_sqli_var).pack()
        self.check_xss_var = tk.BooleanVar(value=Settings['CheckXSS'])
        tk.Checkbutton(root, text='XSS', variable=self.check_xss_var).pack()
        self.check_headers_var = tk.BooleanVar(value=Settings['CheckHeaders'])
        tk.Checkbutton(root, text='Cabeçalhos de Segurança', variable=self.check_headers_var).pack()

        # Progresso
        self.progress_var = tk.StringVar(value='Progresso: 0 vulnerabilidades encontradas')
        tk.Label(root, textvariable=self.progress_var).pack(pady=5)

        # Botões
        tk.Button(root, text='Iniciar Varredura', command=self.start_scan).pack(pady=5)
        tk.Button(root, text='Parar Varredura', command=self.stop_scan).pack(pady=5)
        tk.Button(root, text='Salvar Configurações', command=self.save_settings).pack(pady=5)

        # Resultados
        self.result_text = tk.Text(root, height=10, width=60)
        self.result_text.pack(pady=10)

    def log(self, message):
        self.result_text.insert(tk.END, f"{message}\n")
        self.result_text.see(tk.END)

    def update_progress(self, vulns_found, scanned_items):
        total_items = Settings['PortRange'][1] - Settings['PortRange'][0] + 1
        self.progress_var.set(f'Progresso: {vulns_found} vulnerabilidades, {scanned_items}/{total_items} portas')

    def start_scan(self):
        if ScriptState['IsRunning']:
            messagebox.showerror('Erro', 'Varredura já em andamento!')
            return
        ScriptState['IsRunning'] = True
        ScriptState['Vulnerabilities'] = []
        self.save_settings()

        try:
            target = self.target_entry.get()
            port_range = tuple(map(int, self.port_entry.get().split('-')))
            Settings['PortRange'] = port_range

            # Criar diretório de logs
            log_dir = os.path.dirname(Settings['LogFile'])
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)

            # Iniciar varredura de portas e web
            if target.startswith('http'):
                threading.Thread(target=scan_web, args=(target,), daemon=True).start()
                self.log(f'Varredura web iniciada em {target}')
            else:
                threading.Thread(target=scan_ports, args=(target, port_range, self.update_progress), daemon=True).start()
                self.log(f'Varredura de portas iniciada em {target} ({port_range[0]}-{port_range[1]})')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao iniciar varredura: {e}')
            ScriptState['IsRunning'] = False

    def stop_scan(self):
        ScriptState['IsRunning'] = False
        self.log('Varredura parada.')

    def save_settings(self):
        try:
            Settings['Target'] = self.target_entry.get()
            Settings['PortRange'] = tuple(map(int, self.port_entry.get().split('-')))
            Settings['Threads'] = int(self.threads_entry.get())
            Settings['CheckSQLi'] = self.check_sqli_var.get()
            Settings['CheckXSS'] = self.check_xss_var.get()
            Settings['CheckHeaders'] = self.check_headers_var.get()
            self.log('Configurações salvas.')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao salvar configurações: {e}')

# Iniciar GUI
if __name__ == '__main__':
    root = tk.Tk()
    app = VulnerabilityAnalyzerGUI(root)
    root.mainloop()