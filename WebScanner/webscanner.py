import tkinter as tk
from tkinter import scrolledtext
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import threading

# --- Main Scanning Logic ---

def run_full_scan(url, results_widget):
    """Orchestrates the running of all security scans."""
    log_message(results_widget, f"--- [SESSION STARTED] TARGET: {url} ---")
    
    check_security_headers(url, results_widget)
    forms = get_forms(url, results_widget)
    
    if not forms:
        log_message(results_widget, "[INFO] No forms found on page. Limited scan surface.")
    else:
        log_message(results_widget, f"[INFO] {len(forms)} form(s) detected. Initiating payload injection...")
        scan_xss(url, forms, results_widget)
        scan_sql_injection(url, forms, results_widget)
        
    # --- Hacker-style Attribution ---
    log_message(results_widget, "\n--- [SESSION TERMINATED] ---")
    log_message(results_widget, "╔════════════════════════════════════════════════════╗")
    log_message(results_widget, "║   Scanner Operation by: Utkarsh Aggarwal         ║")
    log_message(results_widget, "║   GitHub Profile: /utkarshcse2026                 ║")
    log_message(results_widget, "╚════════════════════════════════════════════════════╝")

def check_security_headers(url, results_widget):
    """Checks for important security headers."""
    log_message(results_widget, "\n[+] Analyzing HTTP Security Headers...")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        missing = [h for h in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options'] if h not in headers]
        
        if not missing:
            log_message(results_widget, "  [OK] Target headers appear hardened.")
        else:
            for header in missing:
                log_message(results_widget, f"  [WARNING] Missing hardening header: {header}")
    except requests.RequestException as e:
        log_message(results_widget, f"  [ERROR] Header analysis failed: {e}")

def get_forms(url, results_widget):
    """Extracts all HTML forms from a URL."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException as e:
        log_message(results_widget, f"[ERROR] Failed to fetch target page: {e}")
        return []

def submit_form(form, value, url):
    """Submits a form with a given payload."""
    action = form.get('action')
    post_url = urljoin(url, action)
    method = form.get('method', 'get').lower()
    inputs_list = form.find_all('input')
    data = {}
    for input_tag in inputs_list:
        input_name = input_tag.get('name')
        input_type = input_tag.get('type', 'text')
        if input_type == 'text':
            data[input_name] = value
    try:
        if method == 'post':
            return requests.post(post_url, data=data, timeout=5)
        else:
            return requests.get(post_url, params=data, timeout=5)
    except requests.RequestException:
        return None

def scan_xss(url, forms, results_widget):
    """Scans for reflected XSS vulnerabilities."""
    log_message(results_widget, "\n[+] Injecting XSS payloads...")
    payload = "<script>alert('xss')</script>"
    found = False
    for form in forms:
        response = submit_form(form, payload, url)
        if response and payload in response.content.decode(errors='ignore'):
            log_message(results_widget, "  [CRITICAL] Potential XSS vector discovered!")
            found = True
    if not found:
        log_message(results_widget, "  [OK] No obvious XSS vectors found.")

def scan_sql_injection(url, forms, results_widget):
    """Scans for basic error-based SQL Injection vulnerabilities."""
    log_message(results_widget, "\n[+] Injecting SQLi payloads...")
    payload = "' OR '1'='1"
    errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"]
    found = False
    for form in forms:
        response = submit_form(form, payload, url)
        if response:
            for error in errors:
                if error in response.content.decode(errors='ignore').lower():
                    log_message(results_widget, "  [CRITICAL] Potential SQLi vector discovered!")
                    found = True
                    break
    if not found:
        log_message(results_widget, "  [OK] No obvious SQLi vectors found.")


# --- GUI Functions ---

def start_scan_thread(url_entry, results_widget, scan_button):
    """Starts the scanning process in a separate thread."""
    url = url_entry.get()
    if not url:
        results_widget.insert(tk.END, "Please enter a URL to scan.\n")
        return
    
    scan_button.config(state=tk.DISABLED, text="Scanning...")
    results_widget.delete('1.0', tk.END)
    
    def scan_and_reenable():
        run_full_scan(url, results_widget)
        scan_button.config(state=tk.NORMAL, text="Start Scan")

    scan_thread = threading.Thread(target=scan_and_reenable, daemon=True)
    scan_thread.start()

def log_message(widget, message):
    """Thread-safe way to insert styled messages."""
    message += '\n'
    tag = 'normal' # Default tag
    if "[CRITICAL]" in message: tag = 'critical'
    elif "[WARNING]" in message: tag = 'warning'
    elif "[OK]" in message: tag = 'ok'
    elif "[INFO]" in message: tag = 'info'
    elif "---" in message: tag = 'header'
    elif "╔" in message or "║" in message or "╚" in message: tag = 'art'
    
    widget.config(state=tk.NORMAL)
    widget.insert(tk.END, message, tag)
    widget.config(state=tk.DISABLED)
    widget.see(tk.END)

# --- Main Application Setup ---

if __name__ == '__main__':
    # Window setup
    root = tk.Tk()
    root.title("Vulnerability Scanner v1.0")
    root.geometry("750x550")
    root.configure(bg='black')

    # Main frame
    main_frame = tk.Frame(root, bg='black', padx=10, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Input frame
    input_frame = tk.Frame(main_frame, bg='black')
    input_frame.pack(fill=tk.X)
    
    url_label = tk.Label(input_frame, text="TARGET URL >>", font=('Courier New', 11, 'bold'), bg='black', fg='cyan')
    url_label.pack(side=tk.LEFT, padx=5)

    url_entry = tk.Entry(input_frame, font=('Courier New', 11), width=60, bg='#1a1a1a', fg='lime', insertbackground='lime', borderwidth=0)
    url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, ipady=4)
    url_entry.insert(0, "http://testphp.vulnweb.com/login.php")
    
    scan_button = tk.Button(input_frame, text="Start Scan", font=('Courier New', 10, 'bold'), bg='#1a1a1a', fg='lime',
                            activebackground='lime', activeforeground='black', borderwidth=0, padx=10,
                            command=lambda: start_scan_thread(url_entry, results_text, scan_button))
    scan_button.pack(side=tk.LEFT, padx=10)

    # Bind the Enter key to the start_scan_thread function
    url_entry.bind("<Return>", lambda event: start_scan_thread(url_entry, results_text, scan_button))

    # Results display
    results_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=('Courier New', 10), bg='black', fg='lime',
                                             borderwidth=0, state=tk.DISABLED)
    results_text.pack(expand=True, fill=tk.BOTH, pady=10)

    # Configure text styles (tags)
    results_text.tag_config('critical', foreground='red', font=('Courier New', 10, 'bold'))
    results_text.tag_config('warning', foreground='yellow')
    results_text.tag_config('ok', foreground='#39FF14') # Neon Green
    results_text.tag_config('info', foreground='#00BFFF') # Deep Sky Blue
    results_text.tag_config('header', foreground='cyan', font=('Courier New', 10, 'bold'))
    results_text.tag_config('art', foreground='cyan')
    results_text.tag_config('normal', foreground='lime')

    root.mainloop()
