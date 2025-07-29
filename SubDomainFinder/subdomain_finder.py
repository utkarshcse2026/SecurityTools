import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import asyncio
import aiodns
import aiohttp
from bs4 import BeautifulSoup
import time
import random
import string
import threading
import socket  # Added missing import

# --- Shared State & Configuration ---
start_time = 0
completed_tasks = 0
total_tasks = 0
found_subdomains = set()

# --- Core Async Scanning Logic ---

async def probe_http(session, url, results_widget):
    """Probes a URL to get status code and title."""
    try:
        async with session.get(url, timeout=3) as response:
            status = response.status
            if 200 <= status < 400:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                title = soup.find('title').get_text().strip() if soup.find('title') else "No Title"
                log_message(results_widget, f"    └── [WEB] {url} [{status}] - {title[:40]}")
    except Exception:
        pass # Ignore connection errors or timeouts

async def probe_subdomain(sub, domain, resolver, session, results_widget):
    """Probes a single subdomain via DNS, then checks for HTTP/S servers."""
    global completed_tasks, found_subdomains
    full_domain = f"{sub}.{domain}"
    try:
        # Step 1: DNS Lookup
        result = await resolver.query(full_domain, 'A')
        ip_addr = result[0].host
        
        if full_domain not in found_subdomains:
            log_message(results_widget, f"  [+] Found: {full_domain:<35} -> IP: {ip_addr}")
            found_subdomains.add(full_domain)
            
            # Step 2: Probe for web servers on the found subdomain
            await probe_http(session, f"https://{full_domain}", results_widget)
            await probe_http(session, f"http://{full_domain}", results_widget)

    except (aiodns.error.DNSError, asyncio.TimeoutError):
        pass # Subdomain does not exist or timed out
    finally:
        with print_lock:
            completed_tasks += 1

async def run_scan(domain, wordlist, results_widget, progress_bar, status_label, scan_button):
    """Main async function to orchestrate the entire scan."""
    global found_subdomains
    log_message(results_widget, f"--- [INTENSE SCAN INITIATED] TARGET: {domain} ---")
    
    log_message(results_widget, "[INFO] Performing wildcard DNS check...")
    if detect_wildcard(domain, results_widget):
        log_message(results_widget, "[CRITICAL] Wildcard DNS detected. Aborting scan to prevent false positives.")
        scan_button.config(state=tk.NORMAL, text="Start Scan")
        return

    # Setup async components
    resolver = aiodns.DNSResolver()
    async with aiohttp.ClientSession() as session:
        log_message(results_widget, f"[INFO] Launching {total_tasks} probes. This may take a moment...")
        
        tasks = [probe_subdomain(sub, domain, resolver, session, results_widget) for sub in wordlist]
        status_updater_task = asyncio.create_task(update_status(progress_bar, status_label))
        
        await asyncio.gather(*tasks)
        
        status_updater_task.cancel()

    # Finalize GUI
    progress_bar['value'] = 100
    status_label.config(text="Progress: 100% | ETR: 00m 00s")
    
    log_message(results_widget, "\n--- [SCAN COMPLETE] ---")
    log_message(results_widget, "╔════════════════════════════════════════════════════╗")
    log_message(results_widget, "║   Scanner Operation by: Utkarsh Aggarwal         ║")
    log_message(results_widget, "║   GitHub Profile: /utkarshcse2026                 ║")
    log_message(results_widget, "╚════════════════════════════════════════════════════╝")
    scan_button.config(state=tk.NORMAL, text="Start Scan")


# --- Synchronous & GUI Functions ---
print_lock = threading.Lock()

def detect_wildcard(domain, results_widget):
    """Synchronous wildcard detection."""
    random_sub = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
    try:
        socket.gethostbyname(f"{random_sub}.{domain}")
        return True
    except socket.error:
        log_message(results_widget, "[OK] No wildcard DNS detected.")
        return False

def start_scan_thread(domain_entry, results_widget, scan_button, progress_bar, status_label, wordlist_path):
    """Starts the asyncio event loop in a separate thread."""
    global completed_tasks, start_time, total_tasks, found_subdomains
    
    domain = domain_entry.get().strip()
    if not domain or not wordlist_path:
        log_message(results_widget, "[ERROR] Target domain and wordlist are required.")
        return

    # Reset state
    results_widget.config(state=tk.NORMAL); results_widget.delete('1.0', tk.END)
    scan_button.config(state=tk.DISABLED, text="Scanning...")
    completed_tasks, start_time, found_subdomains = 0, time.time(), set()

    try:
        log_message(results_widget, "[INFO] Reading wordlist into memory...")
        with open(wordlist_path, 'r', errors='ignore') as f:
            wordlist = [line.strip() for line in f if line.strip()]
        total_tasks = len(wordlist)
        log_message(results_widget, f"[OK] Wordlist loaded with {total_tasks} entries.")
    except Exception as e:
        log_message(results_widget, f"[ERROR] Failed to read wordlist: {e}")
        scan_button.config(state=tk.NORMAL, text="Start Scan")
        return
        
    def run_async_loop():
        asyncio.run(run_scan(domain, wordlist, results_widget, progress_bar, status_label, scan_button))

    threading.Thread(target=run_async_loop, daemon=True).start()

async def update_status(progress_bar, status_label):
    """Periodically updates the progress bar and ETR label in an async context."""
    while completed_tasks < total_tasks:
        if total_tasks > 0:
            progress = (completed_tasks / total_tasks) * 100
            progress_bar['value'] = progress
            elapsed = time.time() - start_time
            if completed_tasks > 0 and elapsed > 0:
                rate = completed_tasks / elapsed
                etr = (total_tasks - completed_tasks) / rate
                m, s = divmod(int(etr), 60)
                status_label.config(text=f"Progress: {int(progress)}% | ETR: {m:02d}m {s:02d}s")
            else:
                status_label.config(text="Progress: 0% | ETR: Calculating...")
        await asyncio.sleep(0.5)

def log_message(widget, message):
    """Inserts styled messages into the results widget."""
    widget.config(state=tk.NORMAL)
    tag = 'normal'
    if "[CRITICAL]" in message: tag = 'critical'
    elif "[WARNING]" in message: tag = 'warning'
    elif "[OK]" in message: tag = 'ok'
    elif "Found:" in message: tag = 'found'
    elif "[WEB]" in message: tag = 'web'
    elif "---" in message: tag = 'header'
    elif "╔" in message or "║" in message or "╚" in message: tag = 'art'
    widget.insert(tk.END, message + '\n', tag)
    widget.config(state=tk.DISABLED)
    widget.see(tk.END)

def browse_file(path_var):
    filename = filedialog.askopenfilename(title="Select a Wordlist", filetypes=(("Text files", "*.txt"),))
    if filename:
        path_var.set(filename)

# --- Main Application Setup ---

if __name__ == '__main__':
    root = tk.Tk()
    root.title("Intense Subdomain Scanner v3.2")
    root.geometry("850x650"); root.configure(bg='black')

    main_frame = tk.Frame(root, bg='black', padx=10, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    input_frame = tk.Frame(main_frame, bg='black'); input_frame.pack(fill=tk.X)
    
    tk.Label(input_frame, text="TARGET >>", font=('Courier New', 11, 'bold'), bg='black', fg='cyan').pack(side=tk.LEFT, padx=(0,5))
    domain_entry = tk.Entry(input_frame, font=('Courier New', 11), bg='#1a1a1a', fg='lime', insertbackground='lime', borderwidth=0)
    domain_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, ipady=4); domain_entry.insert(0, "example.com")

    wordlist_path = tk.StringVar()
    tk.Button(input_frame, text="Wordlist", font=('Courier New', 10, 'bold'), bg='#1a1a1a', fg='cyan', activebackground='cyan', activeforeground='black', borderwidth=0, padx=10, command=lambda: browse_file(wordlist_path)).pack(side=tk.LEFT, padx=10)
    
    scan_button = tk.Button(input_frame, text="Start Scan", font=('Courier New', 10, 'bold'), bg='#1a1a1a', fg='lime', activebackground='lime', activeforeground='black', borderwidth=0, padx=10)
    scan_button.pack(side=tk.LEFT, padx=10)
    
    results_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=('Courier New', 10), bg='black', fg='lime', borderwidth=0, state=tk.DISABLED)
    results_text.pack(expand=True, fill=tk.BOTH, pady=10)
    
    status_frame = tk.Frame(main_frame, bg='black'); status_frame.pack(fill=tk.X, side=tk.BOTTOM)
    progress_bar = ttk.Progressbar(status_frame, orient='horizontal', mode='determinate')
    progress_bar.pack(side=tk.LEFT, expand=True, fill=tk.X)
    status_label = tk.Label(status_frame, text="Progress: 0% | ETR: --m --s", font=('Courier New', 9), bg='black', fg='cyan')
    status_label.pack(side=tk.LEFT, padx=5)
    
    scan_button.config(command=lambda: start_scan_thread(domain_entry, results_text, scan_button, progress_bar, status_label, wordlist_path.get()))
    domain_entry.bind("<Return>", lambda e: start_scan_thread(domain_entry, results_text, scan_button, progress_bar, status_label, wordlist_path.get()))
    
    results_text.tag_config('critical', foreground='red', font=('Courier New', 10, 'bold'))
    results_text.tag_config('warning', foreground='yellow')
    results_text.tag_config('ok', foreground='#39FF14')
    results_text.tag_config('found', foreground='lime', font=('Courier New', 10, 'bold'))
    results_text.tag_config('header', foreground='cyan', font=('Courier New', 10, 'bold'))
    results_text.tag_config('art', foreground='cyan')
    results_text.tag_config('web', foreground='#cccccc')
    results_text.tag_config('normal', foreground='#cccccc') 

    root.mainloop()
