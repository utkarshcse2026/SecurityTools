import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
from queue import Queue
import time

# --- Main Scanning Logic & Data ---

# Expanded list of common ports for a deeper scan
PORTS_TO_SCAN = list(range(1, 1025)) + [
    1080, 1100, 1433, 1434, 1521, 1900, 2049, 2323, 3268, 3306, 3389, 4444, 
    4899, 5000, 5432, 5631, 5800, 5900, 5901, 6000, 6001, 6646, 7001, 8000, 
    8008, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152
]
TOTAL_PORTS = len(PORTS_TO_SCAN)

# Shared resources for threads
port_queue = Queue()
completed_ports = 0
print_lock = threading.Lock()
start_time = 0

def scan_port(port, target_host, results_widget):
    """Scans a single port and logs the result."""
    global completed_ports
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_host, port))
        if result == 0:
            log_message(results_widget, f"  [+] Port {port:<5} Open")
        sock.close()
    except socket.error:
        pass # Silently ignore connection errors
    finally:
        with print_lock:
            completed_ports += 1

def worker_thread(target_host, results_widget):
    """Pulls a port from the queue and scans it."""
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(port, target_host, results_widget)
        port_queue.task_done()

# --- GUI Functions ---

def start_scan_thread(url_entry, results_widget, scan_button, progress_bar, status_label):
    """Starts the scanning process in a separate thread."""
    global completed_ports, start_time
    target = url_entry.get()
    if not target:
        log_message(results_widget, "[ERROR] Please enter a target host or IP.")
        return
    
    # Reset state for a new scan
    results_widget.config(state=tk.NORMAL)
    results_widget.delete('1.0', tk.END)
    scan_button.config(state=tk.DISABLED, text="Scanning...")
    completed_ports = 0
    start_time = time.time()
    
    # Clear and fill the queue
    while not port_queue.empty():
        port_queue.get()
    for port in PORTS_TO_SCAN:
        port_queue.put(port)

    def run_scan():
        log_message(results_widget, f"--- [SCAN INITIATED] TARGET: {target} ---")
        
        threads = []
        for _ in range(200): # Increased threads for speed
            thread = threading.Thread(target=worker_thread, args=(target, results_widget), daemon=True)
            threads.append(thread)
            thread.start()
        
        # Start the status update loop
        update_status(results_widget, progress_bar, status_label)

        for thread in threads:
            thread.join() # Wait for all worker threads to finish

        # Final attribution
        log_message(results_widget, "\n--- [SCAN COMPLETE] ---")
        log_message(results_widget, "╔════════════════════════════════════════════════════╗")
        log_message(results_widget, "║   Scanner Operation by: Utkarsh Aggarwal         ║")
        log_message(results_widget, "║   GitHub Profile: /utkarshcse2026                 ║")
        log_message(results_widget, "╚════════════════════════════════════════════════════╝")
        scan_button.config(state=tk.NORMAL, text="Start Scan")

    main_scan_thread = threading.Thread(target=run_scan, daemon=True)
    main_scan_thread.start()

def update_status(results_widget, progress_bar, status_label):
    """Periodically updates the progress bar and ETR label."""
    if completed_ports < TOTAL_PORTS:
        # Update progress bar
        progress = (completed_ports / TOTAL_PORTS) * 100
        progress_bar['value'] = progress

        # Calculate ETR
        elapsed_time = time.time() - start_time
        if completed_ports > 0 and elapsed_time > 0:
            ports_per_second = completed_ports / elapsed_time
            remaining_ports = TOTAL_PORTS - completed_ports
            etr_seconds = remaining_ports / ports_per_second
            etr_minutes, etr_secs = divmod(int(etr_seconds), 60)
            status_text = f"Progress: {int(progress)}% | ETR: {etr_minutes:02d}m {etr_secs:02d}s"
        else:
            status_text = "Progress: 0% | ETR: Calculating..."
        
        status_label.config(text=status_text)
        
        # Schedule the next update
        results_widget.after(500, lambda: update_status(results_widget, progress_bar, status_label))
    else:
        progress_bar['value'] = 100
        status_label.config(text="Progress: 100% | ETR: 00m 00s")


def log_message(widget, message):
    """Thread-safe way to insert styled messages."""
    widget.config(state=tk.NORMAL)
    widget.insert(tk.END, message + '\n')
    widget.see(tk.END)
    widget.config(state=tk.DISABLED)

# --- Main Application Setup ---

if __name__ == '__main__':
    root = tk.Tk()
    root.title("Port Scanner v2.0")
    root.geometry("650x500")
    root.configure(bg='black')

    main_frame = tk.Frame(root, bg='black', padx=10, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    input_frame = tk.Frame(main_frame, bg='black')
    input_frame.pack(fill=tk.X)
    
    url_label = tk.Label(input_frame, text="TARGET >>", font=('Courier New', 11, 'bold'), bg='black', fg='cyan')
    url_label.pack(side=tk.LEFT, padx=5)

    url_entry = tk.Entry(input_frame, font=('Courier New', 11), width=50, bg='#1a1a1a', fg='lime', insertbackground='lime', borderwidth=0)
    url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, ipady=4)
    url_entry.insert(0, "scanme.nmap.org")

    scan_button = tk.Button(input_frame, text="Start Scan", font=('Courier New', 10, 'bold'), bg='#1a1a1a', fg='lime',
                            activebackground='lime', activeforeground='black', borderwidth=0, padx=10)
    scan_button.pack(side=tk.LEFT, padx=10)

    results_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=('Courier New', 10), bg='black', fg='lime',
                                             borderwidth=0, state=tk.DISABLED)
    results_text.pack(expand=True, fill=tk.BOTH, pady=10)
    
    status_frame = tk.Frame(main_frame, bg='black')
    status_frame.pack(fill=tk.X, side=tk.BOTTOM)

    progress_bar = ttk.Progressbar(status_frame, orient='horizontal', length=100, mode='determinate')
    progress_bar.pack(side=tk.LEFT, expand=True, fill=tk.X)
    
    status_label = tk.Label(status_frame, text="Progress: 0% | ETR: --m --s", font=('Courier New', 9), bg='black', fg='cyan')
    status_label.pack(side=tk.LEFT, padx=5)
    
    # Configure command for the button after all widgets are created
    scan_button.config(command=lambda: start_scan_thread(url_entry, results_text, scan_button, progress_bar, status_label))
    url_entry.bind("<Return>", lambda event: start_scan_thread(url_entry, results_text, scan_button, progress_bar, status_label))

    root.mainloop()
