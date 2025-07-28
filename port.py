import socket
import sys
import threading
from queue import Queue
from datetime import datetime

# A thread-safe print lock
print_lock = threading.Lock()
target_host = ""

def scan_port(port):
    """Scans a single port on the target host."""
    try:
        # Create a new socket for each thread
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1) # Timeout for the connection attempt

        # Attempt to connect
        result = sock.connect_ex((target_host, port))
        if result == 0:
            # Use lock to prevent messy printing from multiple threads
            with print_lock:
                print(f"Port {port}:    Open")
        sock.close()
    except socket.error as e:
        # This will likely not be hit due to connect_ex, but good practice
        with print_lock:
            print(f"Could not connect to port {port}: {e}")

def threader():
    """Pulls a worker (port) from the queue and scans it."""
    while True:
        worker = port_queue.get()
        scan_port(worker)
        port_queue.task_done()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python port.py <target>")
        print("Example: python port.py scanme.nmap.org")
        sys.exit()

    target_host = sys.argv[1]
    port_queue = Queue()

    print("-" * 50)
    print(f"Scanning Target: {target_host}")
    print(f"Time Started: {datetime.now()}")
    print("-" * 50)

    # Create and start 100 worker threads
    for _ in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True  # Allows main program to exit even if threads are running
        t.start()
    
    # Put all ports to be scanned into the queue
    for worker_port in range(1, 1025):
        port_queue.put(worker_port)
    
    # Wait until the queue is empty and all threads have finished
    port_queue.join()

    print("-" * 50)
    print("Scan Complete.")