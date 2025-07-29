import requests
import sys

def find_subdomains(domain, wordlist_path):
    """Finds valid subdomains for a given domain using a wordlist."""
    
    print("-" * 50)
    print(f"Searching for subdomains for: {domain}")
    print("-" * 50)
    
    discovered_subdomains = []
    
    try:
        with open(wordlist_path, 'r') as file:
            for line in file:
                subdomain = line.strip()
                # Construct the full URL to test
                url = f"http://{subdomain}.{domain}"
                
                try:
                    # Make a request to the URL
                    requests.get(url, timeout=2)
                except requests.ConnectionError:
                    # If it fails to connect, we assume the subdomain does not exist
                    pass
                else:
                    print(f"[+] Discovered Subdomain: {url}")
                    discovered_subdomains.append(url)
                    
    except FileNotFoundError:
        print(f"[!] Wordlist file not found at: {wordlist_path}")
        # We use 'return' instead of 'sys.exit()' to allow the script to continue to the next domain
        return
    except KeyboardInterrupt:
        print("\n[!] User cancelled scan for this domain.")
        return

    print("-" * 50)
    if not discovered_subdomains:
        print("No subdomains discovered for this domain with the given wordlist.")


if __name__ == "__main__":
    # Check if enough arguments are provided (script name, at least one domain, wordlist)
    if len(sys.argv) < 3:
        print("Usage: python subdomain_finder.py <domain1> [domain2...] <wordlist_path>")
        print("Example: python subdomain_finder.py google.com github.com wordlist.txt")
        sys.exit()
        
    # The last argument is always the wordlist path
    wordlist_file = sys.argv[-1]
    # The domains are all arguments between the script name and the wordlist path
    domain_list = sys.argv[1:-1]
    
    # Loop through each domain provided and scan it
    for domain_name in domain_list:
        find_subdomains(domain_name, wordlist_file)
        print("\n") # Add a space before starting the next scan

    print("All scans complete.")