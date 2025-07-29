import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def get_forms(url):
    """Extracts all HTML forms from a given URL."""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException as e:
        print(f"[-] Could not connect to {url}: {e}")
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

    if method == 'post':
        return requests.post(post_url, data=data)
    else:
        return requests.get(post_url, params=data)

def scan_xss(url):
    """Scans for reflected XSS vulnerabilities."""
    print(f"\n[+] Scanning for XSS in {url}")
    forms = get_forms(url)
    if not forms:
        print("[-] No forms found to test for XSS.")
        return False
        
    # A simple, non-malicious XSS payload
    xss_payload = "<script>alert('xss')</script>"
    xss_found = False

    for form in forms:
        response = submit_form(form, xss_payload, url)
        if xss_payload in response.content.decode(errors='ignore'):
            print(f"[!] XSS vulnerability discovered in a form at {url}")
            print(f"    -> Form details: {form}")
            xss_found = True
    
    if not xss_found:
        print("[-] No obvious XSS vulnerabilities found.")
    return xss_found

if __name__ == '__main__':
    target_url = input("Enter the URL to scan (e.g., http://testphp.vulnweb.com/login.php): ")
    scan_xss(target_url)