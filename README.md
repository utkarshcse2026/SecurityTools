# Cyber Arsenal: GUI Security Suite 🛡️

An open-source collection of advanced, GUI-based security tools written in Python. This suite features a 'hacker terminal' aesthetic and provides powerful, multi-threaded, and asynchronous utilities for network reconnaissance and web vulnerability analysis.

---

## Features
---
-   **Deep Port Scanner:** A high-speed, multi-threaded port scanner with a full GUI. It scans over 1,800 common ports and performs **banner grabbing** to identify running services and versions. Includes a real-time progress bar and ETR display.

<img width="934" height="680" alt="{0A6B15FC-9C6E-42B0-9C03-113DE1D12ECA}" src="https://github.com/user-attachments/assets/d099aac5-4d84-46b2-b2c9-aa68d7acb6e0" />

---


-   **Intense Subdomain Finder:** An asynchronous (`asyncio`) subdomain scanner for dramatically fast enumeration. Features **wildcard detection** to prevent false positives and performs **HTTP/S probing** on found subdomains to identify live web servers and their page titles.

<img width="1058" height="815" alt="{9461556F-0995-4AFA-A26C-75D940AD3A7A}" src="https://github.com/user-attachments/assets/ecd836ed-d76c-4f1d-9906-815e28d4c976" />

---

-   **Web Vulnerability Scanner:** A GUI tool that scans web applications for common vulnerabilities, including **Reflected XSS**, basic **SQL Injection**, and missing **Security Headers**.

<img width="861" height="563" alt="{A5ACAFA3-9B17-488E-A02E-ADF1CC4755A2}" src="https://github.com/user-attachments/assets/69e2b3ae-e195-4819-9be0-5f644e940be1" />


---

## Installation

These tools are designed to be run from a local Python environment.

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/utkarshcse2026/Cyber-Arsenal-Suite.git](https://github.com/utkarshcse2026/Cyber-Arsenal-Suite.git)
    cd Cyber-Arsenal-Suite
    ```

2.  **Install all required libraries:**
    ```sh
    pip install requests beautifulsoup4 pynput scapy aiodns aiohttp
    ```

---

## Usage

Each tool is a standalone GUI application.

### 1. Deep Port Scanner

Launches a GUI to scan a target for open ports and services.
```sh
python deep_scanner.py
