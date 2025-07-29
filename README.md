# Cyber Arsenal: GUI Security Suite 🛡️

An open-source collection of advanced, GUI-based security tools written in Python. This suite features a 'hacker terminal' aesthetic and provides powerful, multi-threaded, and asynchronous utilities for network reconnaissance and web vulnerability analysis.

---
## Core Tools

<p align="center">
  <img src="https://i.imgur.com/gKjG1oP.png" alt="Deep Port Scanner GUI" width="400" />
  <img src="https://i.imgur.com/9b9Jc1N.png" alt="Intense Subdomain Finder GUI" width="400" />
</p>
<p align="center">
  <img src="https://i.imgur.com/K1L5i23.png" alt="Web Vulnerability Scanner GUI" width="400" />
</p>

---

## Features

-   **Deep Port Scanner:** A high-speed, multi-threaded port scanner with a full GUI. It scans over 1,800 common ports and performs **banner grabbing** to identify running services and versions. Includes a real-time progress bar and ETR display.

-   **Intense Subdomain Finder:** An asynchronous (`asyncio`) subdomain scanner for dramatically fast enumeration. Features **wildcard detection** to prevent false positives and performs **HTTP/S probing** on found subdomains to identify live web servers and their page titles.

-   **Web Vulnerability Scanner:** A GUI tool that scans web applications for common vulnerabilities, including **Reflected XSS**, basic **SQL Injection**, and missing **Security Headers**.

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