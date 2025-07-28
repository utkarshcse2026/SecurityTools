# Cybersecurity Tool Suite 🛡️

A collection of lightweight, command-line security tools written in Python. This suite provides essential utilities for network reconnaissance and defensive security tasks, perfect for security professionals, developers, and hobbyists.

---

## Features

-   **Network Port Scanner:** A fast, multi-threaded scanner to quickly discover open ports on a target host.
-   **Subdomain Finder:** A versatile script to enumerate subdomains for one or more target domains using a custom wordlist.
-   **File Integrity Checker:** A defensive tool to monitor directories for unauthorized file modifications, additions, or deletions using SHA-256 hashes.

---

## Getting Started

These tools are designed to be run directly from the command line.

### Prerequisites

-   Python 3.x
-   The `requests` library is required **only** for the Subdomain Finder.

### Installation

1.  Clone the repository:
    ```sh
    git clone [https://github.com/utkarshcse2026/Cybersecurity-Tool-Suite.git](https://github.com/utkarshcse2026/Cybersecurity-Tool-Suite.git)
    cd Cybersecurity-Tool-Suite
    ```
2.  Install the required package for the Subdomain Finder:
    ```sh
    pip install requests
    ```

---

## Usage

Here is how to use each tool in the suite.

### 1. Port Scanner

This script discovers open ports on a single target.

<img width="782" height="197" alt="image" src="https://github.com/user-attachments/assets/1fbb8aea-e97d-4eb0-b264-0e45f99eadd8" />

<img width="833" height="193" alt="image" src="https://github.com/user-attachments/assets/1f19545b-22fa-4610-a6dc-53018c0d6444" />


```sh
python port_scanner.py <target_host>

