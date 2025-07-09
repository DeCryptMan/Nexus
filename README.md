# Cerberus v5.1 - Sentinel Nexus

Cerberus is a powerful and intuitive network vulnerability scanner built with Python and Textual, offering a rich terminal user interface (TUI). It allows users to scan target hosts and specified ports for open services and identifies potential vulnerabilities based on banner information against a predefined CVE database.

## Features

* **Fast Asynchronous Scanning**: Utilizes `asyncio` for high-concurrency port scanning.
* **Real-time Host Resolution**: Resolves hostnames to IP addresses.
* **Banner Grabbing**: Collects service banners from open ports.
* **CVE Database Integration**: Checks discovered service banners against a local CVE database to identify known vulnerabilities.
* **Interactive TUI**: Built with Textual for a responsive and user-friendly experience in the terminal.
* **Configurable Scans**: Easily specify target hosts (IPs or domains) and port ranges.
* **Progress Monitoring**: Displays scan progress and found vulnerabilities in real-time.
* **Report Saving**: Export scan results to a JSON file.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/DeCryptMan/Cerberus.git](https://github.com/DeCryptMan/Cerberus.git)
    cd Cerberus
    ```
    *(Note: The actual repository URL might differ if this is not an existing public repository.)*

2.  **Create a virtual environment** (recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Prepare the CVE Database**:
    Ensure you have a `cve_db.json` file in the same directory as `main.py`. An example `cve_db.json` is provided with common vulnerabilities for demonstration purposes.

    ```json
    {
      "vsFTPd 2.3.4": {
        "cve": "CVE-2011-2523",
        "severity": "CRITICAL",
        "details": "Выполнение произвольного кода через бэкдор в vsFTPd."
      },
      "ProFTPD 1.3.5": {
        "cve": "CVE-2015-3306",
        "severity": "HIGH",
        "details": "Уязвимость 'mod_copy' позволяет копировать файлы на сервере."
      },
      "OpenSSH 7.7": {
        "cve": "CVE-2018-15473",
        "severity": "MEDIUM",
        "details": "Перечисление пользователей (User Enumeration)."
      },
      "Apache/2.4.29": {
        "cve": "CVE-2017-15715",
        "severity": "HIGH",
        "details": "Обход ограничений доступа к файлам через директиву <Files>."
      },
      "Microsoft-IIS/7.5": {
        "cve": "CVE-2017-7269",
        "severity": "CRITICAL",
        "details": "Переполнение буфера в WebDAV (RCE)."
      },
      "nginx/1.18.0": {
        "cve": "CVE-2021-23017",
        "severity": "MEDIUM",
        "details": "Уязвимость в обработке DNS-ответов может привести к утечке памяти."
      }
    }
    ```

## Usage

To start the Cerberus scanner, run the `main.py` file:

```bash
python main.py
