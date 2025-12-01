Local CAI Ollama Pentesting AI
https://github.com/jamieduk/cai-ollama-python-ai

A natural-language Blue/Red-Team pentesting assistant powered by Python, Ollama-compatible LLMs, and auto-generated modules.
You can speak to it like a human:

scan my router
scan 192.168.1.55 for vulnerabilities
enumerate all services
explain open ports
run a full recon pack on 192.168.56.103


The framework automatically:

detects your router IP

performs Nmap scans

generates new security modules when required

runs vulnerability checks

analyses results using your configured LLM

suggests a safe next step command

Everything runs locally unless you configure a cloud provider.

Default Configuration

Default provider: ollama

Default model: deepseek-v3.1:671b-cloud

Config file: config.json (generated automatically)

Runtime: Python virtual environment inside the project folder

You can edit config.json to change:

model

provider or proxy URL

nmap ports / arguments

auto-next-step behaviour

logging options

Setup
sudo chmod +x *.sh && ./setup.sh

This:

installs dependencies

creates a venv

downloads Python packages

prepares the CAI environment

Start the AI

sudo ./start.sh 


This launches the interactive CAI CLI:

cai>

Switching Models

ollama run deepseek-v3.1:671b-cloud

You can switch models naturally:

/model ollama:deepseek-v3.1:671b-cloud

This immediately updates the active model and rewrites config.json.

This program assumes you already have ollama and model

curl -fsSL https://ollama.com/install.sh | sh && ollama run deepseek-v3.1:671b-cloud


Example Usage
scan my router
scan 192.168.1.1 for everything
pentest this host 192.168.1.50
explain the risks for each open port
report all vulnerabilities and fixes

Examples that trigger new module generation

Use these to test the module-builder system:

perform a full attack-surface map of 192.168.56.201 including dns, tls, headers, js analysis and subdomain finder

audit my dvwa site at 192.168.56.103 including plugin checks and cve lookup

run a full recon pack on 192.168.56.205 including dns, whois, tls, crawler and tech fingerprinting


These force CAI to create modules such as:

DNS lookup

WHOIS

TLS scanner

JS library auditor

CVE lookup

Header analyser

Subdomain finder

Directory discovery

Tech-stack fingerprinting

Notes

Works with local Ollama and cloud LLM providers that expose an Ollama-compatible /generate endpoint.

Supports models up to 671B via cloud endpoints.

CAI will only analyse systems you explicitly instruct it to.

<img width="986" height="670" alt="Screenshot-01" src="https://github.com/user-attachments/assets/35391a83-126d-4adb-86a3-016d1732e2ec" />

<img width="986" height="670" alt="Screenshot-02" src="https://github.com/user-attachments/assets/28da45ec-7f63-413f-be73-69657be4e9ff" />


Only scan systems you own or have written permission to test.


