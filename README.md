Local CAI Ollama Pentesting AI

A natural-language Blue/Red-Team pentesting assistant powered by Python and Ollama-compatible LLM providers.
You can issue commands like:

scan my router

scan 192.168.1.55 for vulnerabilities

enumerate all services

explain open ports

/model ollama:deepseek-v3.1:671b-cloud

The framework auto-detects your router IP, performs port scans, runs vulnerability checks, and sends all results for LLM-level analysis.

Default Configuration

Default provider: ollama

Default model: deepseek-v3.1:671b-cloud

Config file: config.json (generated automatically)

You can edit config.json at any time to change defaults such as:

provider URL

model

ports

nmap behaviour

proxy settings

Setup
sudo chmod +x *.sh && ./setup.sh


This installs dependencies, creates a venv, installs Python packages, and prepares the environment.

Start
./start.sh


This launches the interactive CAI prompt.

Switching Models

Use natural model-switch commands:

/model ollama:deepseek-v3.1:671b-cloud


ollama run deepseek-v3.1:671b-cloud


This updates the active model and writes the change into config.json.

Example Usage
scan my router
scan 192.168.1.1 for everything
pentest this host 192.168.1.50
explain the risks for each open port
report all vulnerabilities and fixes

Notes

Works with local Ollama and cloud providers (including 671B-scale models) as long as they expose an Ollama-compatible /generate endpoint.

Ensure you only scan systems you own or have explicit permission to test.
