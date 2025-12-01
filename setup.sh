#!/bin/bash
# (c) J~Net 2025
#
python -m venv venv



sudo apt -y update && sudo apt install -y python3 python3-venv python3-pip nmap

python3 -m venv venv
source venv/bin/activate

echo "Virtual Environment Setup and ready!"

pip install -r requirements.txt
pip install --upgrade pip >/dev/null 2>&1
pip install requests >/dev/null 2>&1
# python3 ./cai_ollama.py
echo "To run type ./start.sh"


