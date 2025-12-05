#!/bin/bash
# CAI Launcher (c) J~Net 2025
#

mkdir -p logs modules

echo "To allow nmap scanning CAI will need to allow nmap without requiring sudo"
echo "Or if you prefere, run with sudo like sudo ./start.sh"
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)

echo ""

if [ ! -d venv ];then
    python3 -m venv venv
fi

source venv/bin/activate

if [ ! -f config.json ]; then
cat <<EOF > config.json
{
"model":"deepseek-v3.1:671b-cloud",
"full_auto_next_step":0,
"default_scan_ip":"192.168.1.1",
"mode":"1"
}
EOF
echo "Created default config.json"
fi

echo "CAI Ollama By J~Net (c) 2025"
echo ""
python3 ./cai_ollama.py
