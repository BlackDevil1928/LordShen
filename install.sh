#!/bin/bash
# LordShen — AI-Powered CLI Pentesting Framework Installer

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo."
  exit 1
fi

echo "╔═══════════════════════════════════════╗"
echo "║   LordShen — Installation Starting    ║"
echo "╚═══════════════════════════════════════╝"

echo ""
echo "[1/7] Installing apt packages..."
apt-get update
apt-get install -y nmap masscan nikto whatweb sqlmap testssl.sh wafw00f theharvester hydra smtp-user-enum golang-go python3-pip python3-venv chromium feroxbuster libpcap-dev

echo ""
echo "[2/7] Installing Go tools..."
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &
go install -v github.com/owasp-amass/amass/v4/...@master &
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest &
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest &
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest &
go install -v github.com/ffuf/ffuf/v2@latest &
go install -v github.com/hahwul/dalfox/v2@latest &
go install -v github.com/haccer/subjack@latest &
go install -v github.com/lc/gau/v2/cmd/gau@latest &
go install -v github.com/tomnomnom/waybackurls@latest &
go install -v github.com/trufflesecurity/trufflehog/v3@latest &
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest &

wait

echo ""
echo "[3/7] Installing Python requirements..."
pip3 install -r requirements.txt

echo ""
echo "[4/7] Installing Playwright browsers..."
playwright install chromium

echo ""
echo "[5/7] Updating Nuclei templates..."
nuclei -update-templates -silent

echo ""
echo "[6/7] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh
systemctl start ollama
sleep 5
ollama pull mistral:7b

echo ""
echo "[7/7] Installing LordShen package..."
pip3 install -e .

echo "Creating config directories..."
mkdir -p ~/.lordshen/data
mkdir -p ~/.lordshen/reports
mkdir -p ~/.lordshen/scopes
mkdir -p ~/.lordshen/cache

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║   LordShen Installation Complete! ✓   ║"
echo "╠═══════════════════════════════════════╣"
echo "║                                       ║"
echo "║  Next steps:                          ║"
echo "║  1. lordshen config --groq-key <KEY>  ║"
echo "║  2. lordshen scope create <name>      ║"
echo "║  3. lordshen scan <target> -s <scope> ║"
echo "║                                       ║"
echo "╚═══════════════════════════════════════╝"
