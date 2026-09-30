#!/bin/bash
# AutoPentest AI Installer Script

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo."
  exit 1
fi

echo "Installing apt packages..."
apt-get update
apt-get install -y nmap masscan nikto whatweb sqlmap testssl.sh wafw00f theharvester hydra smtp-user-enum golang-go python3-pip python3-venv chromium feroxbuster libpcap-dev

echo "Installing Go tools..."
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

echo "Installing python requirements..."
pip3 install -r requirements.txt

echo "Installing Playwright browsers..."
playwright install chromium

echo "Updating Nuclei templates..."
nuclei -update-templates -silent

echo "Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh
systemctl start ollama
sleep 5
ollama pull mistral:7b

echo "Installing python package..."
pip3 install -e .

echo "Creating config directories..."
mkdir -p ~/.autopentest/data
mkdir -p ~/.autopentest/reports

echo "========================================="
echo "   AutoPentest AI Installation Complete  "
echo "========================================="
