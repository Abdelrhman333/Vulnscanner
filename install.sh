#!/bin/bash

echo "[*] Installing Python libraries..."
pip install -r requirements.txt

# Check if Go is installed
if ! command -v go &> /dev/null
then
    echo "[!] Go is not installed. Installing Go..."

    # Download & install Go (Linux AMD64)
    wget https://go.dev/dl/go1.21.1.linux-amd64.tar.gz -O go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go.tar.gz
    echo "export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin" >> ~/.bashrc
    source ~/.bashrc

    echo "[+] Go installed successfully."
else
    echo "[+] Go is already installed."
fi

echo "[*] Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[*] Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

echo "[*] Installing SQLMap..."
sudo apt install sqlmap -y

echo "[*] Cloning XSStrike..."
git clone https://github.com/s0md3v/XSStrike.git

echo "[+] Installation complete!"
echo " Make sure you reload your terminal or run: source ~/.bashrc"
