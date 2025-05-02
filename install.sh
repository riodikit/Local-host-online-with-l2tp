#!/bin/bash

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root" >&2
    echo "Please run: sudo bash $0"
    exit 1
fi

# Exit on error
set -e

echo "===== L2TP/IPsec VPN SERVER INSTALLER ====="
echo "This script will install and configure L2TP/IPsec VPN server on Ubuntu"
echo

# Function to handle errors
handle_error() {
    echo "Error occurred at line $1. Installation failed." >&2
    exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

echo "=== UPDATING SYSTEM PACKAGES ==="
apt update || { echo "Failed to update package lists"; exit 1; }

echo "=== INSTALLING REQUIRED DEPENDENCIES ==="
apt install -y strongswan xl2tpd iptables-persistent python3 || {
    echo "Failed to install required packages. Please check your internet connection and try again."
    exit 1
}

echo "=== RUNNING L2TP CONFIGURATION SCRIPT ==="
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
cd "$SCRIPT_DIR" || { echo "Failed to change directory"; exit 1; }

python3 l2tp_config.py || {
    echo "Configuration script failed. Please check the error messages above."
    exit 1
}

echo "\n===== INSTALLATION COMPLETED SUCCESSFULLY ====="
echo "Your L2TP/IPsec VPN server has been installed and configured."
