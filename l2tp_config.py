#!/usr/bin/env python3
import subprocess
import os
import sys
import re
from pathlib import Path

def run(cmd):
    print(f"[+] Menjalankan: {cmd}")
    try:
        return subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: {e}")
        print(f"[!] Output: {e.stdout}")
        print(f"[!] Error output: {e.stderr}")
        return None

def write(path, content):
    try:
        # Ensure directory exists
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        
        # Backup existing file if it exists
        if os.path.exists(path):
            backup_path = f"{path}.bak"
            os.rename(path, backup_path)
            print(f"[+] Backup dibuat: {backup_path}")
            
        with open(path, "w") as f:
            f.write(content)
        print(f"[+] Diperbarui: {path}")
        return True
    except Exception as e:
        print(f"[!] Error menulis ke {path}: {e}")
        return False

def check_root():
    if os.geteuid() != 0:
        print("[!] Error: Script ini harus dijalankan sebagai root")
        print("[!] Jalankan: sudo python3 l2tp_config.py")
        sys.exit(1)

def configure_ipsec():
    print("\n=== CONFIGURE IPSEC ===")
    # Generate a random PSK if user wants
    print("PSK (Pre-Shared Key) digunakan untuk autentikasi koneksi VPN")
    print("Anda dapat menggunakan PSK yang dibuat sendiri atau menggunakan PSK acak yang aman")
    generate_random = input("Generate PSK acak? (y/n) [y]: ").strip().lower()
    
    if not generate_random or generate_random == 'y':
        # Generate a random 16-character PSK
        import random
        import string
        chars = string.ascii_letters + string.digits + '!@#$%^&*()'
        psk = ''.join(random.choice(chars) for _ in range(16))
        print(f"[+] PSK acak dibuat: {psk}")
    else:
        psk = input("Masukkan PSK (Pre-Shared Key): ").strip()
        while not psk:
            print("[!] PSK tidak boleh kosong")
            psk = input("Masukkan PSK (Pre-Shared Key): ").strip()

    ipsec_conf = """
config setup
    uniqueids=no
    charondebug="ike 2, knl 2, net 2, dmn 2, mgr 2"

conn %default
    keyexchange=ikev2
    authby=secret
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1

conn L2TP
    keyexchange=ikev1
    left=%any
    leftprotoport=17/1701
    right=%any
    rightdns=8.8.8.8,8.8.4.4
    rightsourceip=10.0.0.100-200
    auto=add
"""
    write("/etc/ipsec.conf", ipsec_conf.strip() + "\n")
    write("/etc/ipsec.secrets", f"%any : PSK \"{psk}\"\n")
    
    return psk

def configure_xl2tpd():
    print("\n=== CONFIGURE xl2tpd ===")
    xl2tpd_conf = """
[global]
ipsec saref = yes
listen-addr = 0.0.0.0
max redials = 0

[lns default]
ip range = 10.0.0.100-200
local ip = 10.0.0.1
require chap = yes
refuse pap = yes
length bit = 128
name = L2TPServer
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
"""
    write("/etc/xl2tpd/xl2tpd.conf", xl2tpd_conf.strip() + "\n")

    ppp_opts = """
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
auth
mtu 1200
mru 1200
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
"""
    write("/etc/ppp/options.xl2tpd", ppp_opts.strip() + "\n")

def enable_ip_forwarding():
    print("\n=== ENABLE IP FORWARDING ===")
    sysctl_conf = "/etc/sysctl.conf"
    lines = open(sysctl_conf).read().splitlines()
    with open(sysctl_conf, "w") as f:
        found = False
        for l in lines:
            if l.strip().startswith("net.ipv4.ip_forward"):
                f.write("net.ipv4.ip_forward=1\n")
                found = True
            else:
                f.write(l + "\n")
        if not found:
            f.write("net.ipv4.ip_forward=1\n")
    run("sysctl -p")

def get_network_interfaces():
    try:
        # Get list of available network interfaces
        result = subprocess.run("ip -o link show | awk -F': ' '{print $2}'" , 
                               shell=True, check=True, stdout=subprocess.PIPE, text=True)
        interfaces = [iface for iface in result.stdout.strip().split('\n') if iface != 'lo']
        return interfaces
    except Exception as e:
        print(f"[!] Error mendapatkan daftar interface: {e}")
        return []

def configure_iptables():
    print("\n=== IPTABLES SETUP ===")
    # 1. POSTROUTING MASQUERADE
    print("\nContoh: iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    out_if = input("Masukkan interface OUTPUT (POSTROUTING): ").strip()
    run(f"iptables -t nat -A POSTROUTING -o {out_if} -j MASQUERADE")

    # 2. FORWARD RELATED,ESTABLISHED
    print("\nContoh: iptables -A FORWARD -i eth0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
    in_if  = input("Masukkan interface INPUT (established): ").strip()
    ppp_if = input("Masukkan interface PPP (established): ").strip()
    run(f"iptables -A FORWARD -i {in_if} -o {ppp_if} -m state --state RELATED,ESTABLISHED -j ACCEPT")

    # 3. FORWARD reverse
    print("\nContoh: iptables -A FORWARD -i ppp0 -o eth0 -j ACCEPT")
    in_rev  = input("Masukkan interface INPUT (reverse): ").strip()
    out_rev = input("Masukkan interface OUTPUT (reverse): ").strip()
    run(f"iptables -A FORWARD -i {in_rev} -o {out_rev} -j ACCEPT")
    
    # Save iptables rules
    print("\n[+] Menyimpan aturan iptables...")
    run("netfilter-persistent save")
    
    # Create a script to restore iptables rules on reboot
    iptables_script = """
#!/bin/bash
# L2TP VPN iptables rules

# Clear existing rules
iptables -t nat -F POSTROUTING
iptables -F FORWARD

# Apply rules
iptables -t nat -A POSTROUTING -o {0} -j MASQUERADE
iptables -A FORWARD -i {1} -o {2} -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i {3} -o {4} -j ACCEPT

exit 0
""".format(out_if, in_if, ppp_if, in_rev, out_rev)
    
    write("/etc/iptables/l2tp-iptables.sh", iptables_script)
    run("chmod +x /etc/iptables/l2tp-iptables.sh")
    
    # Add to rc.local if it exists
    if os.path.exists("/etc/rc.local"):
        with open("/etc/rc.local", "r") as f:
            rc_content = f.read()
        
        if "/etc/iptables/l2tp-iptables.sh" not in rc_content:
            # Add before exit 0
            if "exit 0" in rc_content:
                rc_content = rc_content.replace("exit 0", "/etc/iptables/l2tp-iptables.sh\nexit 0")
            else:
                rc_content += "\n/etc/iptables/l2tp-iptables.sh\n"
            
            write("/etc/rc.local", rc_content)
            run("chmod +x /etc/rc.local")
    else:
        # Create rc.local if it doesn't exist
        rc_local = """#!/bin/bash
/etc/iptables/l2tp-iptables.sh
exit 0
"""
        write("/etc/rc.local", rc_local)
        run("chmod +x /etc/rc.local")

def restart_services():
    print("\n=== RESTART SERVICES ===")
    run("systemctl restart strongswan")
    run("systemctl restart xl2tpd")

def add_vpn_user():
    print("\n=== TAMBAH USER VPN ===")
    print("Anda akan menambahkan user untuk koneksi VPN")
    
    # Get username
    username = input("Masukkan username: ").strip()
    while not username or ' ' in username:
        print("[!] Username tidak boleh kosong atau mengandung spasi")
        username = input("Masukkan username: ").strip()
    
    # Get password or generate random one
    generate_random = input("Generate password acak? (y/n) [y]: ").strip().lower()
    if not generate_random or generate_random == 'y':
        # Generate a random 12-character password
        import random
        import string
        chars = string.ascii_letters + string.digits + '!@#$%'
        password = ''.join(random.choice(chars) for _ in range(12))
        print(f"[+] Password acak dibuat: {password}")
    else:
        password = input("Masukkan password: ").strip()
        while not password:
            print("[!] Password tidak boleh kosong")
            password = input("Masukkan password: ").strip()
    
    # Add user to chap-secrets
    chap_secrets_path = "/etc/ppp/chap-secrets"
    
    # Backup existing file
    if os.path.exists(chap_secrets_path):
        backup_path = f"{chap_secrets_path}.bak"
        os.rename(chap_secrets_path, backup_path)
        print(f"[+] Backup dibuat: {backup_path}")
    
    # Read existing content or create new
    if os.path.exists(backup_path):
        with open(backup_path, "r") as f:
            content = f.read()
    else:
        content = "# Secrets for authentication using CHAP\n"
        content += "# client\tserver\tsecret\t\t\tIP addresses\n"
    
    # Check if user already exists
    lines = content.splitlines()
    user_exists = False
    for i, line in enumerate(lines):
        if line.strip() and not line.strip().startswith('#'):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == username:
                user_exists = True
                lines[i] = f"{username}\tl2tpd\t{password}\t*"
                break
    
    # Add user if doesn't exist
    if not user_exists:
        lines.append(f"{username}\tl2tpd\t{password}\t*")
    
    # Write updated content
    with open(chap_secrets_path, "w") as f:
        f.write('\n'.join(lines) + '\n')
    
    print(f"\n✅ User VPN berhasil ditambahkan:")
    print(f"   Username: {username}")
    print(f"   Password: {password}")
    print(f"   File: {chap_secrets_path}")
    
    return username, password

def show_connection_info(psk=None, username=None, password=None):
    print("\n=== INFORMASI KONEKSI VPN ===")
    
    # Get server IP
    try:
        result = subprocess.run("curl -s ifconfig.me", shell=True, check=True, stdout=subprocess.PIPE, text=True)
        public_ip = result.stdout.strip()
    except:
        try:
            result = subprocess.run("wget -qO- ifconfig.me", shell=True, check=True, stdout=subprocess.PIPE, text=True)
            public_ip = result.stdout.strip()
        except:
            public_ip = "<IP SERVER ANDA>"
    
    # Get PSK if not provided
    if not psk:
        try:
            with open("/etc/ipsec.secrets", "r") as f:
                for line in f:
                    if "PSK" in line:
                        psk = line.split('"')[1]
                        break
        except:
            psk = "<PSK ANDA>"
    
    # Get username and password if not provided
    if not username or not password:
        try:
            with open("/etc/ppp/chap-secrets", "r") as f:
                for line in f:
                    if line.strip() and not line.strip().startswith('#'):
                        parts = line.split()
                        if len(parts) >= 3:
                            username = parts[0]
                            password = parts[2]
                            break
        except:
            username = "<USERNAME ANDA>"
            password = "<PASSWORD ANDA>"
    
    print("\nGunakan informasi berikut untuk mengkonfigurasi klien VPN L2TP/IPsec:")
    print(f"\nServer IP     : {public_ip}")
    print(f"Pre-Shared Key: {psk}")
    print(f"Username      : {username}")
    print(f"Password      : {password}")
    print(f"\nCatatan: Pastikan opsi 'IPsec' atau 'L2TP/IPsec dengan PSK' diaktifkan pada klien VPN Anda.")

def main():
    print("=== L2TP/IPsec VPN Auto-Configuration ===")
    print("Script ini akan mengkonfigurasi server VPN L2TP/IPsec pada Ubuntu")
    
    # Check if running as root
    check_root()
    
    # Configure components
    psk = None
    username = None
    password = None
    
    try:
        # Configure IPsec
        psk = configure_ipsec()
        
        # Configure xl2tpd
        configure_xl2tpd()
        
        # Enable IP forwarding
        enable_ip_forwarding()
        
        # Configure iptables
        configure_iptables()
        
        # Add VPN user
        username, password = add_vpn_user()
        
        # Restart services
        restart_services()
        
        # Show connection info
        show_connection_info(psk, username, password)
        
        print("\n✅ Setup selesai. L2TP/IPsec VPN siap digunakan.")
        print("   Untuk menambahkan user baru, jalankan: sudo python3 l2tp_config.py --add-user")
        
    except KeyboardInterrupt:
        print("\n[!] Konfigurasi dibatalkan oleh user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        print("[!] Konfigurasi gagal. Silakan coba lagi.")
        sys.exit(1)

if __name__ == "__main__":
    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--add-user":
        check_root()
        username, password = add_vpn_user()
        restart_services()
        show_connection_info(username=username, password=password)
    else:
        main()
