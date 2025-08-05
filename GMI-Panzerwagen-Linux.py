#!/usr/bin/env python3
import os
import subprocess
from cryptography.fernet import Fernet

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"
BG_BLACK = "\033[40m"

def clear_screen():
    os.system('clear')

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error: {e.stderr}{RESET}")
        return None

def get_distro():
    try:
        with open("/etc/os-release") as f:
            data = f.read().lower()
            if "arch" in data:
                return "arch"
            elif "debian" in data or "kali" in data or "ubuntu" in data:
                return "debian"
    except:
        pass
    return None

def install_dependencies():
    distro = get_distro()
    print(f"{BLUE}[*] Detecting distribution...{RESET}")
    
    if distro == "arch":
        print(f"{BLUE}[*] Installing dependencies on BlackArch...{RESET}")
        run_command("sudo pacman -Sy --noconfirm nmap metasploit")
    elif distro == "debian":
        print(f"{BLUE}[*] Installing dependencies on Kali Linux...{RESET}")
        run_command("sudo apt update && sudo apt install -y nmap metasploit-framework")
    else:
        print(f"{RED}[!] Distribution not detected. Please install Nmap and Metasploit manually.{RESET}")

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(file_path + ".enc", "wb") as f:
        f.write(encrypted)
    print(f"{GREEN}[+] File encrypted: {file_path}.enc{RESET}")

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    decrypted = fernet.decrypt(data)
    with open(file_path.replace(".enc", ""), "wb") as f:
        f.write(decrypted)
    print(f"{GREEN}[+] File decrypted: {file_path.replace('.enc', '')}{RESET}")

def vulnerability_scan(target):
    print(f"{BLUE}[*] Scanning {target} for vulnerabilities...{RESET}")
    result = run_command(f"nmap -sV --script vulners {target}")
    print(result if result else f"{RED}[!] Scan failed.{RESET}")

def metasploit_scan(target, port):
    print(f"{BLUE}[*] Launching Metasploit against {target}:{port}...{RESET}")
    msf_command = f"use auxiliary/scanner/portscan/tcp\nset RHOSTS {target}\nset PORTS {port}\nrun\nexit\n"
    with open("msf_script.rc", "w") as f:
        f.write(msf_command)
    run_command(f"msfconsole -r msf_script.rc")

def show_help():
    print(f"\n{RED}GMI-Panzerwagen User Guide{RESET}")
    print(f"{BLUE}1. Vulnerability Scan — Scan for CVEs using Nmap")
    print("2. Metasploit Scan — Exploit targets via Metasploit")
    print("3. Encrypt File — AES-256 encryption")
    print("4. Decrypt File — Secure decryption")
    print("5. Help — Displays this guide")
    print("6. Exit — Quits the tool\n")

def main():
    clear_screen()
    print(f"{BG_BLACK}{RED}=== GMI-Panzerwagen ==={RESET}")
    install_dependencies()

    while True:
        print(f"\n{RED}Tool Menu:{RESET}")
        print("1. Vulnerability Scan")
        print("2. Metasploit Scan")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Help")
        print("6. Exit")
        choice = input(f"{RED}>>> Choose an option (1–6): {RESET}")

        if choice == "1":
            target = input(f"{RED}Enter IP/Domain to scan: {RESET}")
            vulnerability_scan(target)
        elif choice == "2":
            target = input(f"{RED}Enter target IP: {RESET}")
            port = input(f"{RED}Enter port to scan: {RESET}")
            metasploit_scan(target, port)
        elif choice == "3":
            file_path = input(f"{RED}Enter file path to encrypt: {RESET}")
            key = generate_key()
            print(f"{GREEN}[+] Encryption key (save it): {key.decode()}{RESET}")
            encrypt_file(file_path, key)
        elif choice == "4":
            file_path = input(f"{RED}Enter path of encrypted file: {RESET}")
            key = input(f"{RED}Enter decryption key: {RESET}").encode()
            decrypt_file(file_path, key)
        elif choice == "5":
            show_help()
        elif choice == "6":
            print(f"{RED}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid option!{RESET}")

if __name__ == "__main__":
    main()
