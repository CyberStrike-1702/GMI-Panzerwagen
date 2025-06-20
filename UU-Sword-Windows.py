#!/usr/bin/env python3
import os
import sys
import subprocess
import requests
import time
from datetime import datetime
from cryptography.fernet import Fernet

# Colors (Red text on black background)
RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"
BG_BLACK = "\033[40m"

# Configuration
METASPLOIT_PATH = "/usr/bin/msfconsole" if os.name != 'nt' else "C:\\metasploit-framework\\bin\\msfconsole.bat"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error: {e.stderr}{RESET}")
        return None

def install_dependencies():
    print(f"{BLUE}[*] Checking dependencies...{RESET}")
    if os.name == 'nt':  # Windows
        if not os.path.exists("C:\\Program Files (x86)\\Nmap\\nmap.exe"):
            print(f"{RED}[!] Install Nmap from https://nmap.org/{RESET}")
        if not os.path.exists(METASPLOIT_PATH):
            print(f"{RED}[!] Install Metasploit from https://www.metasploit.com/{RESET}")
    else:  # Linux (Arch)
        if not run_command("which nmap"):
            run_command("sudo pacman -Sy --noconfirm nmap")
        if not run_command("which msfconsole"):
            run_command("sudo pacman -Sy --noconfirm metasploit")

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
    print(result if result else f"{RED}Scan failed.{RESET}")

def metasploit_scan(target, port):
    print(f"{BLUE}[*] Launching Metasploit against {target}:{port}...{RESET}")
    msf_command = f"use auxiliary/scanner/portscan/tcp\nset RHOSTS {target}\nset PORTS {port}\nrun\nexit\n"
    with open("msf_script.rc", "w") as f:
        f.write(msf_command)
    run_command(f"{METASPLOIT_PATH} -r msf_script.rc")

def show_help():
    print(f"\n{RED}UU-Sword User Guide{RESET}")
    print(f"{BLUE}1. Vulnerability Scan: Scans a target for CVEs using Nmap.")
    print("2. Metasploit Scan: Runs Metasploit exploits against a target.")
    print("3. Encrypt File: Encrypts a file with AES-256.")
    print("4. Decrypt File: Decrypts a file with the correct key.")
    print(f"5. Help: Shows this guide.{RESET}")

def main():
    clear_screen()
    print(f"{BG_BLACK}{RED}=== UU-Sword (Advanced Cybersecurity Tool) ==={RESET}")
    install_dependencies()

    while True:
        print(f"\n{RED}Tool Menu:{RESET}")
        print(f"{RED}1. Vulnerability Scan")
        print("2. Metasploit Scan")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Help")
        print(f"6. Exit{RESET}")
        choice = input(f"{RED}>>> Select an option (1-6): {RESET}")

        if choice == "1":
            target = input(f"{RED}Enter IP/Domain to scan: {RESET}")
            vulnerability_scan(target)
        elif choice == "2":
            target = input(f"{RED}Enter target IP: {RESET}")
            port = input(f"{RED}Enter port to attack: {RESET}")
            metasploit_scan(target, port)
        elif choice == "3":
            file_path = input(f"{RED}Enter file path to encrypt: {RESET}")
            key = generate_key()
            print(f"{GREEN}[+] Key: {key.decode()}{RESET}")  # Save this key!
            encrypt_file(file_path, key)
        elif choice == "4":
            file_path = input(f"{RED}Enter encrypted file path: {RESET}")
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
