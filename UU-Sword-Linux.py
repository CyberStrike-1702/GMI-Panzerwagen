#!/usr/bin/env python3
import os
import subprocess
from cryptography.fernet import Fernet

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"
BG_BLACK = "\033[40m"

METASPLOIT_PATH = "/usr/bin/msfconsole"

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
        with open("/etc/os-release", "r") as file:
            data = file.read().lower()
            if "kali" in data:
                return "kali"
            elif "blackarch" in data or "arch" in data:
                return "blackarch"
    except Exception as e:
        print(f"{RED}[!] Could not detect Linux distribution: {e}{RESET}")
    return "unknown"

def check_and_install(pkg_name, install_cmd):
    print(f"{BLUE}[*] Checking for {pkg_name}...{RESET}")
    if not run_command(f"which {pkg_name}"):
        print(f"{RED}[!] {pkg_name} not found. Installing...{RESET}")
        run_command(install_cmd)

def install_dependencies():
    distro = get_distro()
    if distro == "kali":
        check_and_install("nmap", "sudo apt update && sudo apt install -y nmap")
        check_and_install("msfconsole", "sudo apt install -y metasploit-framework")
    elif distro == "blackarch":
        check_and_install("nmap", "sudo pacman -Sy --noconfirm nmap")
        check_and_install("msfconsole", "sudo pacman -Sy --noconfirm metasploit")
    else:
        print(f"{RED}[!] Unsupported or undetected distribution. Please install Nmap and Metasploit manually.{RESET}")

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
    print(f"{BLUE}1. Vulnerability Scan: Use Nmap to identify vulnerabilities.")
    print("2. Metasploit Scan: Use Metasploit to scan ports.")
    print("3. Encrypt File: Encrypt a file using AES-256 (Fernet).")
    print("4. Decrypt File: Decrypt an encrypted file using a key.")
    print(f"5. Help: Show this help guide.{RESET}")

def main():
    clear_screen()
    print(f"{BG_BLACK}{RED}=== UU-Sword (Cybersecurity Toolkit) ==={RESET}")
    install_dependencies()

    while True:
        print(f"\n{RED}Tool Menu:{RESET}")
        print("1. Vulnerability Scan")
        print("2. Metasploit Scan")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Help")
        print("6. Exit")
        choice = input(f"{RED}>>> Choose an option (1-6): {RESET}")

        if choice == "1":
            target = input(f"{RED}Enter target IP or domain: {RESET}")
            vulnerability_scan(target)
        elif choice == "2":
            target = input(f"{RED}Enter target IP: {RESET}")
            port = input(f"{RED}Enter port: {RESET}")
            metasploit_scan(target, port)
        elif choice == "3":
            file_path = input(f"{RED}Enter file path to encrypt: {RESET}")
            key = generate_key()
            print(f"{GREEN}[+] Save this decryption key: {key.decode()}{RESET}")
            encrypt_file(file_path, key)
        elif choice == "4":
            file_path = input(f"{RED}Enter path of encrypted file: {RESET}")
            key = input(f"{RED}Enter decryption key: {RESET}").encode()
            decrypt_file(file_path, key)
        elif choice == "5":
            show_help()
        elif choice == "6":
            print(f"{RED}Exiting UU-Sword...{RESET}")
            break
        else:
            print(f"{RED}Invalid option. Please try again.{RESET}")

if __name__ == "__main__":
    main()
