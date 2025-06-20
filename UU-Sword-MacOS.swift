#!/usr/bin/env swift

import Foundation
import CryptoKit

let red = "\u{001B}[31m"
let green = "\u{001B}[32m"
let blue = "\u{001B}[34m"
let reset = "\u{001B}[0m"

func runCommand(_ command: String) -> String? {
    let task = Process()
    task.launchPath = "/bin/zsh"
    task.arguments = ["-c", command]
    
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = pipe
    task.launch()
    
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    return String(data: data, encoding: .utf8)
}

func checkAndInstall(_ tool: String, brewPackage: String) {
    if runCommand("which \(tool)")?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true {
        print("\(red)[!] \(tool) not found. Installing with Homebrew...\(reset)")
        _ = runCommand("brew install \(brewPackage)")
    }
}

func installDependencies() {
    print("\(blue)[*] Checking dependencies...\(reset)")
    checkAndInstall("nmap", brewPackage: "nmap")
    checkAndInstall("msfconsole", brewPackage: "metasploit")
}

func vulnerabilityScan(target: String) {
    print("\(blue)[*] Scanning \(target) for vulnerabilities...\(reset)")
    if let output = runCommand("nmap -sV --script vulners \(target)") {
        print(output)
    } else {
        print("\(red)Failed to run scan.\(reset)")
    }
}

func metasploitScan(target: String, port: String) {
    print("\(blue)[*] Running Metasploit on \(target):\(port)...\(reset)")
    let script = """
    use auxiliary/scanner/portscan/tcp
    set RHOSTS \(target)
    set PORTS \(port)
    run
    exit
    """
    
    let scriptPath = "/tmp/msf_script.rc"
    try? script.write(toFile: scriptPath, atomically: true, encoding: .utf8)
    _ = runCommand("msfconsole -r \(scriptPath)")
}

func generateKey() -> SymmetricKey {
    return SymmetricKey(size: .bits256)
}

func encryptFile(path: String, key: SymmetricKey) {
    let url = URL(fileURLWithPath: path)
    guard let data = try? Data(contentsOf: url) else {
        print("\(red)[!] Could not read file.\(reset)")
        return
    }
    
    do {
        let sealed = try AES.GCM.seal(data, using: key)
        let output = sealed.combined!
        let outputPath = url.appendingPathExtension("enc")
        try output.write(to: outputPath)
        let base64Key = key.withUnsafeBytes { Data($0).base64EncodedString() }
        print("\(green)[+] File encrypted: \(outputPath.path)\(reset)")
        print("\(green)[+] Save this decryption key:\n\(base64Key)\(reset)")
    } catch {
        print("\(red)[!] Encryption failed: \(error)\(reset)")
    }
}

func decryptFile(path: String, base64Key: String) {
    let url = URL(fileURLWithPath: path)
    guard let data = try? Data(contentsOf: url),
          let keyData = Data(base64Encoded: base64Key) else {
        print("\(red)[!] Invalid file or key.\(reset)")
        return
    }

    let key = SymmetricKey(data: keyData)
    do {
        let box = try AES.GCM.SealedBox(combined: data)
        let decrypted = try AES.GCM.open(box, using: key)
        let outputPath = url.deletingPathExtension()
        try decrypted.write(to: outputPath)
        print("\(green)[+] File decrypted: \(outputPath.path)\(reset)")
    } catch {
        print("\(red)[!] Decryption failed: \(error)\(reset)")
    }
}

func showHelp() {
    print("""
    \(blue)UU-Sword macOS CLI - Help Menu\(reset)
    1. Vulnerability Scan  → Scan target with Nmap
    2. Metasploit Scan     → Scan ports using Metasploit
    3. Encrypt File        → Encrypt file (AES-256-GCM)
    4. Decrypt File        → Decrypt file with key
    5. Help                → Show this help menu
    6. Exit
    """)
}

// Main Loop
installDependencies()
print("\(red)=== UU-Sword (macOS Cybersecurity CLI) ===\(reset)")

while true {
    print("""
    \n\(red)Menu:\(reset)
    1. Vulnerability Scan
    2. Metasploit Scan
    3. Encrypt File
    4. Decrypt File
    5. Help
    6. Exit
    """)
    
    print("\(red)>>> Select an option (1-6): \(reset)", terminator: "")
    guard let input = readLine() else { continue }
    
    switch input {
    case "1":
        print("\(red)Enter target IP or domain: \(reset)", terminator: "")
        if let target = readLine() {
            vulnerabilityScan(target: target)
        }
    case "2":
        print("\(red)Enter target IP: \(reset)", terminator: "")
        let ip = readLine() ?? ""
        print("\(red)Enter port to scan: \(reset)", terminator: "")
        let port = readLine() ?? ""
        metasploitScan(target: ip, port: port)
    case "3":
        print("\(red)Enter file path to encrypt: \(reset)", terminator: "")
        if let path = readLine() {
            let key = generateKey()
            encryptFile(path: path, key: key)
        }
    case "4":
        print("\(red)Enter encrypted file path: \(reset)", terminator: "")
        let path = readLine() ?? ""
        print("\(red)Enter decryption key (base64): \(reset)", terminator: "")
        let key = readLine() ?? ""
        decryptFile(path: path, base64Key: key)
    case "5":
        showHelp()
    case "6":
        print("\(green)Goodbye!\(reset)")
        exit(0)
    default:
        print("\(red)[!] Invalid option.\(reset)")
    }
}
