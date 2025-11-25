# ESC8 ADCS Exploitation Automation Tool

An automated proof-of-concept tool for demonstrating the ESC8 (ADCS HTTP Endpoints) vulnerability in Active Directory Certificate Services environments.

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal. Only use this tool in environments where you have explicit permission to perform security testing.

## 📋 Overview

This automation script orchestrates the ESC8 attack chain, which exploits vulnerabilities in Active Directory Certificate Services (ADCS) HTTP endpoints. The attack leverages NTLM relay attacks combined with certificate-based authentication to compromise domain controllers and extract sensitive credentials.

### Attack Flow

1. **CA Discovery**: Identifies the Certificate Authority in the domain
2. **Initial Relay**: Sets up NTLM relay to the ADCS HTTP endpoint
3. **Credential Poisoning**: Uses Responder to capture and relay NTLM authentication
4. **Certificate Extraction**: Obtains and authenticates with administrator certificate
5. **DC Compromise**: Coerces Domain Controller authentication using PetitPotam
6. **Secret Dumping**: Extracts domain credentials using the DC certificate

## 🛠️ Prerequisites

### Required Tools

- **Python 3.8+**
- **ntlmrelayx.py** - Part of Impacket toolkit
- **Responder** - LLMNR/NBT-NS/MDNS poisoner
- **Certipy** - AD CS exploitation tool
- **PetitPotam** - Coercion tool for authentication
- **secretsdump.py** - Impacket credential dumper
- **tqdm** - Progress bar library

### System Requirements

- Linux operating system (tested on Kali Linux)
- Network access to target Active Directory environment
- GNOME Terminal (for background process management)

## 📦 Installation

### 1. Install Python Dependencies

```bash
pip3 install tqdm
```

### 2. Install Impacket

```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .
```

### 3. Install Certipy

```bash
pip3 install certipy-ad
```

### 4. Install Responder

```bash
git clone https://github.com/lgandx/Responder.git
cd Responder
```

### 5. Install PetitPotam

```bash
mkdir -p /root/tools
cd /root/tools
git clone https://github.com/topotam/PetitPotam.git
```

### 6. Configure Tool Paths

Edit the paths at the top of `esc8_automation.py` to match your installation:

```python
ntlmrelayx_path = "ntlmrelayx.py"
responder_path = "responder"
certipy_path = "certipy"
petitpotam_path = "/root/tools/PetitPotam/PetitPotam.py"
secretsdump_path = "/root/.local/bin/secretsdump.py"
```

## 🚀 Usage

### Basic Execution

```bash
python3 esc8_automation.py
```

### Interactive Prompts

The script will prompt you for the following information:

1. **Domain Controller IP**: Target DC IP address (e.g., 192.168.1.10)
2. **Your IP Address**: Attacker machine IP address
3. **Domain Name**: Target domain (e.g., contoso.local)
4. **Domain User**: Valid domain account (e.g., jsmith@contoso.local)
5. **Domain Password**: Password for the domain account

### Example Session

```
Enter the Domain Controller IP address: 192.168.1.10
Enter your IP address: 192.168.1.50
Enter the domain name (e.g., domain.local): contoso.local
Enter the domain user name (e.g., jsmith@hadrian.local): jsmith@contoso.local
Enter the domain user's password (e.g., Password123): SecurePass123!

[INFO] Starting step: Query CA Authority using Certipy
[INFO] Extracted CA Authority IP/Name: CA-SERVER.contoso.local
Automating Attack Sequence: 100%|████████████████| 7/7 [05:23<00:00, 46.21s/step]
```

## 📊 Output Files

- **automation.log**: Detailed execution log with timestamps
- **logs/**: Directory containing ntlmrelayx output files
- **ADMINISTRATOR.pfx**: Administrator certificate (if obtained)
- **DC1$.pfx**: Domain Controller certificate (if obtained)

## 🔍 Logging

The tool provides comprehensive logging at multiple levels:

- **Terminal Output**: Real-time progress and status updates
- **Log File**: Detailed execution history in `automation.log`
- **Error Messages**: Clear error descriptions with troubleshooting guidance

## 🛡️ Mitigations

To protect against ESC8 attacks:

1. **Enable EPA/HTTPS**: Enable Extended Protection for Authentication on ADCS web enrollment
2. **Disable HTTP Endpoints**: Use HTTPS only for certificate enrollment
3. **SMB Signing**: Enforce SMB signing on all domain systems
4. **LDAP Signing**: Require LDAP signing and channel binding
5. **Monitor Certificate Requests**: Alert on unusual certificate enrollments
6. **Disable NTLM**: Where possible, disable NTLM authentication

## 📚 References

- [Certified Pre-Owned - SpecterOps Whitepaper](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ADCS ESC8 Attack Overview](https://www.thehacker.recipes/ad/movement/ad-cs/web-endpoints)
- [PetitPotam Documentation](https://github.com/topotam/PetitPotam)
- [Certipy Documentation](https://github.com/ly4k/Certipy)

## 🐛 Troubleshooting

### Common Issues

**Issue**: "Failed to extract CA Authority IP/Name"
- **Solution**: Verify domain credentials and network connectivity to DC

**Issue**: "PFX certificate was not generated"
- **Solution**: Ensure target has vulnerable ADCS configuration and HTTP endpoint is accessible

**Issue**: "No output captured from Certipy command"
- **Solution**: Check certificate files exist and are not corrupted

**Issue**: Tool paths not found
- **Solution**: Update tool paths in script to match your installation locations

## 📝 License

This project is provided under the MIT License. See LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please ensure any modifications maintain the educational and ethical nature of this tool.

## ⚡ Version History

- **v1.0.0** - Initial release with automated ESC8 attack chain

## 👨‍💻 Author

Created for security research and educational purposes.
