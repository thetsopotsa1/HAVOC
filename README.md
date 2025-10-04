# HAVOC 3.0

**Full-break + instant-evidence engine for security research and penetration testing**

⚠️ **EDUCATIONAL AND AUTHORIZED TESTING ONLY** ⚠️

## Overview

HAVOC 3.0 is a high-performance C-based security testing tool that performs comprehensive web application security assessments. It automatically:

- **Unlocks** directory listings through HTTP parser differentials
- **Walks** discovered directories to extract sensitive files
- **Captures** secrets and configuration files  
- **Tests** administrative endpoints and restart functions
- **Archives** all evidence with SHA-256 verification
- **Generates** ready-to-upload evidence bundles and JSON reports

## Features

✅ **Zero Dependencies** (except OpenSSL)  
✅ **Instant Evidence Archival** - every response captured immediately  
✅ **Automatic Tar.gz Bundling** - ready for upload/sharing  
✅ **JSON Reporting** - structured findings with impact assessment  
✅ **SHA-256 Verification** - integrity checking for all captured data  
✅ **Professional Output** - court-ready evidence documentation  

## Quick Start

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev
```

**CentOS/RHEL:**
```bash
sudo yum install gcc openssl-devel
```

**macOS:**
```bash
brew install openssl
```

### Build & Run

```bash
# Clone the repository
git clone https://github.com/thetsopotsa1/HAVOC.git
cd HAVOC

# Compile
make

# Run against target
./havoc <target-ip> [port]
```

### Example Usage

```bash
# Test local development server
./havoc 127.0.0.1 8080

# Test remote server on standard port
./havoc 203.0.113.10 8080

# Test with custom port  
./havoc 192.168.1.100 3000
```

## Output

When vulnerabilities are found, HAVOC generates:

```
evidence/
├── evidence.tar.gz          # Complete evidence bundle
├── report.json              # Structured findings report  
├── README.txt              # Evidence summary
├── files.sha256            # Integrity checksums
├── baseline-404            # Initial response
├── unlock-200-dir          # Directory listing unlock
├── dir-a1b2c3.html        # Discovered directories
├── /config/database.yml    # Extracted secrets
└── restart-200             # Admin endpoint responses
```

### Sample JSON Report

```json
{
  "target": "192.168.1.100:8080",
  "generated": "Mon Jan 13 20:15:32 2025",
  "findings": [
    {
      "type": "secret",
      "file": "/config/database.yml",
      "sha256": "a1b2c3d4e5f6...",
      "impact": "hard-coded credential or key"
    },
    {
      "type": "rce", 
      "file": "restart-200.json",
      "sha256": "f6e5d4c3b2a1...",
      "impact": "JVM lifecycle control without auth"
    }
  ],
  "severity": "critical",
  "impact": "directory listing enabled + secrets leaked + restart actuator exposed"
}
```

## Technical Details

### Attack Methodology

1. **Baseline Discovery** - Establishes normal application behavior
2. **Parser Differential Unlock** - Exploits HTTP parsing inconsistencies using malformed Content-Length headers
3. **Directory Traversal** - Systematically walks discovered directories using hash-based paths
4. **Secret Extraction** - Downloads and archives configuration files, keys, and credentials
5. **Privilege Escalation** - Tests administrative endpoints with common keys/tokens
6. **Evidence Compilation** - Creates tamper-evident archives with cryptographic verification

### Network Behavior

- **Protocol**: Raw TCP sockets for HTTP/1.0 requests
- **Timeout**: 4-second connection timeout per request  
- **Threading**: Single-threaded sequential execution
- **Footprint**: Minimal - only essential HTTP requests sent

## Ethical Use Guidelines

### ✅ Authorized Use Cases

- **Penetration Testing** with written authorization
- **Bug Bounty Programs** within defined scope
- **Internal Security Assessments** on owned infrastructure  
- **Academic Research** in controlled lab environments
- **Security Training** and education

### ❌ Prohibited Use Cases  

- Testing systems without explicit written permission
- Unauthorized access to production systems
- Violating terms of service or acceptable use policies
- Any activity that may be illegal in your jurisdiction

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are solely responsible for ensuring compliance with all applicable laws and regulations. The developers assume no liability for misuse or damages resulting from the use of this software.

**Always obtain proper authorization before testing any systems you do not own.**

## Build Options

```bash
# Standard build
make

# Debug build with symbols
make debug

# Static binary (portable)
make static  

# Clean build artifacts
make clean

# Install system-wide
sudo make install

# Show all options
make help
```

## System Requirements

- **OS**: Linux, macOS, or Unix-like systems
- **Compiler**: GCC 4.8+ or Clang 3.5+
- **Libraries**: OpenSSL 1.0.0+
- **Architecture**: x86_64, ARM64, or other supported architectures

## Contributing

This is a security research tool. Contributions should focus on:

- Improving evidence collection accuracy
- Enhancing report generation
- Adding new detection techniques
- Strengthening ethical use controls

## License

MIT License - see LICENSE file for details.

---

**For security researchers, by security researchers. Use responsibly.**