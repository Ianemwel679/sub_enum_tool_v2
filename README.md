# 🔍 Enhanced Subdomain Enumeration Tool


A comprehensive, user-friendly subdomain enumeration script that combines multiple reconnaissance tools to discover subdomains efficiently. Perfect for bug bounty hunters, penetration testers, and security researchers.

## ✨ Features

- 🚀 **Multi-Tool Integration**: Combines Subfinder, Assetfinder, Amass, Gobuster, and DIRB
- ⚡ **Parallel Processing**: Concurrent live subdomain checking with configurable threads
- 🎯 **DNS Verification**: Validates subdomains before HTTP/HTTPS checks
- 📊 **Comprehensive Reporting**: Generates both human-readable and JSON reports
- 🎨 **Beautiful Output**: Color-coded terminal output with progress indicators
- 🔧 **Highly Configurable**: Command-line options for custom workflows
- 💾 **Multiple Output Formats**: Text files, JSON, and detailed summary reports
- 🛡️ **Safety First**: Built-in legal disclaimers and permission checks

## 📋 Prerequisites

### Essential Requirements
- **Bash** 5.0 or higher
- **curl** - HTTP client
- **dig** - DNS lookup utility
- **host** - DNS lookup utility

### Optional Enumeration Tools
Install any or all of these tools for better results:

- **[Subfinder](https://github.com/projectdiscovery/subfinder)** - Fast passive subdomain discovery
- **[Assetfinder](https://github.com/tomnomnom/assetfinder)** - Find domains and subdomains
- **[Amass](https://github.com/owasp-amass/amass)** - In-depth DNS enumeration
- **[Gobuster](https://github.com/OJ/gobuster)** - DNS brute-forcing
- **[DIRB](https://dirb.sourceforge.net/)** - Web content scanner with DNS capabilities

> **Note**: The script will work with any combination of these tools. More tools = better results!

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/subdomain-enum-tool.git
cd subdomain-enum-tool
chmod +x subdomain_enum.sh
```

### 2. Install Essential Tools
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y curl dnsutils

# macOS
brew install bind
```

### 3. Install Enumeration Tools (Optional but Recommended)

#### Install Go-based Tools
```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master
```

#### Install System Tools
```bash
# Debian/Ubuntu
sudo apt install -y gobuster dirb

# macOS
brew install gobuster
```

### 4. Install Wordlists (For Bruteforce)
```bash
# Install SecLists (comprehensive wordlists)
sudo apt install seclists

# Or manually
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

## 📖 Usage

### Basic Usage
```bash
./subdomain_enum.sh example.com
```

### Advanced Options
```bash
./subdomain_enum.sh [OPTIONS] <domain>

OPTIONS:
    -h, --help              Show help message
    -o, --output DIR        Specify custom output directory
    -w, --wordlist FILE     Custom wordlist for bruteforce
    -t, --threads NUM       Number of parallel threads (default: 10)
    -s, --skip-live         Skip live subdomain checking
    -q, --quiet             Minimal output
    --no-passive            Skip passive enumeration tools
    --no-bruteforce         Skip bruteforce enumeration
```

### Examples

**Basic scan:**
```bash
./subdomain_enum.sh example.com
```

**Custom output directory:**
```bash
./subdomain_enum.sh -o my_scan_results example.com
```

**Use custom wordlist with 20 threads:**
```bash
./subdomain_enum.sh -w /path/to/wordlist.txt -t 20 example.com
```

**Quick passive scan only (no bruteforce, no live checks):**
```bash
./subdomain_enum.sh --no-bruteforce --skip-live example.com
```

**Silent mode for automation:**
```bash
./subdomain_enum.sh -q -o scan_results example.com
```

## 📊 Output Files

After running the script, you'll find these files in the output directory:

| File | Description |
|------|-------------|
| `all_subdomains.txt` | All unique subdomains discovered |
| `live_subdomains.txt` | Subdomains responding to HTTP/HTTPS |
| `subfinder_results.txt` | Subfinder tool output |
| `assetfinder_results.txt` | Assetfinder tool output |
| `amass_results.txt` | Amass tool output |
| `gobuster_results.txt` | Gobuster tool output |
| `dirb_results.txt` | DIRB tool output |
| `summary_report.txt` | Human-readable summary report |
| `report.json` | Machine-readable JSON report |

## 🎯 How It Works

```
┌─────────────────────────────────────────┐
│  1. Permission Check & Validation      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  2. Passive Enumeration                 │
│     • Subfinder                         │
│     • Assetfinder                       │
│     • Amass                             │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  3. Active Bruteforce                   │
│     • Gobuster DNS                      │
│     • DIRB DNS                          │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  4. Deduplication & Aggregation         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  5. DNS Verification                    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  6. Live HTTP/HTTPS Checks              │
│     (Parallel Processing)               │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  7. Report Generation                   │
│     • Summary Report                    │
│     • JSON Report                       │
└─────────────────────────────────────────┘
```

## 🤝 Contributing

We welcome contributions! Whether it's:
- 🐛 Bug reports
- 💡 Feature suggestions
- 📝 Documentation improvements
- 🔧 Code contributions

Please feel free to open an issue or submit a pull request.

## 🎯 Roadmap & Future Improvements

We're constantly working to improve this tool! Planned features include:

- [ ] Subdomain takeover detection
- [ ] Integration with vulnerability scanners
- [ ] Certificate transparency log monitoring
- [ ] Port scanning integration
- [ ] Screenshot capture of live subdomains
- [ ] Database storage for historical tracking
- [ ] Web-based dashboard
- [ ] Docker containerization
- [ ] CI/CD integration support

Have suggestions? Open an issue and let us know!

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for authorized security testing only. 

- ✅ Only scan domains you own
- ✅ Obtain explicit written permission before testing
- ❌ Never use on systems without authorization
- ❌ Unauthorized scanning may violate laws and terms of service

The authors and collaborators are not responsible for misuse or damage caused by this tool. Users assume all legal responsibility.

## 👥 Collaborators

This project is maintained by:
- **Ian Nemwel** - Security Researcher
- **Dorothy Amarh** - Security Researcher

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all the amazing tool creators: ProjectDiscovery, Tom Hudson, OWASP, and others
- Inspired by the bug bounty and infosec community
- Built with ❤️ for security researchers worldwide

## 📞 Contact & Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/Ianemwel679/subdomain-enum-tool/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Ianemwel679/subdomain-enum-tool/discussions)
- 📧 **Email**: ianemwel679@gmail.com

---

⭐ **If you find this tool helpful, please consider giving it a star!** ⭐

**Happy Hunting! 🎯**
