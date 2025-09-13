# Chapter 7: Python Environment Setup for Ethical Hacking

## Overview

Setting up a proper Python development environment is crucial for ethical hackers and cybersecurity professionals. This chapter covers comprehensive Python environment configuration, virtual environments, essential libraries, and integration with security tools.

## Python Environment Fundamentals

### Why Python for Cybersecurity?
- **Rapid Development**: Quick prototyping of security tools
- **Extensive Libraries**: Rich ecosystem of security-focused packages
- **Cross-Platform**: Works seamlessly across Windows, Linux, and macOS
- **Integration**: Easy integration with existing security frameworks
- **Community**: Large community of security researchers and developers

### Python Versions and Compatibility
```bash
# Check Python versions
python --version          # May show Python 2.7 (legacy)
python3 --version        # Python 3.x (recommended)

# Kali Linux 2024 default:
python3 --version        # Python 3.11.x
pip3 --version          # pip 23.x

# Verify installation
which python3
which pip3
```

## Environment Setup Methods

### Method 1: System Python (Basic)
```bash
# Update package manager (Kali/Debian/Ubuntu)
sudo apt update

# Install Python development packages
sudo apt install -y python3 python3-pip python3-dev python3-venv

# Install essential build tools
sudo apt install -y build-essential libssl-dev libffi-dev python3-setuptools

# Upgrade pip
python3 -m pip install --upgrade pip

# Verify installation
python3 -c "import sys; print(sys.version)"
pip3 --version
```

### Method 2: Virtual Environments (Recommended)
```bash
# Create virtual environment
python3 -m venv ethical_hacking_env

# Activate virtual environment
source ethical_hacking_env/bin/activate

# Verify activation (prompt should change)
(ethical_hacking_env) $ which python
# Should point to virtual environment

# Install packages in virtual environment
pip install requests beautifulsoup4 scapy

# Create requirements file
pip freeze > requirements.txt

# Deactivate when done
deactivate
```

### Method 3: Anaconda/Miniconda (Advanced)
```bash
# Download Miniconda for Linux
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh

# Install Miniconda
bash Miniconda3-latest-Linux-x86_64.sh

# Create conda environment for security work
conda create -n cybersec python=3.11

# Activate environment
conda activate cybersec

# Install packages
conda install requests beautifulsoup4
pip install scapy python-nmap

# List environments
conda env list
```

## Essential Python Libraries for Ethical Hacking

### Network and Protocol Libraries
```bash
# Install core networking libraries
pip install scapy python-nmap paramiko requests urllib3

# Network scanning and manipulation
pip install netaddr netifaces psutil

# HTTP/Web libraries  
pip install requests-oauthlib requests-ntlm selenium

# Example installation verification
python3 -c "import scapy; print('Scapy version:', scapy.__version__)"
```

### Cryptography and Security Libraries
```bash
# Cryptographic libraries
pip install cryptography pycrypto pycryptodome

# Hashing and encoding
pip install hashlib bcrypt passlib

# SSL/TLS libraries
pip install pyopenssl

# JWT handling
pip install pyjwt

# Example cryptography test
python3 -c "from cryptography.fernet import Fernet; print('Cryptography working')"
```

### Web Application Security Libraries
```bash
# Web scraping and parsing
pip install beautifulsoup4 lxml html5lib

# Web application testing
pip install mechanize selenium webdriver-manager

# SQLMap integration
pip install sqlmap-api

# XML processing
pip install defusedxml lxml

# Example BeautifulSoup test
python3 -c "from bs4 import BeautifulSoup; print('BeautifulSoup working')"
```

### Database and Data Processing
```bash
# Database connections
pip install sqlite3 pymongo redis

# Data analysis and visualization
pip install pandas numpy matplotlib seaborn

# Excel/CSV processing
pip install openpyxl xlrd csv-python

# Example pandas test
python3 -c "import pandas as pd; print('Pandas version:', pd.__version__)"
```

## IDE and Development Environment Setup

### VS Code Configuration
```bash
# Install VS Code (if not already installed)
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list
sudo apt update
sudo apt install code

# Essential VS Code extensions for security development:
# 1. Python (Microsoft)
# 2. Python Docstring Generator
# 3. GitLens
# 4. Bracket Pair Colorizer
# 5. Code Runner
# 6. REST Client
```

### PyCharm Configuration
```bash
# Download PyCharm Community Edition
# https://www.jetbrains.com/pycharm/download/

# Extract and install
tar -xzf pycharm-community-*.tar.gz
cd pycharm-community-*/bin
./pycharm.sh

# Configure Python interpreter
# File > Settings > Project > Python Interpreter
# Add virtual environment or system Python
```

### Vim/Neovim for Terminal Development
```bash
# Install enhanced vim
sudo apt install vim-nox neovim

# Install vim-plug for plugin management
curl -fLo ~/.vim/autoload/plug.vim --create-dirs \
    https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

# Basic .vimrc for Python development
cat << 'EOF' > ~/.vimrc
call plug#begin('~/.vim/plugged')
Plug 'vim-python/python-syntax'
Plug 'davidhalter/jedi-vim'
Plug 'vim-airline/vim-airline'
Plug 'preservim/nerdtree'
call plug#end()

syntax on
set number
set expandtab
set tabstop=4
set shiftwidth=4
set autoindent
set hlsearch
EOF

# Install plugins
vim +PlugInstall +qall
```

## Security-Focused Environment Configuration

### Scapy Environment Setup
```bash
# Install Scapy with all dependencies
pip install scapy[complete]

# Additional network tools
sudo apt install tcpdump wireshark-common

# Configure Scapy for non-root usage
sudo usermod -aG wireshark $USER
# Log out and log back in

# Test Scapy installation
python3 -c "
from scapy.all import *
print('Scapy loaded successfully')
print('Available interfaces:', get_if_list())
"
```

### Metasploit Python Integration
```bash
# Install python-msfrpc for Metasploit integration
pip install python-msfrpc

# Alternative: Manual installation
git clone https://github.com/rapid7/metasploit-framework.git
cd metasploit-framework/external/source/meterpreter/python/
python3 setup.py install

# Test Metasploit integration
python3 -c "
try:
    import msfrpc
    print('Metasploit RPC integration available')
except ImportError:
    print('Install python-msfrpc for Metasploit integration')
"
```

### Burp Suite Python Extensions
```bash
# Install Jython for Burp Suite extensions
wget https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar

# Move to appropriate location
sudo mv jython-standalone-2.7.3.jar /opt/jython.jar

# Configure Burp Suite to use Jython
# Extender > Options > Python Environment
# Set Jython standalone JAR location: /opt/jython.jar
```

## Custom Security Libraries Installation

### Installation from GitHub
```bash
# Example: Installing Impacket
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install .

# Example: Installing theHarvester
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements.txt

# Example: Installing SQLMap
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
# SQLMap doesn't require installation, just run python3 sqlmap.py
```

### Creating Requirements Files
```bash
# Create comprehensive requirements file for ethical hacking
cat << 'EOF' > ethical_hacking_requirements.txt
# Network and Protocol Libraries
scapy==2.5.0
python-nmap==0.7.1
paramiko==3.2.0
requests==2.31.0
netaddr==0.8.0
netifaces==0.11.0

# Cryptography
cryptography==41.0.3
pycryptodome==3.18.0

# Web Application Security
beautifulsoup4==4.12.2
selenium==4.11.2
mechanize==0.4.8

# Data Processing
pandas==2.0.3
numpy==1.24.3

# Additional Security Tools
impacket==0.10.0
theHarvester==4.4.3
python-msfrpc==1.0.1

# Development Tools
ipython==8.14.0
jupyter==1.0.0
python-dotenv==1.0.0
EOF

# Install from requirements file
pip install -r ethical_hacking_requirements.txt
```

## Environment Management Scripts

### Virtual Environment Management Script
```bash
# Create environment management script
cat << 'EOF' > ~/scripts/manage_env.sh
#!/bin/bash

ENV_DIR="$HOME/venvs"
mkdir -p "$ENV_DIR"

case "$1" in
    create)
        if [ -z "$2" ]; then
            echo "Usage: $0 create <env_name>"
            exit 1
        fi
        python3 -m venv "$ENV_DIR/$2"
        echo "Virtual environment '$2' created"
        echo "Activate with: source $ENV_DIR/$2/bin/activate"
        ;;
    
    list)
        echo "Available environments:"
        ls -1 "$ENV_DIR" 2>/dev/null || echo "No environments found"
        ;;
    
    remove)
        if [ -z "$2" ]; then
            echo "Usage: $0 remove <env_name>"
            exit 1
        fi
        if [ -d "$ENV_DIR/$2" ]; then
            rm -rf "$ENV_DIR/$2"
            echo "Environment '$2' removed"
        else
            echo "Environment '$2' not found"
        fi
        ;;
    
    activate)
        if [ -z "$2" ]; then
            echo "Usage: source $0 activate <env_name>"
            exit 1
        fi
        if [ -f "$ENV_DIR/$2/bin/activate" ]; then
            source "$ENV_DIR/$2/bin/activate"
            echo "Activated environment '$2'"
        else
            echo "Environment '$2' not found"
        fi
        ;;
    
    *)
        echo "Usage: $0 {create|list|remove|activate} [env_name]"
        exit 1
        ;;
esac
EOF

chmod +x ~/scripts/manage_env.sh

# Usage examples:
# ~/scripts/manage_env.sh create pentest
# ~/scripts/manage_env.sh list
# source ~/scripts/manage_env.sh activate pentest
```

### Environment Testing Script
```bash
# Create environment validation script
cat << 'EOF' > ~/scripts/test_environment.py
#!/usr/bin/env python3
"""
Security Python Environment Test Script
Tests installation of essential libraries for ethical hacking
"""

import sys
import importlib
import subprocess

def test_import(module_name, package_name=None):
    """Test if a module can be imported"""
    try:
        importlib.import_module(module_name)
        print(f"✓ {module_name} - OK")
        return True
    except ImportError:
        pkg = package_name or module_name
        print(f"✗ {module_name} - MISSING (install with: pip install {pkg})")
        return False

def test_command(command, description):
    """Test if a command-line tool is available"""
    try:
        subprocess.run([command, "--version"], 
                      capture_output=True, check=True)
        print(f"✓ {command} - OK")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"✗ {command} - MISSING ({description})")
        return False

def main():
    print("Python Environment Test for Ethical Hacking")
    print("=" * 50)
    
    # Python version check
    print(f"Python version: {sys.version}")
    print()
    
    # Essential modules test
    print("Testing Python modules:")
    modules = [
        ("scapy", "scapy"),
        ("nmap", "python-nmap"),
        ("paramiko", "paramiko"),
        ("requests", "requests"),
        ("bs4", "beautifulsoup4"),
        ("cryptography", "cryptography"),
        ("pandas", "pandas"),
        ("numpy", "numpy"),
        ("selenium", "selenium"),
    ]
    
    passed = 0
    total = len(modules)
    
    for module, package in modules:
        if test_import(module, package):
            passed += 1
    
    print()
    print("Testing command-line tools:")
    
    # Command-line tools test
    commands = [
        ("nmap", "Network scanning tool"),
        ("john", "Password cracking tool"),
        ("hashcat", "Password recovery tool"),
        ("nikto", "Web vulnerability scanner"),
        ("gobuster", "Directory/file brute-forcer"),
    ]
    
    cmd_passed = 0
    cmd_total = len(commands)
    
    for command, description in commands:
        if test_command(command, description):
            cmd_passed += 1
    
    print()
    print("Results:")
    print(f"Python modules: {passed}/{total} ({passed/total*100:.1f}%)")
    print(f"Command tools: {cmd_passed}/{cmd_total} ({cmd_passed/cmd_total*100:.1f}%)")
    
    if passed == total and cmd_passed >= cmd_total * 0.8:
        print("✓ Environment ready for ethical hacking!")
        return 0
    else:
        print("✗ Some tools missing. Install missing components.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x ~/scripts/test_environment.py

# Run the test
python3 ~/scripts/test_environment.py
```

## Jupyter Notebook Setup for Security Research

### Jupyter Installation and Configuration
```bash
# Install Jupyter
pip install jupyter jupyterlab notebook

# Install useful extensions
pip install jupyter_contrib_nbextensions
jupyter contrib nbextension install --user

# Enable useful extensions
jupyter nbextension enable collapsible_headings/main
jupyter nbextension enable code_folding/main
jupyter nbextension enable toc2/main

# Create Jupyter config
jupyter notebook --generate-config

# Configure Jupyter for security research
cat << 'EOF' >> ~/.jupyter/jupyter_notebook_config.py
# Security configuration
c.NotebookApp.ip = '127.0.0.1'  # Only local access
c.NotebookApp.open_browser = False
c.NotebookApp.token = ''  # Use password instead
c.NotebookApp.password_required = True

# Set notebook directory
c.NotebookApp.notebook_dir = '/home/kali/security_notebooks'
EOF

# Create notebooks directory
mkdir -p ~/security_notebooks

# Create sample security notebook
cat << 'EOF' > ~/security_notebooks/network_recon_template.ipynb
{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Network Reconnaissance Template\n",
    "This notebook provides templates for common network reconnaissance tasks."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "import nmap\n",
    "import requests\n",
    "from scapy.all import *\n",
    "import pandas as pd\n",
    "\n",
    "# Configuration\n",
    "TARGET_NETWORK = \"192.168.1.0/24\"\n",
    "TARGET_HOST = \"192.168.1.100\""
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Host Discovery"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "# Nmap host discovery\n",
    "nm = nmap.PortScanner()\n",
    "nm.scan(hosts=TARGET_NETWORK, arguments='-sn')\n",
    "hosts = nm.all_hosts()\n",
    "print(f\"Found {len(hosts)} active hosts:\")\n",
    "for host in hosts:\n",
    "    print(f\"  {host}: {nm[host].hostname()}\")"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.11.0"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 4
}
EOF

# Start Jupyter
# jupyter notebook
```

## Troubleshooting Common Issues

### Permission Issues
```bash
# Fix pip permissions
pip install --user package_name

# Or use sudo (not recommended for development)
sudo pip3 install package_name

# Fix virtual environment permissions
sudo chown -R $USER:$USER ~/venvs/

# Fix Python path issues
echo 'export PYTHONPATH="${PYTHONPATH}:/home/kali/.local/lib/python3.11/site-packages"' >> ~/.bashrc
source ~/.bashrc
```

### Package Conflicts
```bash
# Clear pip cache
pip cache purge

# Upgrade conflicting packages
pip install --upgrade package_name

# Force reinstall
pip install --force-reinstall package_name

# Check for conflicts
pip check

# Use pip-tools for dependency management
pip install pip-tools
pip-compile requirements.in
pip-sync requirements.txt
```

### SSL Certificate Issues
```bash
# Update certificates
sudo apt update && sudo apt install ca-certificates

# Fix pip SSL issues
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org package_name

# Set up pip configuration
mkdir -p ~/.pip
cat << 'EOF' > ~/.pip/pip.conf
[global]
trusted-host = pypi.org
               pypi.python.org
               files.pythonhosted.org
EOF
```

## Performance Optimization

### Python Performance Tuning
```bash
# Install performance monitoring tools
pip install memory_profiler line_profiler py-spy

# Use PyPy for CPU-intensive tasks
sudo apt install pypy3 pypy3-dev
pypy3 -m pip install package_name

# Optimize imports in scripts
# Use specific imports instead of wildcard
from scapy.all import IP, TCP, sr1
# Instead of: from scapy.all import *
```

### Environment Optimization
```bash
# Set Python optimization flags
export PYTHONOPTIMIZE=1

# Disable Python debug mode
export PYTHONDONTWRITEBYTECODE=1

# Increase recursion limit for deep packet analysis
python3 -c "import sys; sys.setrecursionlimit(10000)"

# Use faster JSON library
pip install orjson  # Faster than standard json
pip install ujson   # Alternative fast JSON library
```

## Summary

**Essential Environment Components:**
- **Python 3.11+**: Latest stable Python version
- **Virtual Environments**: Isolated development spaces
- **Core Security Libraries**: Scapy, python-nmap, requests, cryptography
- **Development Tools**: VS Code/PyCharm, Jupyter, testing frameworks

**Best Practices:**
- Always use virtual environments for projects
- Keep requirements.txt files updated
- Test environment setup with validation scripts
- Regular updates of security libraries
- Proper IDE configuration for productivity

**Security Considerations:**
- Isolate different project environments
- Use secure package sources
- Verify package integrity when possible
- Keep development and production environments separate
- Regular security updates for all packages

**Performance Tips:**
- Use compiled libraries when available
- Optimize imports for faster startup
- Monitor memory usage for large-scale operations
- Consider PyPy for CPU-intensive tasks

This comprehensive Python environment setup provides the foundation for professional ethical hacking and security research activities, enabling efficient development of custom security tools and automation scripts.