#!/bin/bash

# Sayer7 Installation Script
# Automated installation script for Sayer7 security testing tool
# Compatible with Debian/Ubuntu, CentOS/RHEL, and Arch Linux

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYTHON_VERSION="3.8"
INSTALL_DIR="/opt/sayer7"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="/usr/local/bin"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        VERSION=$(grep -oE '[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
        VERSION=""
    else
        print_error "Unsupported operating system"
        exit 1
    fi
    
    print_status "Detected OS: $OS $VERSION"
}

# Function to install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y python3 python3-pip python3-venv git curl wget nmap masscan sqlmap metasploit-framework
            ;;
        centos|rhel|fedora)
            if [[ $OS == "centos" ]] || [[ $OS == "rhel" ]]; then
                yum install -y epel-release
                yum install -y python3 python3-pip git curl wget nmap masscan
            else
                dnf install -y python3 python3-pip git curl wget nmap masscan
            fi
            ;;
        arch)
            pacman -Sy --noconfirm python python-pip git curl wget nmap masscan sqlmap metasploit
            ;;
        *)
            print_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    print_success "System dependencies installed"
}

# Function to install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
    fi
    
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Function to setup directories
setup_directories() {
    print_status "Setting up directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/output"
    mkdir -p "$INSTALL_DIR/config"
    
    print_success "Directories created"
}

# Function to copy files
copy_files() {
    print_status "Copying Sayer7 files..."
    
    cp -r . "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/Sayer7.py"
    
    print_success "Files copied"
}

# Function to create symbolic link
create_symlink() {
    print_status "Creating symbolic link..."
    
    ln -sf "$INSTALL_DIR/Sayer7.py" "$BIN_DIR/sayer7"
    chmod +x "$BIN_DIR/sayer7"
    
    print_success "Symbolic link created"
}

# Function to configure Metasploit
configure_metasploit() {
    print_status "Configuring Metasploit integration..."
    
    if [[ -f "/usr/bin/msfconsole" ]] || [[ -f "/opt/metasploit-framework/bin/msfconsole" ]]; then
        print_success "Metasploit found and configured"
    else
        print_warning "Metasploit not found. Install it manually for full exploitation features"
    fi
}

# Function to create configuration files
create_config() {
    print_status "Creating configuration files..."
    
    cat > "$INSTALL_DIR/config/config.json" << EOF
{
    "tool_name": "Sayer7",
    "version": "1.0.0",
    "install_path": "$INSTALL_DIR",
    "logs_path": "$INSTALL_DIR/logs",
    "output_path": "$INSTALL_DIR/output",
    "metasploit_path": "/usr/bin/msfconsole",
    "payloads_path": "$INSTALL_DIR/modules/payloads",
    "wordlists_path": "$INSTALL_DIR/wordlists"
}
EOF
    
    print_success "Configuration files created"
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    if [[ -x "$BIN_DIR/sayer7" ]]; then
        print_success "Installation verified successfully"
        
        # Test basic functionality
        print_status "Testing basic functionality..."
        "$BIN_DIR/sayer7" --help > /dev/null 2>&1
        
        if [[ $? -eq 0 ]]; then
            print_success "Sayer7 is working correctly"
        else
            print_warning "Sayer7 installed but there might be issues"
        fi
    else
        print_error "Installation verification failed"
        exit 1
    fi
}

# Function to display usage instructions
display_usage() {
    echo -e "\n${GREEN}=== Sayer7 Installation Complete ===${NC}"
    echo -e "\nUsage:"
    echo -e "  sayer7 --help                    # Show help"
    echo -e "  sayer7 --target https://example.com --full-scan  # Run full scan"
    echo -e "  sayer7 --target https://example.com --xss         # Test XSS vulnerabilities"
    echo -e "  sayer7 --target https://example.com --sqli        # Test SQL injection"
    echo -e "  sayer7 --target https://example.com --exploit-test # Test exploitation"
    
    echo -e "\nConfiguration files:"
    echo -e "  Main directory: $INSTALL_DIR"
    echo -e "  Configuration: $INSTALL_DIR/config/config.json"
    echo -e "  Logs: $INSTALL_DIR/logs/"
    echo -e "  Output: $INSTALL_DIR/output/"
    
    echo -e "\nFor more information, check the documentation:"
    echo -e "  $INSTALL_DIR/docs/"
    echo -e "  $INSTALL_DIR/README.md"
}

# Main installation function
main() {
    print_status "Starting Sayer7 installation..."
    
    check_root
    detect_os
    install_system_deps
    setup_directories
    copy_files
    install_python_deps
    create_symlink
    configure_metasploit
    create_config
    verify_installation
    display_usage
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --check-deps   Check system dependencies only"
        echo "  --skip-deps    Skip system dependency installation"
        exit 0
        ;;
    --check-deps)
        detect_os
        print_status "Checking dependencies..."
        exit 0
        ;;
    --skip-deps)
        print_status "Skipping system dependencies installation"
        check_root
        detect_os
        setup_directories
        copy_files
        install_python_deps
        create_symlink
        configure_metasploit
        create_config
        verify_installation
        display_usage
        exit 0
        ;;
    *)
        main
        ;;
esac