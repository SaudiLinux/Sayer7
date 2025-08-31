#!/usr/bin/env python3
"""
Sayer7 - One-Step Installation Script
Advanced Web Reconnaissance Tool Installation
Author: SayerLinux
GitHub: https://github.com/SaudiLinux
Email: SayerLinux1@gmail.com
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

class Sayer7Installer:
    """
    Automated installer for Sayer7 web reconnaissance tool
    Handles dependencies, setup, and configuration
    """
    
    def __init__(self):
        self.system = platform.system()
        self.python_version = sys.version_info
        self.install_dir = Path(__file__).parent
        self.venv_dir = self.install_dir / "venv"
        
    def check_python_version(self):
        """Check Python version compatibility"""
        if self.python_version < (3, 7):
            print("❌ Python 3.7+ is required")
            return False
        print(f"✅ Python {self.python_version.major}.{self.python_version.minor} detected")
        return True
    
    def check_pip(self):
        """Check if pip is available"""
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"], 
                         check=True, capture_output=True)
            print("✅ pip is available")
            return True
        except subprocess.CalledProcessError:
            print("❌ pip is not available")
            return False
    
    def create_virtual_environment(self):
        """Create virtual environment"""
        print("📦 Creating virtual environment...")
        try:
            if self.venv_dir.exists():
                shutil.rmtree(self.venv_dir)
            
            subprocess.run([sys.executable, "-m", "venv", str(self.venv_dir)], 
                         check=True)
            print("✅ Virtual environment created")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create virtual environment: {e}")
            return False
    
    def install_dependencies(self):
        """Install all required dependencies"""
        print("📥 Installing dependencies...")
        
        # Determine pip path based on OS
        if self.system == "Windows":
            pip_path = self.venv_dir / "Scripts" / "pip"
            python_path = self.venv_dir / "Scripts" / "python"
        else:
            pip_path = self.venv_dir / "bin" / "pip"
            python_path = self.venv_dir / "bin" / "python"
        
        try:
            # Upgrade pip
            subprocess.run([str(pip_path), "install", "--upgrade", "pip"], 
                         check=True)
            
            # Install requirements
            requirements_file = self.install_dir / "requirements.txt"
            subprocess.run([str(pip_path), "install", "-r", str(requirements_file)], 
                         check=True)
            
            print("✅ Dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
    
    def install_system_dependencies(self):
        """Install system-level dependencies"""
        print("🔧 Installing system dependencies...")
        
        if self.system == "Linux":
            return self._install_linux_deps()
        elif self.system == "Darwin":  # macOS
            return self._install_macos_deps()
        elif self.system == "Windows":
            return self._install_windows_deps()
        else:
            print(f"⚠️  System {self.system} not explicitly supported")
            return True
    
    def _install_linux_deps(self):
        """Install Linux system dependencies"""
        try:
            # Ubuntu/Debian
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y", 
                         "python3-dev", "libssl-dev", "libffi-dev", 
                         "nmap", "dnsutils", "whois"], check=True)
            print("✅ Linux dependencies installed")
            return True
        except subprocess.CalledProcessError:
            print("⚠️  Failed to install some Linux dependencies")
            return False
    
    def _install_macos_deps(self):
        """Install macOS system dependencies"""
        try:
            subprocess.run(["brew", "install", "nmap", "dnsutils"], check=True)
            print("✅ macOS dependencies installed")
            return True
        except subprocess.CalledProcessError:
            print("⚠️  Failed to install some macOS dependencies")
            return False
    
    def _install_windows_deps(self):
        """Install Windows system dependencies"""
        print("✅ Windows dependencies - manual installation may be required for nmap")
        return True
    
    def create_launch_scripts(self):
        """Create launch scripts for different platforms"""
        print("🚀 Creating launch scripts...")
        
        # Determine paths
        if self.system == "Windows":
            python_path = self.venv_dir / "Scripts" / "python.exe"
            
            # Windows batch file
            batch_content = f"""@echo off
cd /d "{self.install_dir}"
call "{python_path}" Sayer7.py %*
pause
"""
            
            with open(self.install_dir / "sayer7.bat", "w") as f:
                f.write(batch_content)
            
            # Windows PowerShell script
            ps_content = f"""#!/usr/bin/env pwsh
Set-Location -Path "{self.install_dir}"
& "{python_path}" Sayer7.py $args
"""
            
            with open(self.install_dir / "sayer7.ps1", "w") as f:
                f.write(ps_content)
                
        else:
            # Unix shell script
            python_path = self.venv_dir / "bin" / "python"
            
            shell_content = f"""#!/bin/bash
cd "{self.install_dir}"
source "{self.venv_dir}/bin/activate"
exec "{python_path}" Sayer7.py "$@"
"""
            
            script_path = self.install_dir / "sayer7.sh"
            with open(script_path, "w") as f:
                f.write(shell_content)
            
            # Make executable
            os.chmod(script_path, 0o755)
        
        print("✅ Launch scripts created")
    
    def create_config_files(self):
        """Create configuration files"""
        print("⚙️  Creating configuration files...")
        
        config_dir = self.install_dir / "config"
        config_dir.mkdir(exist_ok=True)
        
        # Default configuration
        default_config = {
            "general": {
                "timeout": 30,
                "max_threads": 50,
                "user_agent": "Sayer7/1.0",
                "output_format": "json"
            },
            "proxy": {
                "enabled": False,
                "type": "http",
                "host": "127.0.0.1",
                "port": 8080
            },
            "search_engines": {
                "delay": 1,
                "max_results": 100,
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                ]
            },
            "vulnerability_scanning": {
                "xss_payloads_file": "config/xss_payloads.txt",
                "sqli_payloads_file": "config/sqli_payloads.txt",
                "admin_paths_file": "config/admin_paths.txt",
                "subdomain_wordlist": "config/subdomains.txt"
            }
        }
        
        with open(config_dir / "config.json", "w") as f:
            json.dump(default_config, f, indent=2)
        
        # Create payload files
        self._create_payload_files(config_dir)
        
        print("✅ Configuration files created")
    
    def _create_payload_files(self, config_dir):
        """Create default payload files"""
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        with open(config_dir / "xss_payloads.txt", "w") as f:
            f.write("\n".join(xss_payloads))
        
        # SQLi payloads
        sqli_payloads = [
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "admin'--",
            "1' OR '1'='1"
        ]
        
        with open(config_dir / "sqli_payloads.txt", "w") as f:
            f.write("\n".join(sqli_payloads))
        
        # Admin paths
        admin_paths = [
            "/admin",
            "/administrator",
            "/admin.php",
            "/admin.html",
            "/wp-admin",
            "/admin/login",
            "/administrator/index.php",
            "/admin/login.php",
            "/adminpanel",
            "/admincp"
        ]
        
        with open(config_dir / "admin_paths.txt", "w") as f:
            f.write("\n".join(admin_paths))
        
        # Subdomain wordlist
        subdomains = [
            "www", "mail", "ftp", "admin", "blog", "shop", "dev", "test",
            "staging", "api", "app", "mobile", "secure", "support", "help"
        ]
        
        with open(config_dir / "subdomains.txt", "w") as f:
            f.write("\n".join(subdomains))
    
    def create_desktop_shortcut(self):
        """Create desktop shortcut"""
        if self.system == "Windows":
            try:
                import winshell
                desktop = winshell.desktop()
                shortcut_path = os.path.join(desktop, "Sayer7.lnk")
                
                with winshell.shortcut(shortcut_path) as shortcut:
                    shortcut.path = str(self.install_dir / "sayer7.bat")
                    shortcut.description = "Sayer7 Web Reconnaissance Tool"
                    shortcut.working_directory = str(self.install_dir)
                
                print("✅ Desktop shortcut created")
            except:
                print("⚠️  Could not create desktop shortcut")
    
    def verify_installation(self):
        """Verify installation success"""
        print("🔍 Verifying installation...")
        
        # Check if virtual environment exists
        if not self.venv_dir.exists():
            print("❌ Virtual environment not found")
            return False
        
        # Check if main script exists
        if not (self.install_dir / "Sayer7.py").exists():
            print("❌ Main script not found")
            return False
        
        # Test import of key modules
        try:
            # Determine Python path
            if self.system == "Windows":
                python_path = self.venv_dir / "Scripts" / "python.exe"
            else:
                python_path = self.venv_dir / "bin" / "python"
            
            test_cmd = [str(python_path), "-c", 
                       "import sys; sys.path.insert(0, '.'); import Sayer7; print('✅ Installation verified')"]
            
            subprocess.run(test_cmd, check=True, capture_output=True)
            print("✅ Installation verified successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Installation verification failed: {e}")
            return False
    
    def print_success_message(self):
        """Print installation success message"""
        print("\n" + "="*60)
        print("🎉 Sayer7 Installation Complete!")
        print("="*60)
        print()
        print("📁 Installation Directory:", self.install_dir)
        print()
        print("🚀 How to use Sayer7:")
        
        if self.system == "Windows":
            print("   • Double-click sayer7.bat")
            print("   • Or run: .\\sayer7.bat --help")
        else:
            print("   • Run: ./sayer7.sh --help")
            print("   • Or: python3 Sayer7.py --help")
        
        print()
        print("📖 Examples:")
        print("   • Basic scan: sayer7 -u https://example.com")
        print("   • Full scan: sayer7 -u https://example.com --full")
        print("   • With proxy: sayer7 -u https://example.com --proxy 127.0.0.1:8080")
        print()
        print("📧 For support: SayerLinux1@gmail.com")
        print("🌐 GitHub: https://github.com/SaudiLinux")
        print("="*60)
    
    def install(self):
        """Run complete installation process"""
        print("🛠️  Sayer7 Installation Starting...")
        print("="*60)
        
        steps = [
            ("Checking Python version", self.check_python_version),
            ("Checking pip availability", self.check_pip),
            ("Installing system dependencies", self.install_system_dependencies),
            ("Creating virtual environment", self.create_virtual_environment),
            ("Installing Python dependencies", self.install_dependencies),
            ("Creating launch scripts", self.create_launch_scripts),
            ("Creating configuration files", self.create_config_files),
            ("Creating desktop shortcut", self.create_desktop_shortcut),
            ("Verifying installation", self.verify_installation)
        ]
        
        success = True
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            if not step_func():
                if step_name in ["Installing system dependencies", "Creating desktop shortcut"]:
                    print("⚠️  This step failed but continuing...")
                else:
                    success = False
                    break
        
        if success:
            self.print_success_message()
        else:
            print("\n❌ Installation failed. Please check the errors above.")

if __name__ == "__main__":
    installer = Sayer7Installer()
    installer.install()