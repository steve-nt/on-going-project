#!/usr/bin/env python3
"""
Lab 3 Project Launcher
Automated setup and execution script for Authentication Security project
Handles dependencies, provides guided execution, and manages multiple processes
"""

import subprocess
import sys
import os
import time
import signal
from pathlib import Path

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ProjectLauncher:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.processes = []
        self.required_packages = [
            'flask',
            'bcrypt',
            'argon2-cffi',
            'pyotp',
            'qrcode',
            'pillow',
            'fido2',
            'requests'
        ]
        
    def print_header(self, text):
        """Print a formatted header"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{text.center(80)}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")
    
    def print_success(self, text):
        """Print success message"""
        print(f"{Colors.GREEN}✓ {text}{Colors.END}")
    
    def print_error(self, text):
        """Print error message"""
        print(f"{Colors.RED}✗ {text}{Colors.END}")
    
    def print_info(self, text):
        """Print info message"""
        print(f"{Colors.BLUE}ℹ {text}{Colors.END}")
    
    def print_warning(self, text):
        """Print warning message"""
        print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")
    
    def check_python_version(self):
        """Check if Python version is adequate"""
        self.print_header("Python Version Check")
        version = sys.version_info
        print(f"Python version: {version.major}.{version.minor}.{version.micro}")
        
        if version.major >= 3 and version.minor >= 7:
            self.print_success("Python version is adequate (3.7+)")
            return True
        else:
            self.print_error("Python 3.7 or higher is required")
            return False
    
    def check_dependencies(self):
        """Check if required packages are installed"""
        self.print_header("Dependency Check")
        missing_packages = []
        
        for package in self.required_packages:
            try:
                if package == 'pillow':
                    __import__('PIL')
                else:
                    __import__(package.replace('-', '_'))
                self.print_success(f"{package} is installed")
            except ImportError:
                self.print_error(f"{package} is NOT installed")
                missing_packages.append(package)
        
        return missing_packages
    
    def install_dependencies(self, packages):
        """Install missing dependencies"""
        if not packages:
            return True
        
        self.print_warning(f"Missing packages: {', '.join(packages)}")
        response = input(f"\n{Colors.YELLOW}Install missing packages? (y/n): {Colors.END}").lower()
        
        if response != 'y':
            self.print_warning("Skipping installation. Some features may not work.")
            return False
        
        print(f"\n{Colors.CYAN}Installing packages...{Colors.END}")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '--user'
            ] + packages)
            self.print_success("All packages installed successfully!")
            return True
        except subprocess.CalledProcessError:
            self.print_error("Failed to install packages. Please install manually.")
            return False
    
    def start_background_process(self, name, command, cwd):
        """Start a background process"""
        try:
            print(f"\n{Colors.CYAN}Starting {name}...{Colors.END}")
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False
            )
            self.processes.append((name, process))
            time.sleep(2)  # Give process time to start
            
            # Check if process is still running
            if process.poll() is None:
                self.print_success(f"{name} started (PID: {process.pid})")
                return True
            else:
                self.print_error(f"{name} failed to start")
                return False
        except Exception as e:
            self.print_error(f"Failed to start {name}: {e}")
            return False
    
    def run_foreground_script(self, name, command, cwd):
        """Run a script in foreground with output"""
        print(f"\n{Colors.CYAN}Running {name}...{Colors.END}")
        print(f"{Colors.YELLOW}{'─'*80}{Colors.END}")
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                check=False
            )
            print(f"{Colors.YELLOW}{'─'*80}{Colors.END}")
            if result.returncode == 0:
                self.print_success(f"{name} completed successfully")
                return True
            else:
                self.print_warning(f"{name} exited with code {result.returncode}")
                return False
        except Exception as e:
            self.print_error(f"Failed to run {name}: {e}")
            return False
    
    def cleanup_processes(self):
        """Terminate all background processes"""
        if self.processes:
            print(f"\n{Colors.YELLOW}Cleaning up background processes...{Colors.END}")
            for name, process in self.processes:
                if process.poll() is None:
                    print(f"Stopping {name}...")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
            self.processes.clear()
            self.print_success("All processes stopped")
    
    def show_main_menu(self):
        """Show main menu and return choice"""
        self.print_header("Lab 3 Project Launcher - Main Menu")
        print("Choose an option:\n")
        print(f"{Colors.BOLD}1.{Colors.END} Quick Demo (Run full demonstration)")
        print(f"{Colors.BOLD}2.{Colors.END} Step-by-Step Guided Tour")
        print(f"{Colors.BOLD}3.{Colors.END} Individual Component Selection")
        print(f"{Colors.BOLD}4.{Colors.END} Run Tests & Attack Demonstrations")
        print(f"{Colors.BOLD}5.{Colors.END} Check System Status")
        print(f"{Colors.BOLD}6.{Colors.END} Exit")
        
        choice = input(f"\n{Colors.CYAN}Enter choice (1-6): {Colors.END}").strip()
        return choice
    
    def quick_demo(self):
        """Run the complete demonstration automatically"""
        self.print_header("Quick Demo Mode")
        print("This will run a complete demonstration of the authentication system.")
        print("It will start the server, demonstrate attacks, and show security features.\n")
        
        response = input(f"{Colors.CYAN}Continue? (y/n): {Colors.END}").lower()
        if response != 'y':
            return
        
        # Step 1: Start integrated app
        core_dir = self.base_dir / "Core Application Files"
        self.start_background_process(
            "Integrated Authentication Server",
            [sys.executable, "integrated_app.py"],
            core_dir
        )
        
        time.sleep(2)
        self.print_info("Server is running on http://localhost:5000")
        
        # Step 2: Run standalone demos
        mfa_dir = self.base_dir / "MFA Implementation"
        
        input(f"\n{Colors.CYAN}Press ENTER to see TOTP demonstration...{Colors.END}")
        self.run_foreground_script(
            "TOTP Demo",
            [sys.executable, "mfa_totp.py"],
            mfa_dir
        )
        
        input(f"\n{Colors.CYAN}Press ENTER to see HOTP demonstration...{Colors.END}")
        self.run_foreground_script(
            "HOTP Demo",
            [sys.executable, "mfa_hotp.py"],
            mfa_dir
        )
        
        input(f"\n{Colors.CYAN}Press ENTER to see WebAuthn/FIDO2 demonstration...{Colors.END}")
        self.run_foreground_script(
            "WebAuthn Demo",
            [sys.executable, "fido2_webauthn.py"],
            mfa_dir
        )
        
        # Step 3: Run attacks
        attack_dir = self.base_dir / "Attack & Testing Scripts"
        
        input(f"\n{Colors.CYAN}Press ENTER to see timing attack demonstration...{Colors.END}")
        self.run_foreground_script(
            "Timing Attack Demo",
            [sys.executable, "timing_attack.py"],
            attack_dir
        )
        
        input(f"\n{Colors.CYAN}Press ENTER to see password cracking demonstration...{Colors.END}")
        self.run_foreground_script(
            "Password Cracking Demo",
            [sys.executable, "dictionary_attack.py"],
            attack_dir
        )
        
        self.print_success("\nQuick demo completed!")
        
    def step_by_step_tour(self):
        """Guided step-by-step tour"""
        self.print_header("Step-by-Step Guided Tour")
        
        steps = [
            {
                "title": "1. Core Authentication Server",
                "description": "Start the main Flask application with password hashing and MFA",
                "type": "background",
                "command": [sys.executable, "integrated_app.py"],
                "cwd": self.base_dir / "Core Application Files"
            },
            {
                "title": "2. TOTP (Time-based OTP) Demonstration",
                "description": "Shows TOTP enrollment, QR codes, and time window verification",
                "type": "foreground",
                "command": [sys.executable, "mfa_totp.py"],
                "cwd": self.base_dir / "MFA Implementation"
            },
            {
                "title": "3. HOTP (Counter-based OTP) Demonstration",
                "description": "Shows HOTP enrollment and counter desynchronization",
                "type": "foreground",
                "command": [sys.executable, "mfa_hotp.py"],
                "cwd": self.base_dir / "MFA Implementation"
            },
            {
                "title": "4. WebAuthn/FIDO2 Demonstration",
                "description": "Shows origin binding and phishing protection",
                "type": "foreground",
                "command": [sys.executable, "fido2_webauthn.py"],
                "cwd": self.base_dir / "MFA Implementation"
            },
            {
                "title": "5. Timing Attack Demonstration",
                "description": "Compares naive vs constant-time comparison",
                "type": "foreground",
                "command": [sys.executable, "timing_attack.py"],
                "cwd": self.base_dir / "Attack & Testing Scripts"
            },
            {
                "title": "6. Password Cracking Demonstration",
                "description": "Dictionary and brute-force attacks on different hash algorithms",
                "type": "foreground",
                "command": [sys.executable, "dictionary_attack.py"],
                "cwd": self.base_dir / "Attack & Testing Scripts"
            },
            {
                "title": "7. MITM Relay Proxy (Optional)",
                "description": "Demonstrates OTP relay attack (requires server running)",
                "type": "background",
                "command": [sys.executable, "mitm_proxy.py"],
                "cwd": self.base_dir / "Attack & Testing Scripts"
            }
        ]
        
        for i, step in enumerate(steps):
            print(f"\n{Colors.BOLD}{Colors.BLUE}{'─'*80}{Colors.END}")
            print(f"{Colors.BOLD}{step['title']}{Colors.END}")
            print(f"{Colors.CYAN}{step['description']}{Colors.END}")
            print(f"{Colors.BOLD}{Colors.BLUE}{'─'*80}{Colors.END}")
            
            response = input(f"\n{Colors.CYAN}Run this step? (y/n/q to quit): {Colors.END}").lower()
            
            if response == 'q':
                break
            elif response == 'y':
                if step['type'] == 'background':
                    self.start_background_process(step['title'], step['command'], step['cwd'])
                else:
                    self.run_foreground_script(step['title'], step['command'], step['cwd'])
        
        self.print_success("\nGuided tour completed!")
    
    def component_menu(self):
        """Show menu for individual components"""
        while True:
            self.print_header("Individual Component Selection")
            print("Choose a component to run:\n")
            print(f"{Colors.BOLD}Core Applications:{Colors.END}")
            print("  1. Integrated Authentication Server (background)")
            print("  2. Basic Authentication Server (background)")
            print(f"\n{Colors.BOLD}MFA Demonstrations:{Colors.END}")
            print("  3. TOTP Demo")
            print("  4. HOTP Demo")
            print("  5. WebAuthn/FIDO2 Demo")
            print("  6. WebAuthn Interactive Relay Demo (requires servers)")
            print(f"\n{Colors.BOLD}Attack Demonstrations:{Colors.END}")
            print("  7. Timing Attack")
            print("  8. Password Cracking")
            print("  9. MITM Relay Proxy (background)")
            print(f"\n{Colors.BOLD}Other:{Colors.END}")
            print("  10. Stop all background processes")
            print("  11. Back to main menu")
            
            choice = input(f"\n{Colors.CYAN}Enter choice: {Colors.END}").strip()
            
            core_dir = self.base_dir / "Core Application Files"
            mfa_dir = self.base_dir / "MFA Implementation"
            attack_dir = self.base_dir / "Attack & Testing Scripts"
            
            if choice == '1':
                self.start_background_process(
                    "Integrated Authentication Server",
                    [sys.executable, "integrated_app.py"],
                    core_dir
                )
            elif choice == '2':
                self.start_background_process(
                    "Basic Authentication Server",
                    [sys.executable, "app.py"],
                    core_dir
                )
            elif choice == '3':
                self.run_foreground_script(
                    "TOTP Demo",
                    [sys.executable, "mfa_totp.py"],
                    mfa_dir
                )
            elif choice == '4':
                self.run_foreground_script(
                    "HOTP Demo",
                    [sys.executable, "mfa_hotp.py"],
                    mfa_dir
                )
            elif choice == '5':
                self.run_foreground_script(
                    "WebAuthn Demo",
                    [sys.executable, "fido2_webauthn.py"],
                    mfa_dir
                )
            elif choice == '6':
                self.print_info("This requires integrated_app.py (port 5000) and mitm_proxy.py (port 8080) running")
                self.run_foreground_script(
                    "WebAuthn Interactive Relay Demo",
                    [sys.executable, "fido2_webauthn.py", "relay-demo"],
                    mfa_dir
                )
            elif choice == '7':
                self.run_foreground_script(
                    "Timing Attack",
                    [sys.executable, "timing_attack.py"],
                    attack_dir
                )
            elif choice == '8':
                self.run_foreground_script(
                    "Password Cracking",
                    [sys.executable, "dictionary_attack.py"],
                    attack_dir
                )
            elif choice == '9':
                self.start_background_process(
                    "MITM Relay Proxy",
                    [sys.executable, "mitm_proxy.py"],
                    attack_dir
                )
            elif choice == '10':
                self.cleanup_processes()
            elif choice == '11':
                break
            else:
                self.print_warning("Invalid choice. Please try again.")
    
    def run_tests(self):
        """Run all test and attack demonstrations"""
        self.print_header("Tests & Attack Demonstrations")
        
        attack_dir = self.base_dir / "Attack & Testing Scripts"
        
        print("This will run all attack and security demonstrations:\n")
        print("1. Timing Attack Demo")
        print("2. Password Cracking Demo")
        print()
        
        response = input(f"{Colors.CYAN}Continue? (y/n): {Colors.END}").lower()
        if response != 'y':
            return
        
        self.run_foreground_script(
            "Timing Attack",
            [sys.executable, "timing_attack.py"],
            attack_dir
        )
        
        input(f"\n{Colors.CYAN}Press ENTER to continue to password cracking...{Colors.END}")
        
        self.run_foreground_script(
            "Password Cracking",
            [sys.executable, "dictionary_attack.py"],
            attack_dir
        )
        
        self.print_success("\nAll tests completed!")
    
    def check_status(self):
        """Check system status"""
        self.print_header("System Status")
        
        # Check Python
        print(f"{Colors.BOLD}Python:{Colors.END} {sys.version.split()[0]}")
        
        # Check dependencies
        print(f"\n{Colors.BOLD}Dependencies:{Colors.END}")
        for package in self.required_packages:
            try:
                if package == 'pillow':
                    __import__('PIL')
                else:
                    __import__(package.replace('-', '_'))
                print(f"  {Colors.GREEN}✓{Colors.END} {package}")
            except ImportError:
                print(f"  {Colors.RED}✗{Colors.END} {package}")
        
        # Check running processes
        print(f"\n{Colors.BOLD}Running Processes:{Colors.END}")
        if self.processes:
            for name, process in self.processes:
                status = "running" if process.poll() is None else "stopped"
                color = Colors.GREEN if status == "running" else Colors.RED
                print(f"  {color}●{Colors.END} {name} - {status}")
        else:
            print(f"  {Colors.YELLOW}No background processes started by launcher{Colors.END}")
        
        # Check file structure
        print(f"\n{Colors.BOLD}Project Structure:{Colors.END}")
        dirs_to_check = [
            "Core Application Files",
            "MFA Implementation",
            "Attack & Testing Scripts"
        ]
        for dir_name in dirs_to_check:
            dir_path = self.base_dir / dir_name
            if dir_path.exists():
                print(f"  {Colors.GREEN}✓{Colors.END} {dir_name}")
            else:
                print(f"  {Colors.RED}✗{Colors.END} {dir_name}")
        
        input(f"\n{Colors.CYAN}Press ENTER to continue...{Colors.END}")
    
    def run(self):
        """Main execution loop"""
        # Setup signal handler for cleanup
        def signal_handler(sig, frame):
            print(f"\n{Colors.YELLOW}Interrupt received, cleaning up...{Colors.END}")
            self.cleanup_processes()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Welcome message
        self.print_header("Lab 3: Authentication Security Project Launcher")
        print("Welcome! This launcher will help you run and demonstrate the project.\n")
        
        # Check Python version
        if not self.check_python_version():
            return
        
        # Check and install dependencies
        missing = self.check_dependencies()
        if missing:
            if not self.install_dependencies(missing):
                print(f"\n{Colors.YELLOW}Continuing with missing dependencies...{Colors.END}")
        
        # Main menu loop
        try:
            while True:
                choice = self.show_main_menu()
                
                if choice == '1':
                    self.quick_demo()
                elif choice == '2':
                    self.step_by_step_tour()
                elif choice == '3':
                    self.component_menu()
                elif choice == '4':
                    self.run_tests()
                elif choice == '5':
                    self.check_status()
                elif choice == '6':
                    break
                else:
                    self.print_warning("Invalid choice. Please try again.")
        finally:
            self.cleanup_processes()
            self.print_header("Thank You!")
            print("All background processes have been stopped.")
            print("Check the Artifacts folder for generated files (QR codes, logs, etc.)\n")

if __name__ == "__main__":
    launcher = ProjectLauncher()
    launcher.run()
