#!/bin/bash

# WebStrike Installation Script
# Automates the setup process for WebStrike vulnerability scanner

set -e  # Exit on any error

echo "🛡️  WebStrike Installation Script"
echo "=================================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3.11+ is installed
check_python() {
    log_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed. Please install Python 3.11 or higher."
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    python_major=$(echo $python_version | cut -d. -f1)
    python_minor=$(echo $python_version | cut -d. -f2)
    
    if [[ $python_major -lt 3 ]] || [[ $python_major -eq 3 && $python_minor -lt 11 ]]; then
        log_error "Python 3.11 or higher is required. Found: $python_version"
        exit 1
    fi
    
    log_success "Python $python_version found"
}

# Check if pip is installed
check_pip() {
    log_info "Checking pip installation..."
    
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is not installed. Please install pip3."
        exit 1
    fi
    
    log_success "pip3 found"
}

# Install Python dependencies
install_dependencies() {
    log_info "Installing Python dependencies..."
    
    if [[ -f "requirements.txt" ]]; then
        pip3 install -r requirements.txt
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found"
        exit 1
    fi
}

# Install wkhtmltopdf for PDF generation (optional)
install_wkhtmltopdf() {
    log_info "Installing wkhtmltopdf for PDF report generation..."
    
    if command -v wkhtmltopdf &> /dev/null; then
        log_success "wkhtmltopdf already installed"
        return
    fi
    
    # Detect OS and install accordingly
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y wkhtmltopdf
        elif command -v yum &> /dev/null; then
            sudo yum install -y wkhtmltopdf
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y wkhtmltopdf
        else
            log_warning "Could not install wkhtmltopdf automatically. Please install manually."
            return
        fi
        log_success "wkhtmltopdf installed"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install wkhtmltopdf
            log_success "wkhtmltopdf installed via Homebrew"
        else
            log_warning "Homebrew not found. Please install wkhtmltopdf manually from https://wkhtmltopdf.org/"
        fi
    else
        log_warning "Unsupported OS for automatic wkhtmltopdf installation. Please install manually."
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p reports/output
    mkdir -p reports/templates
    
    log_success "Directories created"
}

# Test installation
test_installation() {
    log_info "Testing WebStrike installation..."
    
    if python3 -m cli.webstrike_cli info &> /dev/null; then
        log_success "WebStrike CLI is working correctly"
    else
        log_error "WebStrike CLI test failed"
        exit 1
    fi
}

# Set up shell alias (optional)
setup_alias() {
    log_info "Setting up shell alias..."
    
    alias_command="alias webstrike='python3 -m cli.webstrike_cli'"
    
    # Add to bash profile if it exists
    if [[ -f "$HOME/.bashrc" ]]; then
        if ! grep -q "alias webstrike=" "$HOME/.bashrc"; then
            echo "$alias_command" >> "$HOME/.bashrc"
            log_success "Alias added to ~/.bashrc"
        fi
    fi
    
    # Add to zsh profile if it exists
    if [[ -f "$HOME/.zshrc" ]]; then
        if ! grep -q "alias webstrike=" "$HOME/.zshrc"; then
            echo "$alias_command" >> "$HOME/.zshrc"
            log_success "Alias added to ~/.zshrc"
        fi
    fi
    
    log_info "You can now use 'webstrike' command after restarting your shell"
}

# Display usage information
show_usage() {
    echo
    log_success "🎉 WebStrike installation completed successfully!"
    echo
    echo "📚 Quick Start:"
    echo "  python3 -m cli.webstrike_cli info                    # Show tool information"
    echo "  python3 -m cli.webstrike_cli scan -u https://example.com  # Basic scan"
    echo "  python3 examples.py                                  # Run example scans"
    echo
    echo "📖 Documentation:"
    echo "  README.md  - Project overview and quick start"
    echo "  USAGE.md   - Comprehensive usage guide"
    echo
    echo "🔧 Configuration:"
    echo "  config.ini - Customize default settings"
    echo
    echo "⚠️  Legal Notice:"
    echo "  Only use WebStrike on systems you own or have explicit permission to test."
    echo
}

# Main installation flow
main() {
    echo "Starting WebStrike installation..."
    echo
    
    # Check prerequisites
    check_python
    check_pip
    
    # Install dependencies
    install_dependencies
    
    # Optional components
    if [[ "${1:-}" != "--minimal" ]]; then
        install_wkhtmltopdf
    fi
    
    # Setup
    create_directories
    test_installation
    
    # Optional shell integration
    if [[ "${1:-}" == "--with-alias" ]]; then
        setup_alias
    fi
    
    # Show completion message
    show_usage
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "WebStrike Installation Script"
        echo
        echo "Usage: $0 [OPTIONS]"
        echo
        echo "Options:"
        echo "  --minimal      Skip optional components (wkhtmltopdf)"
        echo "  --with-alias   Set up shell alias for 'webstrike' command"
        echo "  --help, -h     Show this help message"
        echo
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
