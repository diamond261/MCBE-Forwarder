#!/bin/bash

# build.sh - Build script for C++17 MCBE_forwarder application
# Build command: g++ -std=c++17 -O2 -pthread main.cpp -o MCBE_forwarder

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
COMPILER="g++"
CXX_STANDARD="c++17"
OPTIMIZATION_LEVEL="-O2"
THREAD_FLAG="-pthread"
OUTPUT_NAME="MCBE_forwarder"
SOURCE_FILE="main.cpp"
REPO_URL=""  # Add your git repository URL here if needed

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect package manager
detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists yum; then
        echo "yum"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists zypper; then
        echo "zypper"
    elif command_exists brew; then
        echo "brew"
    else
        echo "unknown"
    fi
}

# Function to install dependencies
install_dependencies() {
    local pkg_manager=$(detect_package_manager)
    
    print_message "Detected package manager: $pkg_manager"
    print_message "Installing build dependencies..."
    
    case $pkg_manager in
        "apt")
            sudo apt-get update
            sudo apt-get install -y git g++ build-essential pkg-config
            ;;
        "yum")
            sudo yum install -y git gcc-c++ make pkgconfig
            ;;
        "dnf")
            sudo dnf install -y git gcc-c++ make pkgconfig
            ;;
        "pacman")
            sudo pacman -Sy --noconfirm git gcc make pkgconf
            ;;
        "zypper")
            sudo zypper install -y git gcc-c++ make pkg-config
            ;;
        "brew")
            brew install git gcc
            ;;
        *)
            print_warning "Unknown package manager. Please manually install:"
            echo "  - git"
            echo "  - g++ (gcc-c++ on some systems)"
            echo "  - build-essential/make"
            return 1
            ;;
    esac
    
    return 0
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for git
    if ! command_exists git; then
        missing_deps+=("git")
    fi
    
    # Check for g++
    if ! command_exists g++; then
        missing_deps+=("g++")
    fi
    
    # Check for make (optional but useful)
    if ! command_exists make; then
        missing_deps+=("make")
    fi
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        print_message "All dependencies are installed"
        return 0
    else
        print_warning "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
}

# Function to clone repository (if needed)
clone_repository() {
    if [ -n "$REPO_URL" ] && [ ! -d ".git" ]; then
        print_message "Cloning repository from $REPO_URL"
        git clone "$REPO_URL" .
    elif [ -d ".git" ]; then
        print_message "Git repository already exists"
    else
        print_message "No repository URL specified or already in project directory"
    fi
}

# Function to check for source file
check_source_file() {
    if [ ! -f "$SOURCE_FILE" ]; then
        print_error "Source file '$SOURCE_FILE' not found!"
        echo "Available source files in current directory:"
        ls -la *.cpp *.h 2>/dev/null || echo "No C++ files found"
        return 1
    fi
    return 0
}

# Function to build the project
build_project() {
    print_message "Building project..."
    echo "Command: $COMPILER -std=$CXX_STANDARD $OPTIMIZATION_LEVEL $THREAD_FLAG $SOURCE_FILE -o $OUTPUT_NAME"
    
    # Execute build command
    if $COMPILER -std=$CXX_STANDARD $OPTIMIZATION_LEVEL $THREAD_FLAG "$SOURCE_FILE" -o "$OUTPUT_NAME"; then
        print_message "Build successful!"
        print_message "Output binary: $(pwd)/$OUTPUT_NAME"
        
        # Show file info
        if [ -f "$OUTPUT_NAME" ]; then
            echo -e "\nBinary information:"
            file "$OUTPUT_NAME"
            echo "Size: $(du -h "$OUTPUT_NAME" | cut -f1)"
        fi
    else
        print_error "Build failed!"
        return 1
    fi
}

# Function to run tests (optional)
run_tests() {
    if [ -f "$OUTPUT_NAME" ]; then
        print_message "Testing the binary..."
        if ./"$OUTPUT_NAME" --help 2>&1 | grep -q "usage\|help\|Options"; then
            print_message "Binary executed successfully (help output detected)"
        elif ./"$OUTPUT_NAME" --version 2>&1 | grep -q "version"; then
            print_message "Binary executed successfully (version output detected)"
        else
            # Just try to run it
            if timeout 2 ./"$OUTPUT_NAME" 2>&1; then
                print_message "Binary executed successfully"
            else
                print_warning "Binary execution test inconclusive"
            fi
        fi
    fi
}

# Function to clean build artifacts
clean_build() {
    print_message "Cleaning build artifacts..."
    rm -f "$OUTPUT_NAME" *.o 2>/dev/null || true
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo
    echo "Build script for C++17 forwarder application"
    echo
    echo "Options:"
    echo "  build      Build the project (default)"
    echo "  deps       Install dependencies only"
    echo "  clean      Clean build artifacts"
    echo "  test       Build and run basic tests"
    echo "  all        Install dependencies, build, and test"
    echo "  help       Show this help message"
    echo
    echo "Examples:"
    echo "  $0           # Build the project"
    echo "  $0 deps      # Install dependencies only"
    echo "  $0 all       # Full installation and build"
    echo "  $0 clean     # Clean build artifacts"
    echo
    echo "Build command: $COMPILER -std=$CXX_STANDARD $OPTIMIZATION_LEVEL $THREAD_FLAG $SOURCE_FILE -o $OUTPUT_NAME"
}

# Main execution
main() {
    local action=${1:-"build"}
    
    case "$action" in
        "build")
            check_dependencies || {
                print_warning "Some dependencies are missing"
                read -p "Do you want to install missing dependencies? (y/N): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    install_dependencies
                fi
            }
            check_source_file || exit 1
            build_project
            ;;
            
        "deps"|"dependencies")
            install_dependencies
            check_dependencies
            ;;
            
        "clean")
            clean_build
            ;;
            
        "test")
            check_source_file || exit 1
            clean_build
            build_project
            run_tests
            ;;
            
        "all")
            install_dependencies
            check_source_file || exit 1
            clean_build
            build_project
            run_tests
            ;;
            
        "help"|"--help"|"-h")
            show_help
            ;;
            
        *)
            print_error "Unknown option: $action"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"