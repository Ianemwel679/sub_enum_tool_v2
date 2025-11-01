#!/bin/bash

# Enhanced Subdomain Enumeration Script
# WARNING: Only use this on domains you own or have explicit written permission to test
# Unauthorized scanning may be illegal and violate terms of service

set -euo pipefail  


readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' 


readonly SCRIPT_VERSION="2.0"
readonly CONNECT_TIMEOUT=3
readonly MAX_TIMEOUT=5
readonly PARALLEL_CHECKS=10


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

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════╗
    Subdomain Enumeration Tool v2.0
         by N3m3_sys and Dorothy
           Use Responsibly
╚═══════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}


validate_domain() {
    local domain=$1
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_error "Invalid domain format: $domain"
        return 1
    fi
    return 0
}


check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root is not recommended for security reasons"
    fi
}


show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] <domain>

OPTIONS:
    -h, --help              Show this help message
    -o, --output DIR        Specify custom output directory
    -w, --wordlist FILE     Custom wordlist for bruteforce
    -t, --threads NUM       Number of parallel threads for live checks (default: $PARALLEL_CHECKS)
    -s, --skip-live         Skip live subdomain checking
    -q, --quiet             Minimal output
    --no-passive            Skip passive enumeration tools
    --no-bruteforce         Skip bruteforce enumeration

EXAMPLES:
    $0 example.com
    $0 -o my_scan -w custom.txt example.com
    $0 --skip-live -q example.com

EOF
    exit 0
}


parse_arguments() {
    DOMAIN=""
    OUTPUT_DIR=""
    WORDLIST=""
    THREADS=$PARALLEL_CHECKS
    SKIP_LIVE=false
    QUIET=false
    NO_PASSIVE=false
    NO_BRUTEFORCE=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -w|--wordlist)
                WORDLIST="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -s|--skip-live)
                SKIP_LIVE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            --no-passive)
                NO_PASSIVE=true
                shift
                ;;
            --no-bruteforce)
                NO_BRUTEFORCE=true
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                ;;
            *)
                DOMAIN="$1"
                shift
                ;;
        esac
    done
    
    if [ -z "$DOMAIN" ]; then
        print_error "Domain is required"
        show_usage
    fi
    
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="subdomain_enum_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    fi
}


check_tool() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

check_dependencies() {
    print_status "Checking for required tools..."
    local tools_missing=()
    
    
    for tool in curl dig; do
        if ! check_tool "$tool"; then
            print_error "Essential tool missing: $tool"
            tools_missing+=("$tool")
        fi
    done
    
    if [ ${#tools_missing[@]} -gt 0 ]; then
        print_error "Please install missing essential tools: ${tools_missing[*]}"
        exit 1
    fi
    
    
    local enum_tools=("subfinder" "assetfinder" "amass" "gobuster" "dirb")
    local available_tools=()
    
    for tool in "${enum_tools[@]}"; do
        if check_tool "$tool"; then
            available_tools+=("$tool")
            [ "$QUIET" = false ] && print_success "$tool is available"
        else
            [ "$QUIET" = false ] && print_warning "$tool is not installed (optional)"
        fi
    done
    
    if [ ${#available_tools[@]} -eq 0 ]; then
        print_warning "No enumeration tools found. Results will be limited."
        print_status "Install suggestions:"
        echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "  go install github.com/tomnomnom/assetfinder@latest"
        echo "  go install -v github.com/owasp-amass/amass/v4/...@master"
        echo "  sudo apt install gobuster dirb"
    fi
}


run_tool() {
    local tool_name=$1
    local command=$2
    local output_file=$3
    
    [ "$QUIET" = false ] && print_status "Running $tool_name..."
    
    if timeout 300 bash -c "$command" > "$output_file" 2>/dev/null; then
        local count=$(grep -c . "$output_file" 2>/dev/null || echo "0")
        [ "$QUIET" = false ] && print_success "$tool_name completed - Found $count subdomains"
        return 0
    else
        [ "$QUIET" = false ] && print_warning "$tool_name failed or timed out"
        touch "$output_file"
        return 1
    fi
}


verify_dns() {
    local subdomain=$1
    if dig +short "$subdomain" @8.8.8.8 | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        return 0
    fi
    return 1
}


check_live_subdomains() {
    local input_file=$1
    local output_file=$2
    
    print_status "Checking for live subdomains (this may take a while)..."
    
    > "$output_file"
    local temp_dir=$(mktemp -d)
    
    
    check_single() {
        local subdomain=$1
        local temp_file=$2
        local clean_subdomain=$(echo "$subdomain" | sed 's/\.$//')
        
        
        if ! verify_dns "$clean_subdomain"; then
            return
        fi
        
        
        for protocol in "https" "http"; do
            if curl -k -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT \
                   -o /dev/null -w "%{http_code}" "${protocol}://${clean_subdomain}" 2>/dev/null | \
                   grep -qE "^(2|3)[0-9]{2}$"; then
                echo "${protocol}://${clean_subdomain}" >> "$temp_file"
                [ "$QUIET" = false ] && print_success "Live: ${protocol}://${clean_subdomain}"
                break
            fi
        done
    }
    
    export -f check_single verify_dns print_success
    export CONNECT_TIMEOUT MAX_TIMEOUT QUIET GREEN NC
    
    
    local counter=0
    while IFS= read -r subdomain; do
        local temp_file="${temp_dir}/${counter}.txt"
        check_single "$subdomain" "$temp_file" &
        
        counter=$((counter + 1))
        
        
        if [ $(jobs -r | wc -l) -ge $THREADS ]; then
            wait -n
        fi
    done < "$input_file"
    
    wait
    
    
    cat "${temp_dir}"/*.txt 2>/dev/null | sort -u > "$output_file"
    rm -rf "$temp_dir"
}

# Main enumeration function
enumerate_subdomains() {
    cd "$OUTPUT_DIR"
    
    
    if [ "$NO_PASSIVE" = false ]; then
        print_status "Starting passive enumeration..."
        
        if check_tool "subfinder"; then
            run_tool "Subfinder" "subfinder -d $DOMAIN -silent" "subfinder_results.txt"
        fi
        
        if check_tool "assetfinder"; then
            run_tool "Assetfinder" "assetfinder --subs-only $DOMAIN" "assetfinder_results.txt"
        fi
        
        if check_tool "amass"; then
            run_tool "Amass" "amass enum -passive -d $DOMAIN -timeout 5" "amass_results.txt"
        fi
    fi
    
    
    if [ "$NO_BRUTEFORCE" = false ]; then
        local wordlist_to_use="$WORDLIST"
        
        if [ -z "$wordlist_to_use" ]; then
            # Try common wordlist locations
            for wl in "/usr/share/wordlists/dirb/common.txt" \
                      "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
                      "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
                      "/usr/share/wordlists/dirb/big.txt"; do
                if [ -f "$wl" ]; then
                    wordlist_to_use="$wl"
                    break
                fi
            done
        fi
        
        if [ -n "$wordlist_to_use" ] && [ -f "$wordlist_to_use" ]; then
            # Run Gobuster if available
            if check_tool "gobuster"; then
                run_tool "Gobuster DNS" "gobuster dns -d $DOMAIN -w $wordlist_to_use -q --no-error" "gobuster_results.txt"
            else
                touch "gobuster_results.txt"
            fi
            
            
            if check_tool "dirb"; then
                print_status "Running DIRB DNS enumeration..."
                > "dirb_results.txt"
                
                # DIRB doesn't have direct DNS mode, so we'll use it differently
                # Generate subdomains by prefixing wordlist entries
                local temp_subs=$(mktemp)
                while IFS= read -r word; do
                    # Skip empty lines and comments
                    [[ -z "$word" || "$word" =~ ^# ]] && continue
                    echo "${word}.${DOMAIN}"
                done < "$wordlist_to_use" > "$temp_subs"
                
                # Test each subdomain with DIRB's DNS resolution
                local count=0
                while IFS= read -r subdomain; do
                    if host "$subdomain" >/dev/null 2>&1; then
                        echo "$subdomain" >> "dirb_results.txt"
                        count=$((count + 1))
                    fi
                done < "$temp_subs"
                
                rm -f "$temp_subs"
                [ "$QUIET" = false ] && print_success "DIRB DNS check completed - Found $count subdomains"
            else
                touch "dirb_results.txt"
            fi
        else
            print_warning "No wordlist found for bruteforce enumeration"
            touch "gobuster_results.txt"
            touch "dirb_results.txt"
        fi
    else
        touch "gobuster_results.txt"
        touch "dirb_results.txt"
    fi
    
    
    print_status "Combining and deduplicating results..."
    cat ./*_results.txt 2>/dev/null | \
        grep -oE "([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+$DOMAIN" | \
        sort -u > "all_subdomains.txt"
    
    local total_subdomains=$(grep -c . "all_subdomains.txt" 2>/dev/null || echo "0")
    print_success "Total unique subdomains found: $total_subdomains"
    
    
    if [ "$SKIP_LIVE" = false ] && [ "$total_subdomains" -gt 0 ]; then
        check_live_subdomains "all_subdomains.txt" "live_subdomains.txt"
    else
        touch "live_subdomains.txt"
    fi
}


generate_report() {
    cd "$OUTPUT_DIR"
    
    local total_subdomains=$(grep -c . "all_subdomains.txt" 2>/dev/null || echo "0")
    local live_count=$(grep -c . "live_subdomains.txt" 2>/dev/null || echo "0")
    
    print_status "Generating comprehensive report..."
    
    cat > "summary_report.txt" << EOF
═══════════════════════════════════════════════════════════
         Subdomain Enumeration Report
═══════════════════════════════════════════════════════════

Target Domain: $DOMAIN
Scan Date: $(date '+%Y-%m-%d %H:%M:%S %Z')
Script Version: $SCRIPT_VERSION
Output Directory: $(pwd)

═══════════════════════════════════════════════════════════
                    Results Summary
═══════════════════════════════════════════════════════════

Tool Results:
$([ -f subfinder_results.txt ] && echo "  • Subfinder:   $(grep -c . subfinder_results.txt 2>/dev/null || echo 0) subdomains" || echo "  • Subfinder:   Not run")
$([ -f assetfinder_results.txt ] && echo "  • Assetfinder: $(grep -c . assetfinder_results.txt 2>/dev/null || echo 0) subdomains" || echo "  • Assetfinder: Not run")
$([ -f amass_results.txt ] && echo "  • Amass:       $(grep -c . amass_results.txt 2>/dev/null || echo 0) subdomains" || echo "  • Amass:       Not run")
$([ -f gobuster_results.txt ] && echo "  • Gobuster:    $(grep -c . gobuster_results.txt 2>/dev/null || echo 0) subdomains" || echo "  • Gobuster:    Not run")
$([ -f dirb_results.txt ] && echo "  • DIRB:        $(grep -c . dirb_results.txt 2>/dev/null || echo 0) subdomains" || echo "  • DIRB:        Not run")

═══════════════════════════════════════════════════════════

Total Unique Subdomains: $total_subdomains
Live Subdomains (HTTP/HTTPS): $live_count
Success Rate: $([ $total_subdomains -gt 0 ] && echo "scale=2; $live_count * 100 / $total_subdomains" | bc || echo "0")%

═══════════════════════════════════════════════════════════
                    Files Generated
═══════════════════════════════════════════════════════════

  • all_subdomains.txt     - All unique subdomains discovered
  • live_subdomains.txt    - Subdomains responding to HTTP/HTTPS
  • *_results.txt          - Individual tool outputs
  • summary_report.txt     - This comprehensive report

═══════════════════════════════════════════════════════════
                  Recommended Next Steps
═══════════════════════════════════════════════════════════

1. Review live_subdomains.txt for interesting targets
2. Perform port scanning on live hosts (with authorization)
3. Conduct web application testing (with authorization)
4. Check for subdomain takeover vulnerabilities
5. Analyze DNS records for misconfigurations

═══════════════════════════════════════════════════════════

⚠️  LEGAL REMINDER: Only test systems you own or have 
   explicit written permission to test. Unauthorized 
   testing may violate laws and terms of service.

═══════════════════════════════════════════════════════════
EOF

    
    cat > "report.json" << EOF
{
  "domain": "$DOMAIN",
  "scan_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "script_version": "$SCRIPT_VERSION",
  "statistics": {
    "total_subdomains": $total_subdomains,
    "live_subdomains": $live_count,
    "subfinder": $(grep -c . subfinder_results.txt 2>/dev/null || echo 0),
    "assetfinder": $(grep -c . assetfinder_results.txt 2>/dev/null || echo 0),
    "amass": $(grep -c . amass_results.txt 2>/dev/null || echo 0),
    "gobuster": $(grep -c . gobuster_results.txt 2>/dev/null || echo 0),
    "dirb": $(grep -c . dirb_results.txt 2>/dev/null || echo 0)
  },
  "output_directory": "$(pwd)"
}
EOF

    print_success "Reports generated: summary_report.txt, report.json"
}


cleanup() {
    if [ $? -ne 0 ]; then
        print_error "Script interrupted or failed"
    fi
}

# Main execution
main() {
    trap cleanup EXIT
    
    print_banner
    check_root
    parse_arguments "$@"
    
    
    if ! mkdir -p "$OUTPUT_DIR"; then
        print_error "Failed to create output directory: $OUTPUT_DIR"
        exit 1
    fi
    
    print_status "Starting subdomain enumeration for: $DOMAIN"
    print_status "Output directory: $OUTPUT_DIR"
    
    
    print_warning "═══════════════════════════════════════════════════════"
    print_warning "LEGAL DISCLAIMER: Ensure you have authorization!"
    print_warning "═══════════════════════════════════════════════════════"
    read -p "Do you have explicit permission to scan $DOMAIN? (yes/no): " permission
    
    if [[ ! $permission =~ ^[Yy][Ee][Ss]$ ]]; then
        print_error "Permission not confirmed - Exiting"
        exit 1
    fi
    
    check_dependencies
    enumerate_subdomains
    generate_report
    
    
    cd "$OUTPUT_DIR"
    local total_subdomains=$(grep -c . "all_subdomains.txt" 2>/dev/null || echo "0")
    local live_count=$(grep -c . "live_subdomains.txt" 2>/dev/null || echo "0")
    
    echo ""
    print_success "═══════════════════════════════════════════════════════"
    print_success "Enumeration Complete!"
    print_success "═══════════════════════════════════════════════════════"
    print_status "Results location: $(pwd)"
    print_status "Total subdomains: $total_subdomains"
    print_status "Live subdomains: $live_count"
    print_status "Check summary_report.txt for detailed analysis"
    
    
    if [ "$total_subdomains" -gt 0 ]; then
        echo ""
        print_status "Preview of discovered subdomains:"
        head -10 "all_subdomains.txt" | while read -r subdomain; do
            echo "  • $subdomain"
        done
        [ "$total_subdomains" -gt 10 ] && echo "  ... and $((total_subdomains - 10)) more"
    fi
    
    if [ "$live_count" -gt 0 ]; then
        echo ""
        print_status "Preview of live subdomains:"
        head -5 "live_subdomains.txt" | while read -r subdomain; do
            echo "  • $subdomain"
        done
        [ "$live_count" -gt 5 ] && echo "  ... and $((live_count - 5)) more"
    fi
}


main "$@"
