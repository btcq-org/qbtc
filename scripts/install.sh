#!/bin/bash
set -e

# ========== DEFAULTS ==========
DEFAULT_VERSION="1.0.21"
GITHUB_REPO="btcq-org/qbtc"
INSTALL_DIR="/usr/local/bin"
QBTCD_HOME="$HOME/.qbtc"
BIFROST_HOME="$HOME/.bifrost"
ARCH="linux-amd64"
GENESIS_URL="https://sgp1.vultrobjects.com/genesis/genesis.json"
GENESIS_BIN_URL="https://sgp1.vultrobjects.com/genesis/genesis-954355.bin"
COSMOVISOR_URL="https://github.com/cosmos/cosmos-sdk/releases/download/cosmovisor%2Fv1.7.1/cosmovisor-v1.7.1-linux-amd64.tar.gz"
STATESYNC_RPC="http://45.76.190.51:26657"

# ========== COLORS ==========
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ========== STATE ==========
INSTALLED_QBTCD=false
INSTALLED_BIFROST=false
INSTALLED_COSMOVISOR=false
USE_COSMOVISOR=false
SETUP_QBTCD_SERVICE=false
SETUP_BIFROST_SERVICE=false
VERSION=""

# ========== UTILITY FUNCTIONS ==========

print_header() {
    echo ""
    echo -e "${YELLOW}=== $1 ===${NC}"
    echo ""
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# ask_yn "Question?" "y|n" - returns 0 for yes, 1 for no
ask_yn() {
    local prompt="$1"
    local default="$2"
    local response

    if [[ "$default" == "y" || "$default" == "Y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -r -p "$prompt" response < /dev/tty
    response="${response:-$default}"

    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

check_dependencies() {
    local missing=()

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if ! command -v tar &> /dev/null; then
        missing+=("tar")
    fi

    if ! command -v sudo &> /dev/null; then
        missing+=("sudo")
    fi

    if ! command -v sha256sum &> /dev/null; then
        missing+=("sha256sum")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing[*]}"
        print_info "Please install them and run this script again."
        exit 1
    fi
}

check_systemctl() {
    if ! command -v systemctl &> /dev/null; then
        print_error "systemctl not found. Systemd is required for service setup."
        print_info "Skipping systemd service configuration."
        return 1
    fi
    return 0
}

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Install qbtcd and bifrost binaries from GitHub releases.

Options:
    -v, --version VERSION    Specify version to install (default: $DEFAULT_VERSION)
    -h, --help               Show this help message

Environment Variables:
    QBTC_VERSION             Alternative way to specify version

Examples:
    $(basename "$0")                     # Install default version interactively
    $(basename "$0") -v 1.0.8            # Install version 1.0.8
    QBTC_VERSION=1.0.8 $(basename "$0")  # Install version 1.0.8 via env var

EOF
}

# ========== ARGUMENT PARSING ==========

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--version)
                if [[ -z "$2" || "$2" == -* ]]; then
                    print_error "Option $1 requires a version argument"
                    show_help
                    exit 1
                fi
                VERSION="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Priority: CLI arg > env var > default
    if [[ -z "$VERSION" ]]; then
        VERSION="${QBTC_VERSION:-$DEFAULT_VERSION}"
    fi
}

# ========== INSTALLATION FUNCTIONS ==========

download_and_install_qbtcd() {
    print_header "Installing qbtcd"

    local archive="qbtcd-${VERSION}-${ARCH}.tar.gz"
    local url="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${archive}"
    local checksum_url="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/sha256sum.txt"
    local tmp_dir
    local expected_checksum

    tmp_dir=$(mktemp -d)

    print_info "Downloading qbtcd v${VERSION}..."
    if ! curl -fsSL "$url" -o "$tmp_dir/$archive"; then
        print_error "Failed to download qbtcd from $url"
        rm -rf "$tmp_dir"
        return 1
    fi

    print_info "Downloading checksum file..."
    if ! curl -fsSL "$checksum_url" -o "$tmp_dir/sha256sum.txt"; then
        print_error "Failed to download checksum file from $checksum_url"
        rm -rf "$tmp_dir"
        return 1
    fi

    print_info "Verifying checksum..."
    expected_checksum=$(grep "  ${archive}$" "$tmp_dir/sha256sum.txt" | awk '{print $1}')
    if [[ -z "$expected_checksum" ]]; then
        print_error "Checksum for $archive not found in sha256sum.txt"
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! (cd "$tmp_dir" && echo "$expected_checksum  $archive" | sha256sum -c --status); then
        print_error "Checksum verification failed for $archive"
        rm -rf "$tmp_dir"
        return 1
    fi
    print_success "Checksum verified"

    print_info "Extracting archive..."
    tar -xzf "$tmp_dir/$archive" -C "$tmp_dir"

    print_info "Installing qbtcd to ${INSTALL_DIR} (requires sudo)..."
    sudo install -m 755 "$tmp_dir/qbtcd" "$INSTALL_DIR/qbtcd"

    rm -rf "$tmp_dir"
    print_success "qbtcd installed successfully"
    INSTALLED_QBTCD=true
}

download_and_install_bifrost() {
    print_header "Installing bifrost"

    local archive="bifrost-${VERSION}-${ARCH}.tar.gz"
    local url="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${archive}"
    local checksum_url="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/sha256sum.txt"
    local tmp_dir
    local expected_checksum

    tmp_dir=$(mktemp -d)

    print_info "Downloading bifrost v${VERSION}..."
    if ! curl -fsSL "$url" -o "$tmp_dir/$archive"; then
        print_error "Failed to download bifrost from $url"
        rm -rf "$tmp_dir"
        return 1
    fi

    print_info "Downloading checksum file..."
    if ! curl -fsSL "$checksum_url" -o "$tmp_dir/sha256sum.txt"; then
        print_error "Failed to download checksum file from $checksum_url"
        rm -rf "$tmp_dir"
        return 1
    fi

    print_info "Verifying checksum..."
    expected_checksum=$(grep "  ${archive}$" "$tmp_dir/sha256sum.txt" | awk '{print $1}')
    if [[ -z "$expected_checksum" ]]; then
        print_error "Checksum for $archive not found in sha256sum.txt"
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! (cd "$tmp_dir" && echo "$expected_checksum  $archive" | sha256sum -c --status); then
        print_error "Checksum verification failed for $archive"
        rm -rf "$tmp_dir"
        return 1
    fi
    print_success "Checksum verified"

    print_info "Extracting archive..."
    tar -xzf "$tmp_dir/$archive" -C "$tmp_dir"

    print_info "Installing bifrost to ${INSTALL_DIR} (requires sudo)..."
    sudo install -m 755 "$tmp_dir/bifrost" "$INSTALL_DIR/bifrost"

    rm -rf "$tmp_dir"
    print_success "bifrost installed successfully"
    INSTALLED_BIFROST=true
}

download_and_install_cosmovisor() {
    print_header "Installing cosmovisor"

    local tmp_dir
    tmp_dir=$(mktemp -d)

    print_info "Downloading cosmovisor..."
    if ! curl -fsSL "$COSMOVISOR_URL" -o "$tmp_dir/cosmovisor.tar.gz"; then
        print_error "Failed to download cosmovisor from $COSMOVISOR_URL"
        rm -rf "$tmp_dir"
        return 1
    fi

    print_info "Extracting archive..."
    tar -xzf "$tmp_dir/cosmovisor.tar.gz" -C "$tmp_dir"

    print_info "Installing cosmovisor to ${INSTALL_DIR} (requires sudo)..."
    sudo install -m 755 "$tmp_dir/cosmovisor" "$INSTALL_DIR/cosmovisor"

    rm -rf "$tmp_dir"
    print_success "cosmovisor installed successfully"
    INSTALLED_COSMOVISOR=true
}

setup_cosmovisor_directories() {
    print_header "Setting up cosmovisor directory structure"

    local cosmovisor_dir="$QBTCD_HOME/cosmovisor"
    local genesis_bin_dir="$cosmovisor_dir/genesis/bin"

    print_info "Creating cosmovisor directories..."
    mkdir -p "$genesis_bin_dir"

    print_info "Copying qbtcd binary to cosmovisor genesis..."
    cp "$INSTALL_DIR/qbtcd" "$genesis_bin_dir/qbtcd"

    print_success "Cosmovisor directory structure created at $cosmovisor_dir"
}

setup_statesync() {
    print_header "Configuring statesync"

    if ! command -v jq &> /dev/null; then
        print_error "jq is required for statesync setup. Please install jq and try again."
        return 1
    fi

    local config_file="$QBTCD_HOME/config/config.toml"
    if [[ ! -f "$config_file" ]]; then
        print_error "config.toml not found at $config_file"
        return 1
    fi

    print_info "Querying latest block from $STATESYNC_RPC..."
    local latest_height
    latest_height=$(curl -s --connect-timeout 5 --max-time 10 "$STATESYNC_RPC/block" | jq -r .result.block.header.height)
    if [[ -z "$latest_height" || "$latest_height" == "null" ]]; then
        print_error "Failed to query latest block height from $STATESYNC_RPC"
        return 1
    fi

    if [[ "$latest_height" -le 2000 ]]; then
        print_error "Chain height ($latest_height) is too low for statesync (need > 2000)"
        return 1
    fi

    local trust_height=$((latest_height / 2000 * 2000))
    local trust_hash
    trust_hash=$(curl -s --connect-timeout 5 --max-time 10 "$STATESYNC_RPC/block?height=$trust_height" | jq -r .result.block_id.hash)
    if [[ -z "$trust_hash" || "$trust_hash" == "null" ]]; then
        print_error "Failed to query trust hash at height $trust_height"
        return 1
    fi

    print_info "Latest height: $latest_height"
    print_info "Trust height:  $trust_height"
    print_info "Trust hash:    $trust_hash"

    # Query the node ID for persistent_peers
    local node_id
    node_id=$(curl -s --connect-timeout 5 --max-time 10 "$STATESYNC_RPC/status" | jq -r .result.node_info.id)
    if [[ -z "$node_id" || "$node_id" == "null" ]]; then
        print_error "Failed to query node ID from $STATESYNC_RPC"
        return 1
    fi

    local rpc_host
    rpc_host=$(echo "$STATESYNC_RPC" | sed -E 's|^https?://||; s|:[0-9]+$||')
    local peer="${node_id}@${rpc_host}:26656"
    print_info "Persistent peer: $peer"

    print_info "Updating config.toml..."
    sed -i.bak -E \
        "s|^(enable[[:space:]]+=[[:space:]]+).*$|\1true|
         s|^(rpc_servers[[:space:]]+=[[:space:]]+).*$|\1\"${STATESYNC_RPC},${STATESYNC_RPC}\"|
         s|^(trust_height[[:space:]]+=[[:space:]]+).*$|\1${trust_height}|
         s|^(trust_hash[[:space:]]+=[[:space:]]+).*$|\1\"${trust_hash}\"|
         s|^(persistent_peers[[:space:]]+=[[:space:]]+).*$|\1\"${peer}\"|" "$config_file"
    rm -f "${config_file}.bak"

    print_success "Statesync configured"
}

init_qbtcd() {
    print_header "Initializing qbtcd"

    if [[ -d "$QBTCD_HOME" ]]; then
        print_info "Directory $QBTCD_HOME already exists."

        if ask_yn "Overwrite existing genesis and data?" "n"; then
            print_info "Running qbtcd init with overwrite..."
            qbtcd init qbtc-node --home "$QBTCD_HOME" --chain-id qbtc --overwrite
            qbtcd comet unsafe-reset-all --home "$QBTCD_HOME"
        else
            print_info "Skipping qbtcd initialization."
            return 1
        fi
    else
        print_info "Running qbtcd init..."
        qbtcd init qbtc-node --home "$QBTCD_HOME" --chain-id qbtc
    fi

    qbtcd config set client chain-id qbtc --home "$QBTCD_HOME"
    print_info "Downloading genesis.json..."
    if ! curl -fsSL "$GENESIS_URL" -o "$QBTCD_HOME/config/genesis.json"; then
        print_error "Failed to download genesis.json"
        return 1
    fi

    if ask_yn "Use statesync to bootstrap from the network?" "y"; then
        setup_statesync
    elif ask_yn "Download genesis.bin snapshot? (large file)" "n"; then
        print_info "Downloading genesis.bin (this may take a while)..."
        if ! curl -fL --progress-bar "$GENESIS_BIN_URL" -o "$QBTCD_HOME/config/genesis.bin"; then
            print_error "Failed to download genesis.bin"
            return 1
        fi
        print_success "genesis.bin downloaded"
    fi

    print_success "qbtcd initialized at $QBTCD_HOME"
}

create_bifrost_config() {
    print_header "Creating bifrost configuration"

    if [[ -d "$BIFROST_HOME" ]]; then
        print_info "Directory $BIFROST_HOME already exists."
        if ! ask_yn "Delete existing directory and recreate?" "n"; then
            print_info "Skipping bifrost config creation."
            return 0
        fi
        rm -rf "$BIFROST_HOME"
    fi

    print_info "Creating bifrost directories..."
    mkdir -p "$BIFROST_HOME/db"

    print_info "Creating config template..."
    cat > "$BIFROST_HOME/config.json" << EOF
{
  "listen_addr": "0.0.0.0:30006",
  "http_listen_addr": "0.0.0.0:30007",
  "external_ip": "",
  "root_path": "$HOME/.bifrost/",
  "key_name": "bifrost-p2p-key",
  "start_block_height": 0,
  "bitcoin": {
    "host": "127.0.0.1",
    "port": 8332,
    "rpc_user": "bitcoinrpc",
    "password": "securepassword",
    "local_db_path": "$HOME/.bifrost/db"
  },
  "qbtc_home": "$HOME/.qbtc",
  "ebifrost_address": "localhost:50051",
  "qbtc_grpc_address": "localhost:9090",
  "cometbft_rpc_address": "http://localhost:26657",
  "backoff_time_in_minutes": 1
}
EOF

    chmod 600 "$BIFROST_HOME/config.json"
    print_success "Bifrost config template created at $BIFROST_HOME/config.json"
}

# ========== SYSTEMD FUNCTIONS ==========

setup_qbtcd_systemd() {
    print_header "Setting up qbtcd systemd service"

    local service_file="/etc/systemd/system/qbtcd.service"
    local service_user
    local service_group
    service_user=$(whoami)
    service_group=$(id -gn "$service_user" 2>/dev/null)
    if [[ -z "$service_group" ]]; then
        print_error "Failed to resolve primary group for '$service_user'"
        return 1
    fi

    print_info "Using user: $service_user, group: $service_group"
    print_info "Creating systemd service file..."

    if $USE_COSMOVISOR; then
        print_info "Using cosmovisor to manage qbtcd..."
        sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=QBTC Daemon (via Cosmovisor)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${service_user}
Group=${service_group}
ExecStart=${INSTALL_DIR}/cosmovisor run start --home ${QBTCD_HOME}
Restart=always
RestartSec=10
LimitNOFILE=65535
Environment="DAEMON_NAME=qbtcd"
Environment="DAEMON_HOME=${QBTCD_HOME}"
Environment="DAEMON_ALLOW_DOWNLOAD_BINARIES=false"
Environment="DAEMON_RESTART_AFTER_UPGRADE=true"
Environment="UNSAFE_SKIP_BACKUP=true"

[Install]
WantedBy=multi-user.target
EOF
    else
        sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=QBTC Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${service_user}
Group=${service_group}
ExecStart=${INSTALL_DIR}/qbtcd start --home ${QBTCD_HOME}
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    fi

    print_info "Reloading systemd daemon..."
    sudo systemctl daemon-reload

    print_info "Enabling qbtcd service..."
    sudo systemctl enable qbtcd

    print_success "qbtcd systemd service created and enabled"
    SETUP_QBTCD_SERVICE=true
}

setup_bifrost_systemd() {
    print_header "Setting up bifrost systemd service"

    local service_file="/etc/systemd/system/bifrost.service"
    local service_user
    local service_group
    service_user=$(whoami)
    service_group=$(id -gn "$service_user" 2>/dev/null)
    if [[ -z "$service_group" ]]; then
        print_error "Failed to resolve primary group for '$service_user'"
        return 1
    fi

    print_info "Using user: $service_user, group: $service_group"
    print_info "Creating systemd service file..."

    sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=Bifrost Service

[Service]
Type=simple
User=${service_user}
Group=${service_group}
ExecStart=${INSTALL_DIR}/bifrost start --config ${BIFROST_HOME}/config.json
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    print_info "Reloading systemd daemon..."
    sudo systemctl daemon-reload

    print_info "Enabling bifrost service..."
    sudo systemctl enable bifrost

    print_success "bifrost systemd service created and enabled"
    SETUP_BIFROST_SERVICE=true
}

# ========== SUMMARY ==========

print_summary() {
    print_header "Installation Summary"

    echo "Installed binaries:"
    if $INSTALLED_QBTCD; then
        echo "  - qbtcd v${VERSION} -> ${INSTALL_DIR}/qbtcd"
    fi
    if $INSTALLED_COSMOVISOR; then
        echo "  - cosmovisor -> ${INSTALL_DIR}/cosmovisor"
    fi
    if $INSTALLED_BIFROST; then
        echo "  - bifrost v${VERSION} -> ${INSTALL_DIR}/bifrost"
    fi

    echo ""
    echo "Directories:"
    if [[ -d "$QBTCD_HOME" ]]; then
        echo "  - qbtcd home: $QBTCD_HOME"
    fi
    if [[ -d "$BIFROST_HOME" ]]; then
        echo "  - bifrost home: $BIFROST_HOME"
        echo "  - bifrost config: $BIFROST_HOME/config.json"
    fi

    if $SETUP_QBTCD_SERVICE || $SETUP_BIFROST_SERVICE; then
        echo ""
        echo "Systemd services:"
        if $SETUP_QBTCD_SERVICE; then
            if $USE_COSMOVISOR; then
                echo "  - qbtcd.service (user: $(whoami), via cosmovisor)"
            else
                echo "  - qbtcd.service (user: $(whoami))"
            fi
        fi
        if $SETUP_BIFROST_SERVICE; then
            echo "  - bifrost.service (user: $(whoami))"
        fi
    fi

    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    local step=1

    if [[ -d "$BIFROST_HOME" ]]; then
        echo "  ${step}. Edit bifrost config: vim $BIFROST_HOME/config.json"
        echo "     - Update Bitcoin RPC settings if not using localhost:8332 with user/password"
        echo "     - Set external_ip if running a public node"
        ((step++))
    fi

    if $SETUP_QBTCD_SERVICE || $SETUP_BIFROST_SERVICE; then
        if $SETUP_QBTCD_SERVICE; then
            echo "  ${step}. Start qbtcd: sudo systemctl start qbtcd"
            ((step++))
        fi
        if $SETUP_BIFROST_SERVICE; then
            echo "  ${step}. Start bifrost: sudo systemctl start bifrost"
            ((step++))
        fi
        echo ""
        echo "Service management commands:"
        echo "  sudo systemctl status qbtcd bifrost    # Check status"
        echo "  sudo journalctl -u qbtcd -f            # View qbtcd logs"
        echo "  sudo journalctl -u bifrost -f          # View bifrost logs"
    else
        echo "  ${step}. Start qbtcd: qbtcd start --home $QBTCD_HOME"
        ((step++))
        echo "  ${step}. Start bifrost: bifrost start --config $BIFROST_HOME/config.json"
    fi

    echo ""
    if $INSTALLED_QBTCD || $INSTALLED_BIFROST; then
        echo "Verify installation:"
        if $INSTALLED_QBTCD; then
            echo "  qbtcd version"
        fi
        if $INSTALLED_BIFROST; then
            echo "  bifrost --version"
        fi
    fi
}

# ========== MAIN ==========

main() {
    parse_args "$@"

    print_header "QBTC Installation Script"
    print_info "Version: ${VERSION}"
    print_info "Architecture: ${ARCH}"
    echo ""

    check_dependencies

    # Install qbtcd
    if ask_yn "Install qbtcd?" "y"; then
        download_and_install_qbtcd
    else
        print_info "Skipping qbtcd installation."
    fi

    # Install cosmovisor (for chain upgrades)
    if $INSTALLED_QBTCD; then
        if ask_yn "Install cosmovisor? (manages chain upgrades)" "y"; then
            download_and_install_cosmovisor
            USE_COSMOVISOR=true
        fi
    fi

    # Install bifrost
    if ask_yn "Install bifrost?" "y"; then
        download_and_install_bifrost
    else
        print_info "Skipping bifrost installation."
    fi

    # Initialize qbtcd config
    if $INSTALLED_QBTCD; then
        if ask_yn "Initialize qbtcd config?" "y"; then
            init_qbtcd

            # Setup cosmovisor directories after qbtcd init
            if $USE_COSMOVISOR; then
                setup_cosmovisor_directories
            fi
        fi
    fi

    # Create bifrost config template
    if $INSTALLED_BIFROST; then
        if ask_yn "Create bifrost config template?" "y"; then
            create_bifrost_config
        fi
    fi

    # Setup systemd services
    if $INSTALLED_QBTCD || $INSTALLED_BIFROST; then
        if check_systemctl && ask_yn "Setup systemd services?" "y"; then
            if $INSTALLED_QBTCD; then
                if ask_yn "Create qbtcd systemd service?" "y"; then
                    setup_qbtcd_systemd
                fi
            fi

            if $INSTALLED_BIFROST; then
                if ask_yn "Create bifrost systemd service?" "y"; then
                    setup_bifrost_systemd
                fi
            fi
        fi
    fi

    print_summary
}

main "$@"
