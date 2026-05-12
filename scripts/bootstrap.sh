#!/usr/bin/env bash
# =============================================================
# UAV CTI Defense Lab — Host Bootstrap Script
# Installs: KVM, Vagrant, Ansible, Docker, prerequisites
#
# Citation [23]: Hevner et al. (2004) Design Science in IS Research
#                MIS Quarterly 28(1). doi:10.2307/25148625
# =============================================================
set -euo pipefail
LOG="/var/log/uav-cti-bootstrap.log"
exec > >(tee -a "$LOG") 2>&1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root: sudo bash scripts/bootstrap.sh"
[[ -f /etc/os-release ]] && source /etc/os-release
[[ "$ID" == "ubuntu" ]] || warn "Tested on Ubuntu 22.04; proceeding anyway"

info "=== UAV CTI Lab Bootstrap ==="
info "Host: $(hostname) | OS: ${PRETTY_NAME:-unknown}"

# ── 1. System update ────────────────────────────────────────
info "Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

# ── 2. KVM / libvirt ────────────────────────────────────────
info "Installing KVM virtualisation stack..."
apt-get install -y -qq \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    bridge-utils virtinst virt-manager \
    cpu-checker

# Verify hardware virtualisation
if kvm-ok &>/dev/null; then
    info "KVM hardware acceleration: OK"
else
    warn "KVM hardware acceleration not available — VMs will run in software mode"
fi

usermod -aG libvirt "$SUDO_USER" 2>/dev/null || true
systemctl enable --now libvirtd

# ── 3. Vagrant ──────────────────────────────────────────────
info "Installing Vagrant 2.4..."
VAGRANT_VER="2.4.1"
VAGRANT_DEB="vagrant_${VAGRANT_VER}-1_amd64.deb"
wget -q "https://releases.hashicorp.com/vagrant/${VAGRANT_VER}/${VAGRANT_DEB}" -O "/tmp/${VAGRANT_DEB}"
dpkg -i "/tmp/${VAGRANT_DEB}"
vagrant plugin install vagrant-libvirt 2>/dev/null || true
info "Vagrant version: $(vagrant --version)"

# ── 4. Ansible ──────────────────────────────────────────────
info "Installing Ansible..."
apt-get install -y -qq software-properties-common
add-apt-repository -y ppa:ansible/ansible
apt-get update -qq
apt-get install -y -qq ansible
info "Ansible version: $(ansible --version | head -1)"

# ── 5. Docker Engine ────────────────────────────────────────
info "Installing Docker Engine..."
apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
apt-get install -y -qq \
    ca-certificates curl gnupg lsb-release

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
    tee /etc/apt/sources.list.d/docker.list >/dev/null

apt-get update -qq
apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

usermod -aG docker "$SUDO_USER" 2>/dev/null || true
systemctl enable --now docker
info "Docker version: $(docker --version)"

# ── 6. Supporting tools ─────────────────────────────────────
info "Installing supporting tools..."
apt-get install -y -qq \
    git curl wget jq python3 python3-pip python3-venv \
    net-tools nmap wireshark-common tcpdump \
    build-essential pkg-config openssl libssl-dev \
    iproute2 iptables ipset

# Python packages for CTI scripts
python3 -m pip install --break-system-packages \
    requests pymavlink pymisp thehive4py \
    stix2 taxii2-client elasticsearch \
    pyyaml click rich schedule 2>/dev/null || \
python3 -m pip install \
    requests pymavlink pymisp thehive4py \
    stix2 taxii2-client elasticsearch \
    pyyaml click rich schedule

# ── 7. Lab network bridge ────────────────────────────────────
info "Configuring isolated lab network bridge..."
cat > /etc/netplan/99-uav-lab-bridge.yaml <<'NETPLAN'
network:
  version: 2
  bridges:
    uav-lab-br:
      dhcp4: false
      addresses: [192.168.100.1/24]
      parameters:
        stp: false
        forward-delay: 0
NETPLAN
netplan apply 2>/dev/null || warn "Netplan apply failed — reboot may be required"

# ── 8. Kernel tuning for SIEM ────────────────────────────────
info "Applying kernel parameters for Elasticsearch..."
cat >> /etc/sysctl.conf <<'EOF'
# UAV CTI Lab — Elasticsearch requirements
vm.max_map_count=262144
vm.swappiness=1
net.ipv4.tcp_retries2=5
EOF
sysctl -p

# ── 9. Create Python virtual environment for lab scripts ─────
info "Creating Python virtual environment..."
LAB_DIR="$(dirname "$(realpath "$0")")/.."
python3 -m venv "$LAB_DIR/.venv"
"$LAB_DIR/.venv/bin/pip" install --quiet \
    requests pymavlink stix2 taxii2-client \
    pymisp elasticsearch pyyaml \
    click rich schedule

info ""
info "=== Bootstrap Complete ==="
info "Next steps:"
info "  1. cp .env.example .env && nano .env   # change passwords"
info "  2. vagrant up                           # start lab VMs"
info "  3. cd docker && docker compose -f stacks/cti.yml -f stacks/monitor.yml -f stacks/uav.yml up -d"
info ""
warn "Log out and back in for group membership (docker, libvirt) to take effect."
