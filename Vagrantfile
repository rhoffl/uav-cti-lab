# =============================================================
# UAV CTI Defense Lab — Vagrantfile
# Dissertation: "Leveraging CTI to Defend UAVs Against Cyber Attacks"
#
# Citations:
#  [6]  Rodday et al. (2016) MAVLink vulnerabilities. IEEE NOMS 2016.
#  [8]  Yaacoub et al. (2020) UAV security survey. IoT Journal 11.
#  [10] Strom et al. (2018) MITRE ATT&CK. MITRE MTR180035.
#  [11] OASIS (2021) STIX 2.1 Standard.
# =============================================================
Vagrant.configure("2") do |config|

  config.vm.box_check_update = false
  config.ssh.insert_key       = false

  # Helper: configure libvirt provider
  def libvirt_cfg(v, cpus:, mem:)
    v.driver         = "kvm"
    v.cpus           = cpus
    v.memory         = mem
    v.disk_bus       = "virtio"
    v.nic_model_type = "virtio"
    v.graphics_type  = "none"
  end

  # Helper: attach Ansible provisioner
  def ansible_prov(vm, playbook)
    vm.vm.provision "ansible" do |a|
      a.playbook       = "ansible/playbooks/#{playbook}.yml"
      a.inventory_path = "ansible/inventories/lab.ini"
      a.become         = true
    end
  end

  # ── GCS Linux (Ubuntu) — 192.168.100.11 ──────────────────────
  # Ground Control Station: MAVProxy + DroneKit-Python [6]
  # Represents the operator-side system targeted by GCS malware
  config.vm.define "gcs-linux" do |vm|
    vm.vm.box      = "ubuntu/jammy64"
    vm.vm.hostname = "gcs-linux"
    vm.vm.network "private_network",
                  ip: "192.168.100.11",
                  libvirt__network_name: "uav-lab"
    vm.vm.provider("libvirt") { |v| libvirt_cfg(v, cpus: 2, mem: 4096) }
    ansible_prov(vm, "gcs-linux")
  end

  # ── IDS / NSM Monitor — 192.168.100.30 ───────────────────────
  # Network Security Monitoring: Suricata 6.x + Zeek 5.x + Arkime
  # Primary detection node; receives mirrored copy of all lab traffic
  config.vm.define "ids-monitor" do |vm|
    vm.vm.box      = "ubuntu/jammy64"
    vm.vm.hostname = "ids-monitor"
    vm.vm.network "private_network",
                  ip: "192.168.100.30",
                  libvirt__network_name: "uav-lab"
    # Second NIC on mirror VLAN (promiscuous — receives all lab traffic)
    vm.vm.network "private_network",
                  ip: "192.168.200.30",
                  libvirt__network_name: "uav-mirror",
                  libvirt__promisc: true
    vm.vm.provider("libvirt") { |v| libvirt_cfg(v, cpus: 4, mem: 8192) }
    ansible_prov(vm, "ids-monitor")
  end

  # ── SIEM — 192.168.100.40 ────────────────────────────────────
  # Elasticsearch 8.12 + Kibana + Logstash
  # Implements 23 custom UAV KQL detection rules
  config.vm.define "siem" do |vm|
    vm.vm.box      = "ubuntu/jammy64"
    vm.vm.hostname = "siem"
    vm.vm.network "private_network",
                  ip: "192.168.100.40",
                  libvirt__network_name: "uav-lab"
    vm.vm.provider("libvirt") { |v| libvirt_cfg(v, cpus: 4, mem: 16384) }
    ansible_prov(vm, "siem")
  end

  # ── CTI Platform — 192.168.100.50 ────────────────────────────
  # OpenCTI 5.12 + MISP 2.4 + TheHive 5 + Cortex 3
  # Implements STIX 2.1 / TAXII [11] with UAV-specific extensions
  config.vm.define "cti-platform" do |vm|
    vm.vm.box      = "ubuntu/jammy64"
    vm.vm.hostname = "cti-platform"
    vm.vm.network "private_network",
                  ip: "192.168.100.50",
                  libvirt__network_name: "uav-lab"
    vm.vm.provider("libvirt") { |v| libvirt_cfg(v, cpus: 4, mem: 16384) }
    ansible_prov(vm, "cti-platform")
  end

  # ── UAV Simulator — 192.168.100.60 ───────────────────────────
  # ArduPilot SITL + Gazebo 11 + MAVLink Router
  # Emulates a real UAV flight controller over UDP/14550 [6]
  config.vm.define "uav-sim" do |vm|
    vm.vm.box      = "ubuntu/jammy64"
    vm.vm.hostname = "uav-sim"
    vm.vm.network "private_network",
                  ip: "192.168.100.60",
                  libvirt__network_name: "uav-lab"
    vm.vm.provider("libvirt") { |v| libvirt_cfg(v, cpus: 4, mem: 8192) }
    ansible_prov(vm, "uav-sim")
  end

  # ── Malware Sandbox — 192.168.200.70 (ISOLATED) ──────────────
  # Cuckoo Sandbox — intentionally on a separate segment
  # No routing to the primary lab network for safety isolation
  config.vm.define "sandbox" do |vm|
    vm.vm.box      = "ubuntu/jammy64"
    vm.vm.hostname = "sandbox"
    vm.vm.network "private_network",
                  ip: "192.168.200.70",
                  libvirt__network_name: "uav-sandbox"
    vm.vm.provider("libvirt") { |v| libvirt_cfg(v, cpus: 2, mem: 4096) }
    vm.vm.provision "shell", path: "vagrant/provision/sandbox.sh"
  end

end
