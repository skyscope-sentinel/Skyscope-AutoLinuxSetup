#!/bin/bash

# Set up logging
LOG_FILE="/root/install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Exit on error
set -e

# Colors for output
GREEN='\033[1;32m'
NC='\033[0m'

echo -e "${GREEN}"
echo "Skyscope Sentinel Intelligence - Installation Script v1.0"
echo "Setting up a secure Debian 13 environment..."
echo -e "${NC}"

# *** Hardware Detection ***
echo "Detecting hardware..."

# Motherboard
MOTHERBOARD=$(dmidecode -t baseboard | grep "Product Name" | awk -F: '{print $2}' | tr -d ' ')
if ! echo "$MOTHERBOARD" | grep -q "B760M-H-DDR4"; then
    echo "Error: Motherboard not recognized! Expected B760M-H-DDR4, got $MOTHERBOARD"
    exit 1
fi

# CPU
CPU_MODEL=$(lscpu | grep "Model name" | awk -F: '{print $2}' | tr -d ' ')
if ! echo "$CPU_MODEL" | grep -q "i7-12700"; then
    echo "Error: CPU model mismatch! Expected i7-12700, got $CPU_MODEL"
    exit 1
fi

# RAM
TOTAL_RAM=$(dmidecode -t memory | grep "Size:" | awk '{sum += $2} END {print sum}')
if [ "$TOTAL_RAM" -lt 32768 ]; then
    echo "Error: Insufficient RAM! Expected at least 32GB, got $TOTAL_RAM MB"
    exit 1
fi

# Storage
if ! lsblk -d -o TRAN,SIZE | grep -q "nvme 1T" || ! lsblk -d -o TRAN,SIZE | grep -q "sata 1T" || ! lsblk -d -o TRAN,SIZE | grep -q "sata 2T"; then
    echo "Error: Required storage devices not found (1TB NVMe, 1TB SSD, 2TB SSD)!"
    exit 1
fi

# GPU
GPU_MODEL=$(lspci | grep VGA | awk -F: '{print $3}' | tr -d ' ')
if ! echo "$GPU_MODEL" | grep -q "GeForce970"; then
    echo "Error: GPU model mismatch! Expected GeForce 970, got $GPU_MODEL"
    exit 1
fi

echo "Hardware detection successful."

# *** Fetch Debian 13 Weekly ISO ***
echo "Fetching latest Debian 13 weekly ISO..."
ISO_PAGE="https://cdimage.debian.org/cdimage/weekly-builds/amd64/iso-dvd/"
ISO_FILE=$(curl -s "$ISO_PAGE" | grep -oP 'href="K(debian-testing-amd64-DVD-1\.iso)"' | sed 's/href="//; s/"//' | head -1)
ISO_URL="${ISO_PAGE}${ISO_FILE}"

if [ -z "$ISO_FILE" ]; then
    echo "Error: Failed to find the ISO file."
    exit 1
fi

wget -O /tmp/debian.iso "$ISO_URL" || {
    echo "Error: Failed to download ISO."
    exit 1
}

# *** Prompt for Encryption Password ***
echo "Please enter the encryption password for full disk encryption:"
read -s ENCRYPTION_PASSWORD
echo "Confirm password:"
read -s ENCRYPTION_PASSWORD_CONFIRM
if [ "$ENCRYPTION_PASSWORD" != "$ENCRYPTION_PASSWORD_CONFIRM" ]; then
    echo "Error: Passwords do not match!"
    exit 1
fi

# *** Prompt for User Password ***
echo "Please enter the password for user 'ssi':"
read -s USER_PASSWORD
echo "Confirm password:"
read -s USER_PASSWORD_CONFIRM
if [ "$USER_PASSWORD" != "$USER_PASSWORD_CONFIRM" ]; then
    echo "Error: Passwords do not match!"
    exit 1
fi
HASHED_PASSWORD=$(mkpasswd -m sha-512 "$USER_PASSWORD")

# *** Create Autoinstall Configuration ***
TARGET_DISK="/dev/nvme0n1"  # Using NVMe as the target disk
cat <<EOF > /tmp/autoinstall.yaml
version: 1
storage:
  config:
    - type: disk
      id: disk0
      path: $TARGET_DISK
      ptable: gpt
      wipe: superblock
    - type: partition
      id: efi-part
      device: disk0
      size: 512M
      flag: boot
    - type: format
      id: efi-format
      volume: efi-part
      fstype: fat32
    - type: mount
      id: efi-mount
      device: efi-format
      path: /boot/efi
    - type: partition
      id: root-part
      device: disk0
      size: -1
    - type: luks
      id: root-luks
      device: root-part
      name: root
      key: $ENCRYPTION_PASSWORD
    - type: format
      id: root-format
      volume: root-luks
      fstype: ext4
    - type: mount
      id: root-mount
      device: root-format
      path: /
packages:
  - task-gnome-desktop
  - gnome-boxes
  - kexec-tools
  - sbctl
  - ufw
user-data:
  hostname: skyscope
  users:
    - name: ssi
      lock_passwd: false
      passwd: '$HASHED_PASSWORD'
      shell: /bin/bash
      sudo: ALL=(ALL) NOPASSWD:ALL
late-commands:
  - curl -o /target/root/post-install.sh http://localhost:8000/post-install.sh
  - chroot /target chmod +x /root/post-install.sh
  - chroot /target bash -c "echo -e '[Unit]\nDescription=Post Install Script\nAfter=network.target\n[Service]\nType=oneshot\nExecStart=/root/post-install.sh\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/post-install.service"
  - chroot /target systemctl enable post-install.service
EOF

# *** Create Post-Install Script ***
cat <<'EOF' > /tmp/post-install.sh
#!/bin/bash

# Log file
LOG_FILE="/root/post-install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Update system
apt update && apt upgrade -y

# Configure firewall
ufw default deny incoming
ufw allow 22/tcp  # SSH
ufw enable

# Secure SSH
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Generate secure boot keys (user must enroll manually)
sbctl create-keys
sbctl sign -s /boot/efi/EFI/debian/grubx64.efi
echo "Secure Boot keys generated. Please reboot into BIOS to enroll keys with 'sbctl enroll-keys'."

# Install additional packages from template
apt install -y git cmake libssl-dev cryptsetup grub-efi-amd64 python3-pip

# Install quantum libraries (simplified from template)
pip3 install numpy qiskit pennylane

# Configure GRUB (basic customization)
cat <<EOC > /etc/default/grub
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="Skyscope Sentinel Intelligence"
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_GFXMODE=1920x1080
EOC
update-grub

# Clean up
systemctl disable post-install.service
rm /etc/systemd/system/post-install.service
rm /root/post-install.sh

echo "Post-installation complete. System will reboot."
reboot
EOF

# *** Start Web Server ***
cd /tmp
python3 -m http.server 8000 &
WEB_SERVER_PID=$!

# *** Extract Kernel and Initrd from ISO ***
mkdir -p /tmp/iso
mount -o loop /tmp/debian.iso /tmp/iso || {
    echo "Error: Failed to mount ISO."
    exit 1
}
cp /tmp/iso/install/vmlinuz /tmp/vmlinuz
cp /tmp/iso/install/initrd.gz /tmp/initrd.gz
umount /tmp/iso

# *** Install kexec-tools if not present ***
apt update
apt install -y kexec-tools

# *** Boot into Installer with kexec ***
kexec -l /tmp/vmlinuz --initrd=/tmp/initrd.gz --append="auto=true priority=critical url=http://localhost:8000/autoinstall.yaml" || {
    echo "Error: Failed to load kernel with kexec."
    exit 1
}
kill $WEB_SERVER_PID
echo "Starting installation. System will reboot into the new OS after completion."
kexec -e
