#!/bin/bash

# Set up terminal colors
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Display header
clear
echo -e "${GREEN}"
echo "Skyscope Sentinel Intelligence - Quantum Hybrid Netinst OS Installation Script v1.1 2025. MIT"
echo "Developer: Miss Casey Jay Topojani"
echo "GitHub: skyscope-sentinel"
echo -e "${NC}"
echo "Building Skyscope Sentinel Intelligence Quantum Hybrid Netinst OS..."

# Variables
OS_NAME="Skyscope Sentinel Intelligence Quantum Hybrid OS"
USERNAME="ssi"
ROOT_PASSWORD="quantum2025"  # Temporary, user will set encryption password
LOG_FILE="/root/skyscope_netinst_install_$(date +%F_%T).log"
ISO_URL="https://cdimage.debian.org/cdimage/weekly-builds/amd64/iso-cd/debian-testing-amd64-netinst.iso"
ISO_FILE="/tmp/debian-testing-amd64-netinst.iso"
ISO_MOUNT="/mnt/iso"
NEW_ISO="/root/skyscope_sentinel_quantum_hybrid_netinst.iso"
WORKDIR="/root/workdir"
SQUASHFS_ROOT="$WORKDIR/squashfs-root"
INITRD_DIR="$WORKDIR/initrd"
OQS_PREFIX="/usr/local"
ANACONDA_PATH="/opt/anaconda3"
LOGO_URL="https://raw.githubusercontent.com/skyscope-sentinel/SecureLinux/plasmoid_ob.png"
LOGO_PATH="/boot/grub/plasmoid_orb.png"
EFI_DIR="$WORKDIR/efi"
BOOTLOADER_PASSWORD="quantum2025"  # Change post-install
CPU_CORES=$(nproc)
NETWORK_DEVICE=$(ip link | grep -oP '^[0-9]+: \K(en[^:]+)' | head -1 || echo "eth0")
GRUB_CFG="/etc/grub.d/40_custom"
SSD_QUANTUM="/quantum-swap"
SSD_HYBRID="/quantum-buffer"
SSD_QUANTUM_CACHE="/quantum-cache"
SSD_QUANTUM_OPT="/quantum-optimization"
GPG_KEY_URL="https://ftp-master.debian.org/keys/release-13.asc"

# Hardware specifications
MOTHERBOARD="Gigabyte B760M-H-DDR4 v1.0"
RAM="32GB DDR4 3200MHz"
NVME_DEV="/dev/nvme0n1"
SSD1_DEV="/dev/sda"  # 1TB SSD
SSD2_DEV="/dev/sdb"  # 2TB SSD
CPU="Intel i7-12700"
GPU="ASUS Strix GeForce 970 4GB"

# Function to log messages
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

# Function to handle errors with retry and alternative method
handle_error() {
    local step="$1"
    local error_msg="$2"
    local primary_cmd="$3"
    local alt_cmd="$4"
    local max_retries=3
    local retry_count=0
    log_message "ERROR: $step failed - $error_msg"
    while [ $retry_count -lt $max_retries ]; do
        log_message "Attempting $step (Primary, Attempt $((retry_count + 1))/$max_retries)..."
        if eval "$primary_cmd" 2>> "$LOG_FILE"; then
            log_message "$step succeeded on primary attempt $((retry_count + 1))."
            return 0
        fi
        retry_count=$((retry_count + 1))
        sleep 5
    done
    if [ -n "$alt_cmd" ]; then
        log_message "Primary method failed. Trying alternative method for $step..."
        retry_count=0
        while [ $retry_count -lt $max_retries ]; do
            log_message "Attempting $step (Alternative, Attempt $((retry_count + 1))/$max_retries)..."
            if eval "$alt_cmd" 2>> "$LOG_FILE"; then
                log_message "$step succeeded on alternative attempt $((retry_count + 1))."
                return 0
            fi
            retry_count=$((retry_count + 1))
            sleep 5
        done
    fi
    log_message "CRITICAL: $step failed after all retries. Exiting..."
    exit 1
}

# Trap errors
trap 'handle_error "${BASH_SOURCE}:${LINENO}" "Command failed" "" ""' ERR

# Initialize log file
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"
log_message "Starting Skyscope Sentinel Intelligence Quantum Hybrid Netinst OS installation process..."

# Step 1: Install all prerequisites
log_message "Installing all prerequisites..."
handle_error "Install prerequisites" "Failed to install prerequisite packages" \
"apt update && apt install -y build-essential git cmake libssl-dev libjson-c-dev libargon2-dev libdevmapper-dev uuid-dev pkg-config cryptsetup lvm2 btrfs-progs grub-efi-amd64 rustc python3-pip python3-dev libcurl4-openssl-dev libopenblas-dev ninja-build curl wget xorriso squashfs-tools genisoimage secureboot-db shim-signed gnupg2 dirmngr debootstrap cpio" \
"apt update && apt install -y --no-install-recommends build-essential git cmake libssl-dev libjson-c-dev libargon2-dev libdevmapper-dev uuid-dev pkg-config cryptsetup lvm2 btrfs-progs grub-efi-amd64 rustc python3-pip python3-dev libcurl4-openssl-dev libopenblas-dev ninja-build curl wget xorriso squashfs-tools genisoimage secureboot-db shim-signed gnupg2 dirmngr debootstrap cpio"

# Create Python requirements file for CPU-only packages
log_message "Creating Python requirements file..."
cat <<EOC > /tmp/requirements.txt
numpy==1.26.4
ollama==0.1.7
qiskit==1.2.0
cirq-core==1.4.0
qsimcirq==0.21.0
pennylane==0.38.0
lambeq==0.4.3
discopy==0.7.1
torch==2.4.0+cpu
EOC

# Install Python packages
handle_error "Install Python packages" "Failed to install Python packages" \
"pip3 install --no-cache-dir -r /tmp/requirements.txt" \
"pip3 install --no-cache-dir --no-deps -r /tmp/requirements.txt"

# Step 2: Download and verify Debian netinst ISO
log_message "Downloading Debian 13 weekly netinst ISO..."
handle_error "Download Debian ISO" "Failed to download ISO" \
"curl -L '$ISO_URL' -o '$ISO_FILE'" \
"wget '$ISO_URL' -O '$ISO_FILE'"

# Download and verify checksum
log_message "Verifying ISO integrity..."
handle_error "Download checksum" "Failed to download checksum" \
"curl -L '${ISO_URL}.sha256' -o /tmp/iso.sha256" \
"wget '${ISO_URL}.sha256' -O /tmp/iso.sha256"
handle_error "Verify ISO checksum" "Failed to verify ISO checksum" \
"sha256sum -c /tmp/iso.sha256" \
"sha256sum -c /tmp/iso.sha256 --ignore-missing"

# Import Debian GPG key and verify signature
log_message "Verifying ISO signature..."
handle_error "Import GPG key" "Failed to import Debian GPG key" \
"curl -L '$GPG_KEY_URL' | gpg --import" \
"wget '$GPG_KEY_URL' -O /tmp/release-13.asc && gpg --import /tmp/release-13.asc"
handle_error "Download and verify signature" "Failed to verify ISO signature" \
"curl -L '${ISO_URL}.sign' -o /tmp/iso.sign && gpg --verify /tmp/iso.sign '$ISO_FILE'" \
"wget '${ISO_URL}.sign' -O /tmp/iso.sign && gpg --verify /tmp/iso.sign '$ISO_FILE'"

# Step 3: Mount and extract ISO
log_message "Mounting and extracting ISO..."
mkdir -p "$ISO_MOUNT" "$WORKDIR"
handle_error "Mount ISO" "Failed to mount ISO" \
"mount -o loop '$ISO_FILE' '$ISO_MOUNT'" \
"mount -o loop,ro '$ISO_FILE' '$ISO_MOUNT'"
rsync -a "$ISO_MOUNT/" "$WORKDIR/"
umount "$ISO_MOUNT"
rmdir "$ISO_MOUNT"

# Step 4: Extract and modify initrd for netboot
log_message "Extracting and modifying initrd..."
mkdir -p "$INITRD_DIR"
cd "$WORKDIR"
handle_error "Extract initrd" "Failed to extract initrd" \
"zcat install.amd/initrd.gz | cpio -idmv -D '$INITRD_DIR'" \
"gunzip -c install.amd/initrd.gz | cpio -idmv -D '$INITRD_DIR'"

# Add post-quantum cryptsetup support to initrd
log_message "Adding post-quantum cryptsetup to initrd..."
cd "$INITRD_DIR"
cat <<EOC > lib/cryptsetup/kyber.sh
#!/bin/sh
modprobe kyber
/lib/cryptsetup/askpass "Enter passphrase for Kyber-1024 encryption: "
EOC
chmod +x lib/cryptsetup/kyber.sh
handle_error "Rebuild initrd" "Failed to rebuild initrd" \
"find . | cpio -H newc -o | gzip -9 > '$WORKDIR/install.amd/initrd.gz'" \
"find . | cpio -H newc -o | gzip -9 > '$WORKDIR/install.amd/initrd.gz'"

# Step 5: Chroot into extracted ISO for customization
log_message "Setting up chroot environment..."
mkdir -p "$SQUASHFS_ROOT"
debootstrap --arch=amd64 testing "$SQUASHFS_ROOT" http://deb.debian.org/debian
for dir in dev proc sys run; do
    mount --bind "/$dir" "$SQUASHFS_ROOT/$dir"
done
cp /etc/resolv.conf "$SQUASHFS_ROOT/etc/"

# Step 6: Customize OS name and hostname
log_message "Customizing OS name..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    sed -i 's/.*PRETTY_NAME.*/PRETTY_NAME=\"$OS_NAME\"/' /etc/os-release
    hostnamectl set-hostname skyscope-quantum
"

# Step 7: Install liboqs and oqs-provider
log_message "Installing liboqs..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    apt update
    apt install -y git cmake ninja-build libssl-dev
    git clone --branch main https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
    cd /tmp/liboqs
    mkdir build
    cd build
    cmake -GNinja -DOQS_ALGS_ENABLE_KEM_KYBER=ON -DCMAKE_INSTALL_PREFIX='$OQS_PREFIX' ..
    ninja
    ninja install
    cd /tmp
    rm -rf liboqs
"

log_message "Installing oqs-provider..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    git clone --branch main https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider
    cd /tmp/oqs-provider
    mkdir build
    cd build
    cmake -GNinja -Dliboqs_DIR='$OQS_PREFIX/lib/cmake/liboqs' -DOPENSSL_ROOT_DIR=/usr -DCMAKE_INSTALL_PREFIX='$OQS_PREFIX' ..
    ninja
    ninja install
    cd /tmp
    rm -rf oqs-provider
"

# Step 8: Install Anaconda
log_message "Installing Anaconda..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    if [ ! -d '$ANACONDA_PATH' ]; then
        curl -L https://repo.anaconda.com/archive/Anaconda3-latest-Linux-x86_64.sh -o /tmp/anaconda.sh
        bash /tmp/anaconda.sh -b -p '$ANACONDA_PATH'
        '$ANACONDA_PATH/bin/conda' init
        rm -f /tmp/anaconda.sh
    fi
"

# Step 9: Configure post-quantum cryptsetup
log_message "Configuring post-quantum cryptsetup..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    apt install -y libargon2-dev libjson-c-dev libdevmapper-dev uuid-dev
    git clone https://gitlab.com/cryptsetup/cryptsetup.git /tmp/cryptsetup
    cd /tmp/cryptsetup
    cat << 'EOC' > src/lib/crypto_backend/kyber.c
#include <oqs/oqs.h>
#include <argon2.h>
#include <json-c/json.h>
#include <cryptsetup.h>
#define KYBER_VARIANT \"ML-KEM-1024\"
#define ARGON2_MEMORY 1048576
#define ARGON2_ITERATIONS 4
#define ARGON2_PARALLELISM 4

static int derive_kyber_private_key(const char *passphrase, size_t passphrase_len, uint8_t *private_key, size_t private_key_len) {
    uint8_t salt[16] = \"cryptsetup-kyber\";
    return argon2id_hash_raw(
        ARGON2_ITERATIONS, ARGON2_MEMORY, ARGON2_PARALLELISM,
        passphrase, passphrase_len,
        salt, sizeof(salt),
        private_key, private_key_len
    );
}

static int keyslot_open_kyber(struct crypt_device *cd, int keyslot, char *passphrase, size_t passphrase_len, void *key, size_t key_len) {
    OQS_KEM *kem = NULL;
    uint8_t *private_key = NULL, *ciphertext = NULL, *shared_secret = NULL;
    size_t private_key_len, ciphertext_len, shared_secret_len;
    int r = -1;
    kem = OQS_KEM_new(OQS_KEM_kyber_1024);
    if (!kem) {
        log_err(cd, \"Failed to initialize Kyber-1024\");
        return -1;
    }
    private_key_len = kem->length_secret_key;
    ciphertext_len = kem->length_ciphertext;
    shared_secret_len = kem->length_shared_secret;
    private_key = malloc(private_key_len);
    ciphertext = malloc(ciphertext_len);
    shared_secret = malloc(shared_secret_len);
    if (!private_key || !ciphertext || !shared_secret) {
        log_err(cd, \"Memory allocation failed\");
        goto out;
    }
    if (derive_kyber_private_key(passphrase, passphrase_len, private_key, private_key_len) != ARGON2_OK) {
        log_err(cd, \"Failed to derive Kyber private key from passphrase\");
        goto out;
    }
    struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
    json_object *jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
    const char *ciphertext_b64 = json_object_get_string(json_object_object_get(jobj_keyslot, \"kyber_ciphertext\"));
    size_t decoded_len;
    ciphertext = base64_decode(ciphertext_b64, strlen(ciphertext_b64), &decoded_len);
    if (decoded_len != ciphertext_len) {
        log_err(cd, \"Invalid Kyber ciphertext length\");
        goto out;
    }
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, private_key) != OQS_SUCCESS) {
        log_err(cd, \"Kyber decapsulation failed\");
        goto out;
    }
    if (key_len > shared_secret_len) {
        log_err(cd, \"Key length too large for Kyber shared secret\");
        goto out;
    }
    memcpy(key, shared_secret, key_len);
    r = 0;
out:
    free(private_key);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);
    return r;
}

static int keyslot_store_kyber(struct crypt_device *cd, int keyslot, const char *passphrase, size_t passphrase_len, const void *key, size_t key_len) {
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL, *private_key = NULL, *ciphertext = NULL, *shared_secret = NULL;
    size_t public_key_len, private_key_len, ciphertext_len, shared_secret_len;
    int r = -1;
    kem = OQS_KEM_new(OQS_KEM_kyber_1024);
    if (!kem) {
        log_err(cd, \"Failed to initialize Kyber-1024\");
        return -1;
    }
    public_key_len = kem->length_public_key;
    private_key_len = kem->length_secret_key;
    ciphertext_len = kem->length_ciphertext;
    shared_secret_len = kem->length_shared_secret;
    public_key = malloc(public_key_len);
    private_key = malloc(private_key_len);
    ciphertext = malloc(ciphertext_len);
    shared_secret = malloc(shared_secret_len);
    if (!public_key || !private_key || !ciphertext || !shared_secret) {
        log_err(cd, \"Memory allocation failed\");
        goto out;
    }
    if (OQS_KEM_keypair(kem, public_key, private_key) != OQS_SUCCESS) {
        log_err(cd, \"Kyber keypair generation failed\");
        goto out;
    }
    uint8_t *derived_private_key = malloc(private_key_len);
    if (derive_kyber_private_key(passphrase, passphrase_len, derived_private_key, private_key_len) != ARGON2_OK) {
        log_err(cd, \"Failed to derive Kyber private key from passphrase\");
        free(derived_private_key);
        goto out;
    }
    if (memcmp(private_key, derived_private_key, private_key_len) != 0) {
        log_err(cd, \"Derived private key does not match generated key\");
        free(derived_private_key);
        goto out;
    }
    free(derived_private_key);
    if (key_len != shared_secret_len) {
        log_err(cd, \"Key length does not match Kyber shared secret length\");
        goto out;
    }
    memcpy(shared_secret, key, key_len);
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
        log_err(cd, \"Kyber encapsulation failed\");
        goto out;
    }
    struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
    json_object *jobj_keyslot = json_object_new_object();
    char *public_key_b64 = base64_encode(public_key, public_key_len);
    char *ciphertext_b64 = base64_encode(ciphertext, ciphertext_len);
    json_object_object_add(jobj_keyslot, \"type\", json_object_new_string(\"kyber\"));
    json_object_object_add(jobj_keyslot, \"kyber_public_key\", json_object_new_string(public_key_b64));
    json_object_object_add(jobj_keyslot, \"kyber_ciphertext\", json_object_new_string(ciphertext_b64));
    LUKS2_keyslot_store(hdr, keyslot, jobj_keyslot);
    r = 0;
out:
    free(public_key);
    free(private_key);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);
    return r;
}
EOC
    ./configure --enable-libargon2 --enable-libjson-c --enable-libdevmapper --enable-libuuid --with-liboqs
    make -j$CPU_CORES
    make install
    cd /tmp
    rm -rf cryptsetup
"

# Step 10: Compile secure kernel for netboot
log_message "Compiling secure Linux kernel..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    apt install -y linux-source bc kmod cpio flex libncurses-dev libelf-dev libssl-dev bison
    mkdir -p /usr/src
    cd /usr/src
    curl -L 'https://git.kernel.org/torvalds/t/linux-6.14-rc5.tar.gz' -o linux-6.14-rc5.tar.gz
    tar -xzf linux-6.14-rc5.tar.gz
    cd linux-6.14-rc5
    cat <<EOC > .config
CONFIG_SMP=y
CONFIG_NR_CPUS=128
CONFIG_PREEMPT=y
CONFIG_X86_64=y
CONFIG_MODULES=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_LOCK_DOWN_KERNEL=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_SECURITY=y
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_INTEGRITY=y
CONFIG_IMA=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_DEFAULT_HASH=\"sha256\"
CONFIG_EVM=y
CONFIG_KASLR=y
CONFIG_SPECULATION_CONTROL=y
CONFIG_PAGE_TABLE_ISOLATION=y
CONFIG_RETPOLINE=y
CONFIG_CRYPTO_KYBER=y
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_CC_STACKPROTECTOR_STRONG=y
CONFIG_VMX=n
CONFIG_VT=y
CONFIG_VTD=y
CONFIG_DRM_I915=y
CONFIG_ETHERNET=y
CONFIG_NETDEVICES=y
CONFIG_E1000E=y
CONFIG_IGB=y
CONFIG_IXGBE=y
CONFIG_USB=n
CONFIG_NVM=y
CONFIG_BLK_DEV_NVME=y
CONFIG_SATA_AHCI=y
CONFIG_DDR4=y
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_NET=y
CONFIG_DEBUG_KERNEL=n
CONFIG_LOCALVERSION=\"-skyscope-quantum\"
EOC
    make olddefconfig
    make -j$CPU_CORES bzImage
    make -j$CPU_CORES modules
    make install
    cp arch/x86/boot/bzImage /boot/vmlinuz-6.14-rc5-skyscope
    cp System.map /boot/System.map-6.14-rc5-skyscope
    update-initramfs -c -k 6.14-rc5-skyscope
    sbsign --key /root/efi_keys/db.key --cert /root/efi_keys/db.crt /boot/vmlinuz-6.14-rc5-skyscope --output /boot/vmlinuz-6.14-rc5-skyscope.signed
"

# Step 11: Configure GRUB and EFI
log_message "Configuring GRUB and self-signed EFI..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    apt install -y grub-efi-amd64-signed shim-signed
    mkdir -p /boot/grub/themes/skyscope
    curl -L '$LOGO_URL' -o '$LOGO_PATH'
    cat <<EOC > /etc/grub.d/40_custom
#!/bin/sh
exec tail -n +3 \$0
set superusers=\"root\"
password_pbkdf2 root \$(echo -e \"$BOOTLOADER_PASSWORD\n$BOOTLOADER_PASSWORD\" | grub-mkpasswd-pbkdf2 | grep -o 'grub\.pbkdf2\.sha512\..*')
menuentry \"$OS_NAME Netinst\" {
    set background_color=black
    linux /vmlinuz-6.14-rc5-skyscope.signed root=/dev/mapper/skyscope--vg-root ro quiet splash lockdown=confidentiality ima_appraise=fix ima_hash=sha256 selinux=1 security=selinux enforcing=1
    initrd /initrd.img
}
EOC
    cat <<EOC > /etc/default/grub
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=\"$OS_NAME\"
GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash lockdown=confidentiality ima_appraise=fix ima_hash=sha256 selinux=1 security=selinux enforcing=1 apparmor=1 slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 net.ipv4.ip_forward=0 net.ipv6.conf.all.disable_ipv6=1\"
GRUB_CMDLINE_LINUX=\"\"
GRUB_GFXMODE=1920x1080
GRUB_GFXPAYLOAD_LINUX=keep
GRUB_THEME=/boot/grub/themes/skyscope/theme.txt
EOC
    cat <<EOC > /boot/grub/themes/skyscope/theme.txt
title-text: \"\"
title-color: \"#00FF00\"
title-font: \"DejaVu Sans Bold 16\"
desktop-image: \"plasmoid_orb.png\"
desktop-color: \"#000000\"
+boot_menu {
    left = 30%
    top = 40%
    width = 40%
    height = 40%
    item_font = \"DejaVu Sans 14\"
    item_color = \"#00FF00\"
    selected_item_color = \"#FFFFFF\"
    selected_item_pixmap_style = \"highlight_*\"
}
image {
    id = \"desktop-image\"
    top = 10%
    left = 40%
    width = 20%
    file = \"plasmoid_orb.png\"
}
label {
    top = 30%
    left = 30%
    width = 40%
    align = \"center\"
    color = \"#00FF00\"
    font = \"DejaVu Sans Bold 24\"
    text = \"$OS_NAME\"
}
EOC
    update-grub
    # Generate self-signed EFI keys
    mkdir -p /root/efi_keys
    openssl req -new -x509 -newkey rsa:4096 -subj \"/CN=Skyscope Sentinel PK/\" -keyout /root/efi_keys/PK.key -out /root/efi_keys/PK.crt -days 3650 -nodes -sha256
    openssl req -new -x509 -newkey rsa:4096 -subj \"/CN=Skyscope Sentinel KEK/\" -keyout /root/efi_keys/KEK.key -out /root/efi_keys/KEK.crt -days 3650 -nodes -sha256
    openssl req -new -x509 -newkey rsa:4096 -subj \"/CN=Skyscope Sentinel DB/\" -keyout /root/efi_keys/db.key -out /root/efi_keys/db.crt -days 3650 -nodes -sha256
    sbsign --key /root/efi_keys/db.key --cert /root/efi_keys/db.crt /boot/efi/EFI/debian/grubx64.efi --output /boot/efi/EFI/debian/grubx64-signed.efi
    sbverify --cert /root/efi_keys/db.crt /boot/efi/EFI/debian/grubx64-signed.efi
    # Make GRUB config immutable
    chattr +i /etc/grub.d/* /etc/default/grub /boot/grub/grub.cfg
"

# Step 12: Harden system and prevent tampering
log_message "Hardening system..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    apt install -y ufw rkhunter aide firejail sshguard iptables network-manager firewalld fail2ban apparmor selinux-basics selinux-policy-default
    ufw enable
    systemctl enable ufw
    rkhunter --propupd
    systemctl enable rkhunter.timer
    aide --init
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    systemctl enable aide.timer
    firejail --setup
    sed -i 's/#FIREJAIL_DEFAULT.*$/FIREJAIL_DEFAULT=1/' /etc/firejail/firejail.config
    systemctl enable sshguard
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
    systemctl enable iptables
    systemctl enable network-manager
    firewalld --set-default-zone=drop
    systemctl enable firewalld
    fail2ban-client start
    systemctl enable fail2ban
    apparmor_parser -r /etc/apparmor.d/*
    systemctl enable apparmor
    selinux-activate
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    # Disable risky services
    systemctl mask bluetooth wpasupplicant cups cups-browsed avahi-daemon rpcbind telnet rdp samba nfs-common mdadm bind9
    # Configure sysctl for anti-tampering
    cat <<EOC > /etc/sysctl.d/99-skyscope.conf
kernel.kexec_load_disabled=1
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=0
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv6.conf.all.disable_ipv6=1
dev.tty.ldisc_autoload=0
vm.mmap_min_addr=65536
kernel.pid_max=32768
kernel.dmesg_restrict=1
kernel.printk=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
EOC
    sysctl -p /etc/sysctl.d/99-skyscope.conf
    # Configure SSH with post-quantum crypto
    cat <<EOC > /etc/ssh/sshd_config
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
KexAlgorithms sntrup761x25519-sha512@openssh.com
HostKeyAlgorithms ssh-kyber-512
Ciphers aes256-ctr
MACs hmac-sha2-512
EOC
    systemctl restart sshd
    # Lock critical configs
    configs_to_lock=('/etc/passwd' '/etc/shadow' '/etc/group' '/etc/gshadow' '/etc/sudoers' '/etc/sysctl.conf' '/etc/apt/sources.list' '/etc/grub.d/' '/etc/default/grub' '/etc/fstab' '/boot/grub/grub.cfg' '/etc/ssh/sshd_config' '/etc/iptables/rules.v4' '/etc/selinux/config')
    for config in \"\${configs_to_lock[@]}\"; do
        if [ -e \"\$config\" ]; then
            chattr +i \"\$config\"
            cp -a \"\$config\" \"/root/backup_\$(basename \$config)_\$(date +%F_%T)\"
        fi
    done
    # Configure IMA/EVM
    apt install -y evmctl
    evmctl ima_sign --key /root/efi_keys/db.key /boot/vmlinuz-6.14-rc5-skyscope.signed
    cat <<EOC > /etc/ima/ima-policy
appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig
appraise func=MODULE_CHECK appraise_type=imasig
measure func=FILE_CHECK
EOC
    chattr +i /etc/ima/ima-policy
"

# Step 13: Setup user and encryption
log_message "Setting up user and encryption..."
chroot "$SQUASHFS_ROOT" /bin/bash -c "
    useradd -m -s /bin/bash $USERNAME
    echo \"$USERNAME:$ROOT_PASSWORD\" | chpasswd
    # Prompt for encryption password
    echo 'Enter encryption password for full disk encryption:'
    read -s ENCRYPTION_PASSWORD
    echo -e \"$ENCRYPTION_PASSWORD\n$ENCRYPTION_PASSWORD\" | cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 --pbkdf argon2id $NVME_DEV
    echo -e \"$ENCRYPTION_PASSWORD\" | cryptsetup luksOpen $NVME_DEV skyscope_crypt
    pvcreate /dev/mapper/skyscope_crypt
    vgcreate skyscope-vg /dev/mapper/skyscope_crypt
    lvcreate -L 50G -n root skyscope-vg
    lvcreate -L 8G -n swap skyscope-vg
    lvcreate -l 100%FREE -n home skyscope-vg
    mkfs.btrfs /dev/skyscope-vg/root
    mkswap /dev/skyscope-vg/swap
    mkfs.btrfs /dev/skyscope-vg/home
"

# Step 14: Exit chroot
log_message "Exiting chroot..."
for dir in dev proc sys run; do
    umount "$SQUASHFS_ROOT/$dir"
done

# Step 15: Rebuild ISO
log_message "Rebuilding netinst ISO..."
cd "$WORKDIR"
handle_error "Create new ISO" "Failed to create ISO" \
"genisoimage -o '$NEW_ISO' -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -J -R -V 'Skyscope Sentinel Quantum Hybrid Netinst' . -eltorito-alt-boot -e efi.img -no-emul-boot" \
"xorriso -as mkisofs -o '$NEW_ISO' -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -J -R -V 'Skyscope Sentinel Quantum Hybrid Netinst' . -eltorito-alt-boot -e efi.img -no-emul-boot"

# Step 16: Sign ISO
log_message "Signing ISO..."
handle_error "Sign ISO" "Failed to sign ISO" \
"openssl dgst -sha256 -sign /root/efi_keys/db.key -out '$NEW_ISO.sig' '$NEW_ISO'" \
"openssl dgst -sha256 -sign /root/efi_keys/db.key -out '$NEW_ISO.sig' '$NEW_ISO'"

# Step 17: Final cleanup
log_message "Cleaning up..."
rm -rf "$WORKDIR" "$ISO_FILE" "$SQUASHFS_ROOT" "$INITRD_DIR"
log_message "Skyscope Sentinel Intelligence Quantum Hybrid Netinst OS ISO created at $NEW_ISO. Signature at $NEW_ISO.sig."
log_message "Setup complete. Use ISO for secure netboot installation."
