#VM SETTING
#!/bin/bash

set -e  # Stop on error

TOOLS=/home/ubuntu/app_server/gem5-dpdk-setup/dpdk-pktgen-build/dpdk/usertools
DPDK_BIND_TOOL=$TOOLS/dpdk-devbind.py
DPDK_DRIVER="igb_uio"

# Network settings
NET_MASK_CIDR="24"  # Subnet mask

echo "[INFO] Detecting NIC devices and assigning IPs based on MAC addresses..."

# Get list of NICs (excluding loopback)
NIC_DEVICES=($(ip -o link show | awk -F': ' '!/lo/ {print $2}'))

# Remove any existing default routes
if ip route | grep -q '^default'; then
    echo "[INFO] Removing existing default route(s)..."
    sudo ip route del default || true
fi

for NIC in "${NIC_DEVICES[@]}"; do
    # Get MAC address
    MAC_ADDR=$(cat /sys/class/net/"$NIC"/address 2>/dev/null)

    if [[ -n "$MAC_ADDR" ]]; then
        # Extract last byte of MAC and convert to decimal
        LAST_BYTE_HEX=$(echo "$MAC_ADDR" | awk -F':' '{print $6}')
        LAST_BYTE_DEC=$(( 0x$LAST_BYTE_HEX ))

        # Generate unique IP address based on MAC
        IP_ADDR="10.0.2.$LAST_BYTE_DEC"

        echo "[INFO] Assigning IP $IP_ADDR to NIC $NIC (MAC: $MAC_ADDR)"

        # Remove existing IP and assign new IP
        sudo ip addr flush dev "$NIC"
        sudo ip addr add "$IP_ADDR/$NET_MASK_CIDR" dev "$NIC"

        # Bring up interface
        sudo ip link set "$NIC" down
    else
        echo "[WARN] Skipping NIC $NIC (MAC address not found)"
    fi
done

echo "✅ Network setup completed (no gateway configured)."

# Binding igb_uio
sudo modprobe igb_uio
lsmod | grep igb


echo "[INFO] Scanning for DPDK-compatible NICs via lspci..."

# 1. DPDK에서 사용 가능한 NIC 목록 필터링 (virtio 또는 Intel NIC 포함)
NIC_PCI_LIST=$(lspci -Dvmmnn | awk '/^Slot/ {slot=$2} /^Class/ && $2 ~ /Ethernet/ {print slot}' | sort)

if [ -z "$NIC_PCI_LIST" ]; then
    echo "[ERROR] No NIC PCI devices found via lspci"
    exit 1
fi

echo "[INFO] Found PCI devices:"
echo "$NIC_PCI_LIST"

# 2. 인터페이스 다운 + 바인딩
for pci_addr in $NIC_PCI_LIST; do
    echo "[INFO] Trying to bind $pci_addr to $DPDK_DRIVER..."
    
    # 바인딩
    sudo python3 "$DPDK_BIND_TOOL" -b "$DPDK_DRIVER" "$pci_addr"
done

echo "[INFO] Showing DPDK NIC status..."
sudo python3 "$DPDK_BIND_TOOL" -s

# HugePage configuration
echo "Configuring HugePages..."

# Initial HugePage setup (1024 pages of 2MB, 2 pages of 1GB)
sudo sh -c 'echo 6144 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'



# Check HugePage status
echo "Checking HugePage status..."
cat /proc/meminfo | grep HugePages
mount | grep hugetlbfs

echo "Network and HugePage setup completed successfully!"

