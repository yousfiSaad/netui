#!/bin/bash
# Run netui with eBPF backend in Lima VM
#
# This script drops you into the Lima VM shell where you can run netui directly.
# The interactive shell already has proper TTY allocation for the TUI.

set -e

echo "╭─────────────────────────────────────────────────────────────╮"
echo "│  Entering Lima VM for eBPF development                       │"
echo "│  Interface: eth0 | Backend: ebpf (XDP + TC egress)          │"
echo "╰─────────────────────────────────────────────────────────────╯"
echo ""
echo "Once inside, run:"
echo "  cd ~/enetui"
echo "  sudo ./target/debug/netui --name eth0 --backend ebpf"
echo ""

limactl shell enetui
