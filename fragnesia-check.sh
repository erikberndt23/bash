#!/bin/bash
# fragnesia_audit.sh - Passive Vulnerability Assessment for CVE-2026-46300

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Starting Passive Audit for Fragnesia (CVE-2026-46300)...${NC}"

# 1. Kernel Version Audit
CURRENT_KERNEL=$(uname -r)
echo -e "\n[*] Running Kernel: $CURRENT_KERNEL"

# Reference fixed version for Debian 13 (Trixie) branch: 6.12.113-1
if [[ "$CURRENT_KERNEL" =~ 6\.12\.111 ]]; then
    echo -e "${RED}[!] Status: Running vulnerable kernel version (6.12.111). Upgrade to 6.12.113-1 or higher is required.${NC}"
else
    echo -e "${GREEN}[+] Status: Kernel version may be patched or outside the immediate vulnerable release string. Verify with distribution changelogs.${NC}"
fi

# 2. Kernel Module Status Check
echo -e "\n[*] Checking state of associated networking modules..."
VULN_MODULES=$(lsmod | grep -E '^(esp4|esp6|rxrpc)' | awk '{print $1}')

if [ -n "$VULN_MODULES" ]; then
    echo -e "${RED}[!] Alert: Active vulnerable modules found loaded: ${VULN_MODULES//$'\n'/ /}${NC}"
    echo -e "${YELLOW}[i] Mitigation: Consider blacklisting these modules if they are not actively required by infrastructure.${NC}"
else
    echo -e "${GREEN}[+] Pass: Relevant modules (esp4, esp6, rxrpc) are not currently loaded in memory.${NC}"
fi

# 3. Unprivileged User Namespaces Check
echo -e "\n[*] Checking unprivileged user namespace settings..."
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    USER_NS=$(cat /proc/sys/kernel/unprivileged_userns_clone)
    if [ "$USER_NS" -eq 0 ]; then
        echo -e "${GREEN}[+] Pass: Unprivileged user namespaces are disabled via sysctl.${NC}"
    else
        echo -e "${YELLOW}[!] Note: Unprivileged user namespaces are enabled.${NC}"
    fi
else
    echo -e "${YELLOW}[i] Note: /proc/sys/kernel/unprivileged_userns_clone not present. Checking AppArmor restrictions...${NC}"
fi

# 4. AppArmor Restriction Audit (Debian Specific)
if [ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    AA_RESTRICT=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
    if [ "$AA_RESTRICT" -eq 1 ]; then
        echo -e "${GREEN}[+] Pass: AppArmor is actively restricting unprivileged user namespaces.${NC}"
    else
        echo -e "${RED}[!] Alert: AppArmor unprivileged namespace restriction is disabled.${NC}"
    fi
fi

echo -e "\n${YELLOW}[*] Audit complete.${NC}"