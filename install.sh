#! /bin/bash

green='\033[0;32m'
plain='\033[0m'

setup_ip_forward() {
    echo -e "${green}Setting up IP forwarding${plain}"
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
}

setup_rp_filter() {
    echo -e "${green}Setting up RP filter${plain}"
    echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
}

install_base() {
    echo -e "${green}Installing basic packages${plain}"
    apt update && apt install bird2 wireguard -y
}

