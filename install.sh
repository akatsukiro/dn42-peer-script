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

setup_bird() {
    echo -e "${green}Setting up BIRD${plain}"
    echo "Please enter your information"
    read -p "Your AS number: " as_number
    read -p "Your dn42 IPv4 address: " dn42_ip
    read -p "Your dn42 IPv6 address: " dn42_ip_v6
    read -p "Your dn42 IPv4 CIDR: " dn42_cidr
    read -p "Your dn42 IPv6 CIDR: " dn42_cidr_v6
    cat > /etc/bird/bird.conf <<EOF
# /etc/bird/bird.conf
################################################
#               Variable header                #
################################################

define OWNAS =  ${as_number};
define OWNIP =  ${dn42_ip};
define OWNIPv6 = ${dn42_ip_v6};
define OWNNET = ${dn42_cidr};
define OWNNETv6 = ${dn42_cidr_v6};
define OWNNETSET = [${dn42_cidr}+];
define OWNNETSETv6 = [${dn42_cidr_v6}+];

################################################
#                 Header end                   #
################################################

router id OWNIP;

protocol device {
    scan time 10;
}

/*
 *  Utility functions
 */

function is_self_net() {
  return net ~ OWNNETSET;
}

function is_self_net_v6() {
  return net ~ OWNNETSETv6;
}

function is_valid_network() {
  return net ~ [
    172.20.0.0/14{21,29}, # dn42
    172.20.0.0/24{28,32}, # dn42 Anycast
    172.21.0.0/24{28,32}, # dn42 Anycast
    172.22.0.0/24{28,32}, # dn42 Anycast
    172.23.0.0/24{28,32}, # dn42 Anycast
    172.31.0.0/16+,       # ChaosVPN
    10.100.0.0/14+,       # ChaosVPN
    10.127.0.0/16{16,32}, # neonetwork
    10.0.0.0/8{15,24}     # Freifunk.net
  ];
}

roa4 table dn42_roa;
roa6 table dn42_roa_v6;

protocol static {
    roa4 { table dn42_roa; };
    include "/etc/bird/roa_dn42.conf";
};

protocol static {
    roa6 { table dn42_roa_v6; };
    include "/etc/bird/roa_dn42_v6.conf";
};

function is_valid_network_v6() {
  return net ~ [
    fd00::/8{44,64} # ULA address space as per RFC 4193
  ];
}

protocol kernel {
    scan time 20;

    ipv6 {
        import none;
        export filter {
            if source = RTS_STATIC then reject;
            krt_prefsrc = OWNIPv6;
            accept;
        };
    };
};

protocol kernel {
    scan time 20;

    ipv4 {
        import none;
        export filter {
            if source = RTS_STATIC then reject;
            krt_prefsrc = OWNIP;
            accept;
        };
    };
}

protocol static {
    route OWNNET reject;

    ipv4 {
        import all;
        export none;
    };
}

protocol static {
    route OWNNETv6 reject;

    ipv6 {
        import all;
        export none;
    };
}

template bgp dnpeers {
    local as OWNAS;
    path metric 1;

    ipv4 {
        import filter {
          if is_valid_network() && !is_self_net() then {
            if (roa_check(dn42_roa, net, bgp_path.last) != ROA_VALID) then {
              print "[dn42] ROA check failed for ", net, " ASN ", bgp_path.last;
              reject;
            } else accept;
          } else reject;
        };

        export filter { if is_valid_network() && source ~ [RTS_STATIC, RTS_BGP] then accept; else reject; };
        import limit 1000 action block;
    };

    ipv6 {   
        import filter {
          if is_valid_network_v6() && !is_self_net_v6() then {
            if (roa_check(dn42_roa_v6, net, bgp_path.last) != ROA_VALID) then {
              print "[dn42] ROA check failed for ", net, " ASN ", bgp_path.last;
              reject;
            } else accept;
          } else reject;
        };
        export filter { if is_valid_network_v6() && source ~ [RTS_STATIC, RTS_BGP] then accept; else reject; };
        import limit 1000 action block; 
    };
}


include "/etc/bird/peers/*";
EOF
    systemctl enable bird
    systemctl restart bird
}

setup_roa() {
    echo -e "${green}Setting up ROA${plain}"
    wget -O /tmp/dn42_roa.conf https://dn42.burble.com/roa/dn42_roa_bird2_4.conf && mv -f /tmp/dn42_roa.conf /etc/bird/roa_dn42.conf
    wget -O /tmp/dn42_roa_v6.conf https://dn42.burble.com/roa/dn42_roa_bird2_6.conf && mv -f /tmp/dn42_roa_v6.conf /etc/bird/roa_dn42_v6.conf
}

setup_cron() {
    echo -e "${green}Setting up crontab job${plain}"
    cat > /etc/crontab <<EOF
0 0 */1 * * ? wget -O /tmp/dn42_roa.conf https://dn42.burble.com/roa/dn42_roa_bird2_4.conf && mv -f /tmp/dn42_roa.conf /etc/bird/roa_dn42.conf
0 0 */1 * * ? wget -O /tmp/dn42_roa_v6.conf https://dn42.burble.com/roa/dn42_roa_bird2_6.conf && mv -f /tmp/dn42_roa_v6.conf /etc/bird/roa_dn42_v6.conf
3 0 */1 * * ? birdc c
EOF
}

generate_key() {
    echo -e "${green}Generating WireGuard key pair${plain}"
    wg genkey | tee privatekey | wg pubkey > publickey
    echo "Your private key is $(cat privatekey)"
    echo "Your public key is $(cat publickey)"
}
