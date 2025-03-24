#!/bin/bash

test_ip() {
  curl -v --parallel --parallel-immediate \
  "http://$1:8888/$2" \
  "http://$1:8888/$2" \
  "http://$1:8888/$2" \
  "http://$1:8888/$2" \
  "http://$1:8888/$2"
}

echo "Detecting IP addresses on all network interfaces..."
echo "=================================================="

# Determine the operating system
if [[ "$(uname)" == "Darwin" ]]; then
    # macOS
    echo "Detected macOS system"
    echo ""

    # Get list of network interfaces
    interfaces=$(ifconfig -l)

    for interface in $interfaces; do
        # Skip loopback and inactive interfaces
        if [[ "$interface" != "lo0" && "$(ifconfig $interface 2>/dev/null | grep 'status: active' 2>/dev/null)" != "" ]]; then
            echo "Interface: $interface"

            # Get IPv4 addresses
            ipv4=$(ifconfig $interface | grep inet | grep -v inet6 | awk '{print $2}')
            if [[ -n "$ipv4" ]]; then
                test_ip $ipv4 "one"
                test_ip $ipv4 "two"
            fi
        fi
    done

elif [[ "$(uname)" == "Linux" ]]; then
    # Linux
    echo "Detected Linux system"
    echo ""

    # Check if 'ip' command is available, otherwise use ifconfig
    if command -v ip &>/dev/null; then
        # Using 'ip' command (modern Linux)
        interfaces=$(ip -o link show | awk -F': ' '{print $2}')

        for interface in $interfaces; do
            # Skip loopback
            if [[ "$interface" != "lo" ]]; then
                # Check if interface is up
                if [[ "$(ip link show dev $interface | grep 'state UP')" != "" ]]; then
                    echo "Interface: $interface"

                    # Get IPv4 addresses
                    ipv4=$(ip -4 addr show dev $interface | grep inet | awk '{print $2}')
                    if [[ -n "$ipv4" ]]; then
                        test_ip $ipv4 "one"
                        test_ip $ipv4 "two"
                    fi
                fi
            fi
        done

    else
        # Using 'ifconfig' (older Linux distributions)
        interfaces=$(ifconfig | grep -E '^[a-zA-Z0-9]+:' | awk '{print $1}' | sed 's/://')

        for interface in $interfaces; do
            # Skip loopback
            if [[ "$interface" != "lo" ]]; then
                echo "Interface: $interface"

                # Get IPv4 addresses
                ipv4=$(ifconfig $interface | grep inet | grep -v inet6 | awk '{print $2}' | sed 's/addr://')
                if [[ -n "$ipv4" ]]; then
                    test_ip $ipv4
                fi
            fi
        done
    fi

else
    echo "Unsupported operating system: $(uname)"
    exit 1
fi

test_ip "127.0.0.1" "one"

echo "API Request"

curl "http://localhost:9000/api/one" -v --output one.bin
curl "http://localhost:9000/api/two" -v --output two.bin
