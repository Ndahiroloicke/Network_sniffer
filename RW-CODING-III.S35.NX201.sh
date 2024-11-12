#!/bin/bash

# Ndahiro Loic
# RW-CODING-III
# Student Code: s35
# Lecturer: Nizeyimana Celestin

# Function to install required applications
install_apps() {
    echo "Installing required applications..."

    # Array of required applications
    required_apps=(sshpass tor nmap whois)

    for app in "${required_apps[@]}"; do
        if ! command -v $app &> /dev/null; then
            echo "$app is not installed. Installing..."
             apt-get install -y $app
        else
            echo "$app is already installed."
        fi
    done
}

# Function to check anonymity
check_anonymity() {
    echo "Checking if the network connection is anonymous..."

    # Check if Tor is active
    if ! ps aux | grep -v grep | grep tor > /dev/null; then
        echo "Network connection is NOT anonymous. Please enable anonymity and restart the script."
        exit 1
    else
        echo "Network connection is anonymous."
        spoofed_country=$(torify curl -s https://ipinfo.io/country)
        echo "Spoofed Country: $spoofed_country"
    fi
}

# Function to get user input for remote IP and address to scan
get_user_inputs() {
    read -p "Enter the remote server IP address: " remote_ip
    read -p "Enter the address to scan: " address

    # Determine remote country from the IP provided
    remote_country=$(whois $remote_ip | grep -i "Country" | head -n 1 | awk '{print $NF}')
    echo "Detected Remote Country: $remote_country"
}

# Function to connect to the remote server and execute commands
execute_remote_commands() {
    echo "Connecting to the remote server..."

    # Prompt for SSH password or key file for secure access
    read -s -p "Enter SSH password: " ssh_password
    echo ""

    # Display remote server details
    echo "Remote server details:"
    uptime=$(sshpass -p "$ssh_password" ssh -o StrictHostKeyChecking=no user@$remote_ip "uptime")
    echo "Country: $remote_country"
    echo "IP: $remote_ip"
    echo "Uptime: $uptime"

    # Get Whois information and save it to a file
    echo "Fetching Whois information..."
    whois_output=$(sshpass -p "$ssh_password" ssh -o StrictHostKeyChecking=no user@$remote_ip "whois $address")
    echo "$whois_output" > domain_info.txt
    echo "Whois Information saved to domain_info.txt."

    # Extract the owner's name from the Whois output
    owner_name=$(echo "$whois_output" | grep -i "OrgName" | head -n 1 | awk '{print $NF}')
    echo "Owner's Name: $owner_name"

    # Scan for open ports and save results to a file
    echo "Scanning for open ports..."
    nmap_output=$(sshpass -p "$ssh_password" ssh -o StrictHostKeyChecking=no user@$remote_ip "nmap $address")
    echo "$nmap_output" > port_scan_results.txt
    echo "Nmap Scan Results saved to port_scan_results.txt."
}

# Function to log and audit data collection
log_audit() {
    echo "Logging and auditing data collection..."
    {
        echo "Student Name: Ndahiro Loic"
        echo "Student Code: S35"
        echo "Teacher's Name: Nizeyimana Celestin"
        echo "Class Code: RW-CODING-III"
        echo "Address Scanned: $address"
        echo "Remote Server IP: $remote_ip"
        echo "Remote Server Country: $remote_country"
        echo "Owner's Name: $owner_name"
        echo "Timestamp: $(date)"
    } >> execution_audit.txt
    echo "Audit log updated."
}

# Main execution
install_apps
check_anonymity
get_user_inputs
execute_remote_commands
log_audit

echo "Script execution completed."
