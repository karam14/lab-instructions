

1. Using PowerShell

List all computers in the domain and their IPs:

Get-ADComputer -Filter * | Select-Object Name, IPv4Address

Filter for specific OS types:

Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} | Select-Object Name, IPv4Address


2. Using nslookup

Look up the IP address of a known hostname:

nslookup <hostname>


3. Using ping with a Range of IPs

Ping a range of IPs using a PowerShell loop:

1..254 | ForEach-Object { Test-Connection -ComputerName "192.168.1.$_" -Count 1 -Quiet } | ForEach-Object { Write-Host "Device found at 192.168.1.$_" }


4. Using Nmap (Network Mapper)

Scan a subnet for active devices:

nmap -sn 192.168.1.0/24


5. Using net view Command

List computers in a specific domain:

net view /domain:<DomainName>


6. Using Active Directory Users and Computers (ADUC)

Navigate to Computers or an OU to view devices and use ping/nslookup to find their IPs.


7. Using DHCP Console

View Address Leases under the DHCP Management Console to see leased IP addresses and corresponding hostnames.


8. Using arp (Address Resolution Protocol)

Display the ARP table:

arp -a


9. Using Network Monitoring Tools

Wireshark: Capture traffic and filter by IP to identify devices.

Angry IP Scanner: Scan a subnet for active devices.

Advanced IP Scanner: A simple GUI tool for scanning network ranges.


10. Using DNS Server to List Devices

Use DNS Manager (dnsmgmt.msc) and look under Forward Lookup Zones for Host (A) records.


11. Using netstat Command

List active connections:

netstat -an


12. Using WMIC (Windows Management Instrumentation Command-line)

Query remote machines for IP and other details:

wmic /node:<remote_computer_name> nicconfig get description, ipaddress


13. Using Group Policy Management Console (GPMC)

Create a logon script through Group Policy to log IP addresses to a central location.


14. Using Event Viewer for Logins

Check Logon events (Event ID 4624) in Event Viewer to identify devices logging into the domain.


15. Using LDAP Queries

Query for computer objects in the domain:

dsquery computer -name *


16. Using SCCM (System Center Configuration Manager)

Generate reports on devices, showing their IP addresses through SCCM.


17. Using Network Discovery in File Explorer

Browse Network in File Explorer to see visible computers and manually query their IPs.


18. Using Scripts for Automated Scanning

Example Python script for pinging a subnet:

import os
for ip in range(1, 255):
    address = f"192.168.1.{ip}"
    response = os.system(f"ping -n 1 {address}")
    if response == 0:
        print(f"{address} is active")


19. Using nbtstat for NetBIOS

Retrieve NetBIOS details of remote devices:

nbtstat -a <remote_computer_name_or_IP>


20. Using Microsoft Endpoint Manager (Intune)

Access Microsoft Endpoint Manager to view IP addresses of managed devices.




