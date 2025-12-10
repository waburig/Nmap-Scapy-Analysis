#Nmap and Scapy Network Analysis

#1.	Objective
This assignment reproduces network analysis techniques covered in class, utilizing Nmap for host discovery and vulnerability identification, and Scapy for custom packet sniffing and protocol analysis. The target network is 10.6.6.0/24, focusing primarily on the host 10.6.6.23 gravemimd.vm.

#2.	Network Scan (10.6.6.0/24)
Command used: nmap -sn 10.6.6.0/24
Explanation of Command: This command performs a basic scan of the entire 10.6.6.0/24 network range to discover active hosts and their basic port information.
Explanation of Output: The scan detected 7 live hosts out of 256 IP addresses. The output lists the IP addresses, such as 10.6.6.11 webgoat.vm and 10.6.6.23 gravemind.vm, along with their MAC addresses and confirmation that they are up.
![Nmap Network Scan Output](scans/Networkn Scan 10.6.6.0.jpg)

##3.	Host Scan (10.6.6.23)
Command used: nmap -O 10.6.6.23
Explanation of Command: This performs a focused, single-target scan to reveal open ports and running services on the host.
Explanation of Output: The scan on 10.6.6.23 gravemind.vm shows several open TCP ports, including 21 (ftp), 22 (ssh), 80 (http), 139 (netbios-ssn), and 445 (microsoft-ds). It also provides OS details, indicating the target is running Linux
 
![Nmap Host Scan Output showing open ports and OS details](scans/Host Scan 10.6.6.23.jpg)

##4.	Aggressive Scan
Command used: nmap -p 21 -sV -A -T4 10.6.6.23
•	Explanation of Command: This is a focused aggressive scan.
-p 21: Targets only port 21 (FTP).
-sV: Enables version detection to determine the exact service and version2.
-A: Enables the aggressive scan features, including OS detection, script scanning, and traceroute3.
-T4: Sets the scanning speed to Aggressive (level 4).
Explanation of Output
This aggressive, port-specific scan collected detailed information about the FTP service running on 10.6.6.23.
•	Service Versioning: Confirms that the FTP service running on 21/tcp is vsftpd 3.0.3.
•	FTP Status Script Output: Provides detailed session information, including:
Control connection is plain text (no encryption).
Session timeout is 300 seconds.
•	Security Finding: Indicates **Anonymous FTP** login is allowed (FTP code 230).
•	File Listing: Lists several files accessible via the anonymous login: file1.txt, file2.txt, file3.txt, and supersecretfile.txt.
•	Traceroute/OS Details: The scan also provided basic OS details (Running: Linux 4.X|5.X) and a TRACEROUTE indicating the host is 1 hop away.
This aggressive scan enables OS detection, version detection, script scanning, and traceroute. It collects the maximum amount of detail about the target machine.

 ![Nmap Aggressive Scan showing vsftpd 3.0.3 and Anonymous Login](scans/Aggresive scan.jpg)

##4. Aggressive Scan Continued
This is the continuation of the aggressive scan output.

 ![Continuation of the Aggressive Scan script output](scans/Aggressive Scan Continued.jpg)


##5. SMB Port Scan (Ports 139 & 445)
Command used: nmap -p 139,445 10.6.6.23
Explanation of Command: This scan focuses on ports 139 and 445, which are used by SMB (Server Message Block) for Windows file sharing, to identify potential vulnerabilities.
Explanation of Output (Screenshot):
•	Service Version: Ports 139/tcp and 445/tcp are open and running Samba smbd 4.9.5-Debian.
•	Script Results: The smb-security-mode script indicates the account_used is guest, and message_signing is disabled, which is a potentially dangerous default setting. The target's NetBIOS computer name is GRAVEMIND.

 ![Nmap SMB Scan output showing Samba version and disabled message signing](scans/SMB Port Scan Ports 139 & 445.jpg)
 
##7. Anonymous SMB Access Test
Command used: smbclient //10.6.6.23/print$ -N
This test attempts to connect to the specific print$ share on the target host. The -N flag attempts login without a password. The output 'Anonymous login successful' confirms the system allows unauthenticated access to this share.

 ![smbclient output showing Anonymous login successful to print$ share](scans/Anonymous SMB Access Test.jpg)
 
##8. Route Check
Command used: ip route
Displays the system's routing table, showing gateways and traffic flow paths.

 ![ip route command output showing network routing table](scans/Route Check.jpg)

##9. Route Check Continued
More routing table output showing network paths.

 ![Continuation of the route check output showing network paths](scans/Route Check Continued.jpg)

##10. Scapy Packet Sniffing
Command used: sniff()
This captures live network packets and prints their summary details.
Explanation of Command: This Scapy function captures the first 10 live network packets and prints their summary details.
Explanation of Output (Screenshot): The paro.summary() output shows a variety of packets, including Ether / IP / TCP traffic between different hosts 10.0.2.15 and 2.17.161.83.

![Scapy output showing captured packet summaries](scans/Scapy Packet Sniffing.jpg)
 
##11. Scapy ls() Output
Command used: ls()
Lists available Scapy packet fields and structures. The screenshot shows Shows the list of Scapy packet fields and structures

##12. Additional Scapy Sniff Output
Command used: Scapy: sniff(iface="br-internal")
Explanation of Command: Captures live packets on the br-internal interface.
Explanation of Output (Screenshot): The summary (paro2.summary()) shows a detailed TCP exchange (HTTP traffic) between 10.6.6.1 and 10.6.6.23. The packets include S (SYN), SA (SYN-ACK), A (ACK), and FA(FIN-ACK) flags, illustrating the TCP three-way handshake and session closure.

 ![Scapy output showing TCP handshake details on br-internal](scans/Additional Scapy Packet Sniffing.jpg)

##13. Scapy ICMP Filtered Sniff
Command used:Scapy: sniff(iface="br-internal", filter="icmp", count=5) 
Explanation of Command: Captures exactly 5 packets on the br-internal interface, filtered to only include ICMP (ping) traffic.
Explanation of Output (Screenshot): The summary (paro3.summary()) shows a successful exchange of ICMP echo-request from 10.6.6.1 to 10.6.6.23 and echo-reply (from 10.6.6.23 to 10.6.6.1) packets, confirming a successful ping test between the two hosts.

![Scapy ICMP Filtered Sniff output showing echo-request and echo-reply](scans/Scapy ICMP Filtered Sniff.jpg)
 
#Feedback
The network analysis revealed three primary, critical configuration weaknesses that allow for unauthenticated access to system data and services.
1. Anonymous FTP Access (Port 21/tcp)
•	Vulnerability: The configuration allows for Anonymous FTP login.
•	Impact: An unauthenticated attacker can connect to the FTP server and immediately access files in the public directory4. The aggressive scan output confirmed that files like file1.txt, file2.txt, file3.txt, and supersecretfile.txt are readable.
•	Mitigation: Anonymous login should be disabled, or the anonymous directory should be completely empty and not writable by the FTP service.
2. Anonymous SMB Access to Shares (Ports 139/tcp & 445/tcp)
The target is running Samba smbd 4.9.5-Debian for Server Message Block (SMB) services.
•	Vulnerability: The system permits anonymous access to at least one specific share (print$). The smbclient test confirmed "Anonymous login successful”.
•	Impact: This configuration allows an unauthenticated user to view, and potentially interact with, files or resources within that share, leading to information leakage.
•	Mitigation: All SMB shares should require valid user authentication credentials.
3. Weak SMB Security Configuration
The Nmap SMB script results identified an additional weakness in the Samba configuration.
•	Vulnerability: Message signing is disabled (or "enabled but not required"). Message signing is a security feature used to verify the origin and integrity of SMB packets.
•	Impact: Without message signing, an attacker could potentially perform a Man-in-the-Middle (MITM) attack to intercept, modify, and relay SMB traffic, including authentication attempts, without detection.
•	Mitigation: SMB message signing should be enforced (required) for all connections.






