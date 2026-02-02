# snort-project-1
LAB ENVIRONMENT
==============

Attacker Machine
----------------
Parrot OS
Linux Mint

Target Machine
--------------
Kali Linux

Tool Used
---------
Snort (Network Intrusion Detection System)

Network Type
------------
Local Network (Host-only / Internal LAN)


Snort Configuration
-------------------
Snort was configured with custom rules to detect basic network activities such as ICMP, HTTP, DNS, Telnet, and port scanning. 
The goal was to understand traffic visibility and basic intrusion detection.


PROJECT 1 – BASIC DETECTION AND VISIBILITY
=========================================

1. ICMP Ping Detection
---------------------
Snort Rule:
alert icmp any any -> $HOME_NET any (msg:"Ping is detected"; sid:1000001; rev:1;)

Attacker Command:
ping <KALI_IP>

Expected Result:
Snort generates an alert when ICMP echo requests are detected.


2. HTTP Traffic Detection
------------------------
Snort Rule:
alert tcp any any -> $HOME_NET [80,8080] (msg:"HTTP Traffic detected"; sid:1000002; rev:1;)

Attacker Command:
curl http://<KALI_IP>

Expected Result:
Snort alerts on HTTP traffic targeting web ports.


3. DNS Query Detection
---------------------
Snort Rule:
alert udp any any -> any 53 (msg:"DNS Query Detected"; sid:1000003; rev:1;)

Attacker Command:
dig google.com @<KALI_IP>

Expected Result:
Snort detects DNS queries sent over UDP port 53.


4. Telnet Detection
------------------
Snort Rule:
alert tcp any any -> any 23 (msg:"TELNET Attempt Detected"; sid:1000005; rev:1;)

Attacker Command:
telnet <KALI_IP>

Expected Result:
Snort raises an alert for Telnet connection attempts, indicating insecure remote access usage.


5. Port Scan Detection
---------------------
Snort Rule:
alert tcp any any -> $HOME_NET any (msg:"Stealth Scan Detected"; flags:S; detection_filter:track by_src, count 10, seconds 5; sid:1000009; rev:1;)

Attacker Command:
nmap -sS <KALI_IP>

Expected Result:
Snort detects multiple SYN packets in a short time window, indicating a stealth port scan.


Summary
-------
This project demonstrates basic Snort detection capabilities by identifying common network activities such as ping, web access, DNS queries, Telnet usage, and port scanning. 
These simple rules help build visibility into network traffic and form the foundation for more advanced intrusion detection techniques.
