### Network Topology

The following machines were identified on the network:
- Hypervisor / Host Machine (Not a VM)
  - **Operating System**: Microsoft Windows
  - **Purpose**: Hypervisor / Gateway
  - **IP Address**: 192.168.1.1
- ELK
  - **Operating System**: Linux
  - **Purpose**: Elasticsearch, Logstash, Kibana Server
  - **IP Address**: 192.168.1.100
- Capstone
  - **Operating System**: Linux
  - **Purpose**: Basic HTTP Server (this is a red herring)
  - **IP Address**: 192.168.1.105
- Target 1
  - **Operating System**: Linux
  - **Purpose**: HTTP Server (also wordpress site)
  - **IP Address**: 192.168.1.110
- Target 2
  - **Operating System**: Linux
  - **Purpose**: HTTP Server
  - **IP Address**: 192.168.1.115

### Description of Targets

The target of this attack was: `Target 1` (`192.168.1.110`).

Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are
possible ports of entry for attackers. As such, the following alerts have been
implemented:

* [Excessive HTTP Errors](#excessive-http-errors)
* [HTTP Request Size Monitor](#http-request-size-monitor)
* [CPU Usage Monitor](#cpu-usage-monitor)

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### Excessive HTTP Errors
Alert 1 is implemented as follows:
  - **Metric**: `http.response.status_code` > 400
  - **Threshold**: 5 in last 5 minutes
  - **Vulnerability Mitigated**: By creating an alert, the security team can identify attacks & block the ip, change the password, & close or filter the port 22
  - **Reliability**: No, this alert does not generate a lot of false positives. This alert is highly reliable in identifying brute force attacks.

#### HTTP Request Size Monitor
Alert 2 is implemented as follows:
  - **Metric**: `http.request.bytes`
  - **Threshold**: 3500 in last 1 minute
  - **Vulnerability Mitigated**: By controlling the number of http request size through a filter it protects against DDOS attacks
  - **Reliability**: No, this alert doesn't generate a lot of false positives bc it is reliable.
#### CPU Usage Monitor
Alert 3 is implemented as follows:
  - **Metric**: `system.process.cpu.total.pct`
  - **Threshold**: 0.5 in last 5 minutes
  - **Vulnerability Mitigated**: By controlling the CPU usuage percentage at 50%, it will trigger a memory dump of stored information is generated
  - **Reliability**: Yes this alert can generate a lot of false positives bc the cpu can spike even if there is not an attack.

### Suggestions for Going Further (Optional)
- Each alert above pertains to a specific vulnerability/exploit. Recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identified by the alerts above, suggest a patch. E.g., implementing a blocklist is an effective tactic against brute-force attacks. It is not necessary to explain _how_ to implement each patch.

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:
- Vulnerability 1- Excessive HTTP Errors
  - **Patch**: Require a stronger password policy in the user account settings. Update the account password policy in Windows group policy through /etc/security/pwquality.conf & through /etc/security/pwquality.conf in Linux
  -  **Why It Works**: By having a strong password it will be almost impossible to guess or brute force
  
- Vulnerability 2 - HTTP Request Size Monitor
  - **Patch**: Use advanced intrusion prevention and threat management systems, which combine firewalls, VPN, anti-spam, content filtering, load balancing, and other layers of DDoS defense techniques. Together they enable constant and consistent network protection to prevent a DDoS attack from happening. This includes everything from identifying possible traffic inconsistencies with the highest level of precision in blocking the attack
  - **Why It Works**: Given the complexity of DDoS attacks, there’s hardly a way to defend against them without appropriate systems to identify anomalies in traffic and provide instant response. Backed by secure infrastructure and a battle-plan, such systems can minimize the threat.
 
- Vulnerability 3 - CPU Usage Monitor
  - **Patch**: Use Host Instrusion Prevention System to identify DOS attack
  - **Why It Works**: This stops malware by monitoring the behavior of code

# Network Forensic Analysis Report

## Time Thieves
You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site?
  - `frank-n-ted.com`
2. What is the IP address of the Domain Controller (DC) of the AD network?
  - `10.6.12.12` (`Frank-n-Ted-DC.frank-n-ted.com`)
3. What is the name of the malware downloaded to the 10.6.12.203 machine?
  - `june11.dll`
5. What kind of malware is this classified as?
  - Trojan

---

## Vulnerable Windows Machine

1. Find the following information about the infected Windows machine:
    - Host name: `Rotterdam-PC.mindhammer.net`
    - IP address: `172.16.4.205`
    - MAC address: `00:59:07:b0:63:a4`

2. What is the username of the Windows user whose computer is infected?
  - `matthijs.devries`

3. What are the IP addresses used in the actual infection traffic?
  - Initial HTTP Request made from `172.16.4.205` to `205.185.216.10`
  - This request downloaded malware to the machine at `172.16.4.205`

4. As a bonus, retrieve the desktop background of the Windows host.

---
## Illegal Downloads

1. Find the following information about the machine with IP address `10.0.0.201`:
    - MAC address: `00:16:17:18:66:c8`
    - Windows username: `elmer.blanco`
    - OS version: `Windows 10 NT 10.0`

2. Which torrent file did the user download?
    - `Betty_Boop_Rhythm_on_the_Reservation.avi`

