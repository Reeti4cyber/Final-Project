# Network Forensic Analysis Report

## Time Thieves
Inspect the traffic captured,  their IP addresses were somewhere in the range 10.6.12.0/24.

1. What is the domain name of the users' custom site?
  - `frank-n-ted.com`
  
  ![domainname](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/TimethievesDNS.png)
  
  
2. What is the IP address of the Domain Controller (DC) of the AD network?
  - `10.6.12.12` (`Frank-n-Ted-DC.frank-n-ted.com`)
3. What is the name of the malware downloaded to the 10.6.12.203 machine?
  - `june11.dll`

![malware](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/TimeThievesGET.png)

Exported the file to  Kali machine's desktop.

- ` Clicked on the packet that displays malware  --> File --> ExportObjects --> HTTP--> june11.dll `

 ![exportmalware](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/JuneDLL2.png)
 
  ![exportmalware](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/JuneDLL1.png)
 
 

4. Uploaded the file to VirusTotal.com.

 ![virustotal](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/VirusTotal.png)

6. What kind of malware is this classified as?

  - Trojan

---

## Vulnerable Windows Machine

- Machines in the network live in the range 172.16.4.0/24.
- The domain mind-hammer.net is associated with the infected computer.
- The DC for this network lives at 172.16.4.4 and is named Mind-Hammer-DC.
- The network has standard gateway and broadcast addresses.

1. Find the following information about the infected Windows machine:
    - Host name: `Rotterdam-PC.mindhammer.net`
    - IP address: `172.16.4.205`
    - MAC address: `00:59:07:b0:63:a4`
     
     ![rotterdam](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/VWM1.png)
     
     ![rotterdam](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/VWM2.png)
     

2. What is the username of the Windows user whose computer is infected?

  - ``Kerberos.CNameString && ip.src==172.16.4.205``
  
  - `matthijs.devries`

 ![username](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/UsernameVWM.png)

3. What are the IP addresses used in the actual infection traffic?
  - Initial HTTP Request made from `172.16.4.205` to `205.185.216.10`
  - This request downloaded malware to the machine at `172.16.4.205`


---
## Illegal Downloads

1. Find the following information about the machine with IP address `10.0.0.201`:
    - MAC address: `00:16:17:18:66:c8`
    - Windows username: `elmer.blanco`
    - OS version: `Windows 10 NT 10.0`
 
 ![usernameBlanco](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/UsernameBlanco.png)


2. Which torrent file did the user download?
    - `Betty_Boop_Rhythm_on_the_Reservation.avi`

![torrent](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/TorrentBlanco.png)


