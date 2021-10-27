# Network Security VAPT Checklist/Methodology 

## 1. Identify live hosts

* Ping
```bash
ping $IP
```
* Nmap
```bash
nmap -sn $IP/24

nmap -sP $IP-100
```
* Hping
```bash
hping3 -A $IP
```

## 2. Identify OS type

* Nmap
* Xprobe2
* Banner grabbing using nc(netcat), telnet

## 3. Port scan

* Nmap full SYN scan with verbose mode and service detection and disabling ping scan. Export normal and greppable output for future use.
```bash
nmap -Pn -p- -sV $IP -v -sS -oG nmap_grepable_SYN -oN nmap_normal_SYN
```

* Nmap top 1000 UDP scan with verbose mode and service detection and disabling ping scan. Export normal and greppable output for future use.
```bash
nmap -Pn -top-ports=1000 -sV $IP -v -sS -oG nmap_grepable_UDP -oN nmap_normal_UDP
```

* Nmap Full port scan identifying any weak algos and ciphers in SSH and SSL. Export normal and greppable output for future use.
```bash
nmap -Pn -A -T4 -vv --script ssh2-enum-algos --script ssl-enum-ciphers <Target List>
```

## 4. Use Nessus

Following things to be looked in the Nessus policy before scan is run:

* DoS disabled
* Enable TCP and UDP scan
* Plugins are updated as per defined plugin policy

## 5. Use NMAP scanner on specific open ports

For example port 22 (SSH) is open and you want to run all scripts pertaining to SSH then use below command:
```bash
nmap -Pn -sS -p22 --script ssh* -v $IP
```

## 6. Audit SSL (Use testssl.sh or TestSSLMaster.exe for SSL related vulnerability mentioned here for quicker results)

* Use openssl, sslyze tools to find below issues within SSL.
* Self-signed certificate
* SSL version 2 and 3 detection
* Weak hashing algorithm
* Use of RC4 and CBC ciphers
* Logjam issue
* Sweet32 issue
* Certificate expiry
* Openssl ChangeCipherSec issue
* POODLE vulnerability
* Openssl heartbleed issue
* Lucky 13 and Beast Issue

## 7. Check for default passwords in server/device/service documentation

When during your port scan or VA you found some services running on the server for example: `cisco, brocade fabric OS, sonic firewall, apache tomcat manager`. Then for these services Google what are the default configuration administrative username and password. Try those in your login and check your luck.

## 8. Hunting some common ports:

### 1. DNS (53) UDP:

* Examine domain name system (DNS) using `dnsenum, nslookup, dig and fierce tool`.
* Check for zone transfer.
* Bruteforce subdomain using fierce tool.
* Run all nmap scripts using following command:
```bash
nmap -Pn -sU -p53 $IP --script dns* -v 
```
* Banner grabbing and finding publicly known exploits.
* Check for DNS amplification attack.

### 2. SMTP (25) TCP: 

* Check for SMTP open relay.
* Check for email spoofing.
* Check for username enumeration using VRFY command.
* Banner grabbing and finding publicly known exploits.
* Send modified cryptors and check if SMTP gateway is enable to detect and block it?
* Run all nmap script using following command:
```bash
nmap -Pn -sS -p25 $IP --script smtp* 
```
### 3. SNMP (161) UDP:

* Check for default community strings ‘public’ & ‘private’ using `snmpwalk` and `snmpenum.pl` script.
* Banner grabbing and finding publicly known exploits
* Perform MIG enumeration.
```
- .1.3.6.1.2.1.1.5 Hostnames
- .1.3.6.1.4.1.77.1.4.2 Domain Name
- .1.3.6.1.4.1.77.1.2.25 Usernames
- .1.3.6.1.4.1.77.1.2.3.1.1 Running Services
- .1.3.6.1.4.1.77.1.2.27 Share Information
```

### 4. SSH (22) TCP:

* Banner grabbing and finding publicly known exploits.
* Check if that supports `sshv1` or not.
* Bruteforce password using `hydra` and `medusa`.
* Check if it supports weak CBC ciphers and hmac algorithms using `ssh2-enum-algos.nse` nmap script.
* Run all nmap scripts using following command:
```bash
nmap -Pn -sS -p22 $IP --script ssh* -v 
```

### 5. Cisco VPN (500) UDP:

* Check for aggressive and main mode enable using `ikescan` tool.
* Enumeration using `ikeprobe` tool
* Check for VPN group and try to crack PSK in order to get credentials to login into the VPN service through web panel.

### 6. SMB (445,137,139) TCP:

* Check SAMBA service using metasploit use `auxiliary/scanner/smb/smb_version`
* Get reverse shell using meterpreter reverse tcp module.
* Check for SMB related vulnerability using `smb-check-vulns` nmap script.
* Reference: [https://myexploit.wordpress.com/control-smb-445-137-139/](https://myexploit.wordpress.com/control-smb-445-137-139/)

### 7. FTP (21) TCP:

* Run all nmap script using following command:
```bash
nmap -Pn -sS -p21 $IP --script ftp* -v
```
* Check for cleartext password submission for ftp login
* Check for anonymous access using username and password as `anonymous:anonymous`
* Banner grabbing and finding publicly known exploits.
* Bruteforce FTP password using `hydra` and `medusa`

### 8. Telnet (23) TCP:

* Banner grabbing and finding publicly known exploits.
* Bruteforce telnet password using `hydra` and `medusa`
* Run following nmap scripts:
``` bash
nmap -p23 $IP --script telnet-brute.nse

nmap -p23 $IP --script telnet-encryption.nse

nmap -p23 $IP --script telnet-ntlm-info.nse

```
### 9. TFTP (69) UDP:

* TFTP Enumeration:
```bash
tftp $IP PUT local_file

tftp $IP GET conf.txt (or other files)

tftp – i GET /etc/passwd (old Solaris)
```
* Bruteforce TFTP using TFTP bruteforcer tool
* Banner grabbing and finding publicly known exploits.
* Run nmap script:
```bash
nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=customlist.txt $IP
```

### 10. RPC (111) TCP/UDP:

* Banner grabbing and finding publicly known exploits.
* Run following nmap scripts

	- bitcoinrpc-info.nse
	- metasploit-msgrpc-brute.nse
	- metasploit-xmlrpc-brute.nse 
	- msrpc-enum.nse
	- nessus-xmlrpc-brute.nse 
	- rpcap-brute.nse 
	- rpcap-info.nse  
	- rpc-grind.nse 
	- rpcinfo.nse  
	- xmlrpc-methods.nse

* Perform RPC enumeration using `rcpinfo` tool
* Check for the NFS folders so that data could be exported using `showmount -e` command.

### 11. NTP (123) UDP:

* Perform NTP enumeration using below commands:
```bash
ntpdc -c monlist $IP

ntpdc -c sysinfo $IP
```
* Run all nmap scripts:
```bash
nmap -Pn -sS -p21 $IP --script ntp* -v
```
### 12. HTTP/HTTPs (443,80,8080,8443) TCP:

* Banner grabbing using burp response.
* Run `Nikto` and `dirb`
* Banner grabbing and finding publicly known exploits.

### 13. SQL Server (1433,1434, 3306) TCP:

* Banner grabbing and finding publicly known exploits.
* Bruteforce and perform other operation using following tools:

	- Piggy
	- SQLping
	- SQLpoke
	- SQLrecon
	- SQLver

* Run following nmap scripts:

	- ms-sql-brute.nse
	- ms-sql-config.nse
	- ms-sql-dac.nse
	- ms-sql-dump-hashes.nse
	- ms-sql-empty-password.nse
	- ms-sql-hasdbaccess.nse
	- ms-sql-info.nse
	- ms-sql-ntlm-info.nse
	- ms-sql-query.nse
	- ms-sql-tables.nse
	- ms-sql-xp-cmdshell.nse
	- pgsql-brute.nse

* For MySQL default user is `root` and by default it has no password.

### 14. RDP (3389) TCP:

* Perform enumeration via connecting and checking login screen. Gather all active user’s name and domain/group name.
* Perform RDP cryptography check using `RDP-sec-check.pl` script.
* Run following nmap script:
```bash
nmap -p 3389 --script rdp-enum-encryption.nse $IP

nmap -p 3389 --script rdp-vuln-ms12-020.nse $IP
```

### 15. Oracle (1521) TCP:

* Enumeration using following tools:
```bash
tnsver [host] [port]

tnscmd
```
```bash
perl tnscmd.pl -h $IP

perl tnscmd.pl version -h $IP

perl tnscmd.pl status -h $IP
```
* Enumeration & Bruteforce using below nmap scripts:
```bash
nmap -p 1521-1560 $IP --script oracle-brute.nse

namp -p 1521-1560 $IP oracle-brute-stealth.nse

namp -p 1521-1560 $IP oracle-enum-users.nse

namp -p 1521-1560 $IP oracle-sid-brute.nse

namp -p 1521-1560 $IP oracle-tns-version.nse
```


### Disclaimer: 

The contents stated above is a summarised common methodology that is followed during VA-PT. The author does not claim any rights on the content. The commands and tools used can be found in many guides and blogs. The main purpose of this document is to make aware or facilitate readers of common methodology to be followed during VA-PT. However, the author is not responsible for any misuse of any commands mentioned above. The scans / VAPT activity is to be conducted only after the consent of the Application owner/ Server Owner.
