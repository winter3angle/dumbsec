Title: HTB Bastard box writeup
Tags: oscp, htb, drupal, drupalgeddon
Summary: Presenting newb way to privesc
Date: 2020-09-30 17:00
Status: published

# Enumeration
Traditional full TCP range scan:
```text
    Nmap 7.80 scan initiated Tue Sep 29 13:05:41 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.9
    Nmap scan report for bastard.htb (10.10.10.9)
    Host is up (0.068s latency).
    Not shown: 65532 filtered ports
    PORT      STATE SERVICE
    80/tcp    open  http
    135/tcp   open  msrpc
    49154/tcp open  unknown
    Nmap done at Tue Sep 29 13:08:17 2020 -- 1 IP address (1 host up) scanned in 155.78 seconds
```
As always followed by general scripted scan:
```text
    Nmap 7.80 scan initiated Tue Sep 29 13:54:54 2020 as: nmap -sC -A -T4 -p80,135,49153 -oA enum/nmap-sCAT4-open 10.10.10.9
    Nmap scan report for bastard.htb (10.10.10.9)
    Host is up (0.057s latency).
    PORT      STATE    SERVICE VERSION
    80/tcp    open     http    Microsoft IIS httpd 7.5
    |_http-generator: Drupal 7 (http://drupal.org)
    | http-methods: 
    |_  Potentially risky methods: TRACE
    | http-robots.txt: 36 disallowed entries (15 shown)
    | /includes/ /misc/ /modules/ /profiles/ /scripts/ 
    | /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
    | /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
    |_/LICENSE.txt /MAINTAINERS.txt
    |_http-server-header: Microsoft-IIS/7.5
    |_http-title: Welcome to 10.10.10.9 | 10.10.10.9
    135/tcp   open     msrpc   Microsoft Windows RPC
    49153/tcp filtered unknown
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose|phone|specialized
    Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
    OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
    Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    TRACEROUTE (using port 135/tcp)
    HOP RTT      ADDRESS
    1   56.58 ms 10.10.14.1
    2   57.44 ms bastard.htb (10.10.10.9)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Tue Sep 29 13:55:18 2020 -- 1 IP address (1 host up) scanned in 24.32 seconds
```
Some available entries from robots.txt:
```text
    Starting Parsero v0.75 (https://github.com/behindthefirewalls/Parsero) at 09/30/20 11:50:30
    Parsero scan report for 10.10.10.9
    http://10.10.10.9/?q=comment/reply/ 200 OK
    http://10.10.10.9/?q=user/register/ 200 OK
    http://10.10.10.9/user/login/ 200 OK
    http://10.10.10.9/?q=user/login/ 200 OK
    http://10.10.10.9/INSTALL.mysql.txt 200 OK
    http://10.10.10.9/INSTALL.pgsql.txt 200 OK
    http://10.10.10.9/filter/tips/ 200 OK
    http://10.10.10.9/?q=filter/tips/ 200 OK
    http://10.10.10.9/install.php 200 OK
    http://10.10.10.9/INSTALL.txt 200 OK
    http://10.10.10.9/xmlrpc.php 200 OK
    http://10.10.10.9/LICENSE.txt 200 OK
    http://10.10.10.9/?q=user/password/ 200 OK
    http://10.10.10.9/user/password/ 200 OK
    http://10.10.10.9/user/register/ 200 OK
    http://10.10.10.9/UPGRADE.txt 200 OK
    http://10.10.10.9/CHANGELOG.txt 200 OK
    http://10.10.10.9/MAINTAINERS.txt 200 OK
    http://10.10.10.9/INSTALL.sqlite.txt 200 OK
```
I'm no expert in Drupal by any means, but this list doesn't look unusual at a
glance. Some useful hint is that according to `CHANGELOG.txt` Drupal version is
`7.54`, which is vulnerable to notorious Drupalgeddon RCE vuln. It might require
valid credentials though. 

# Exploitation
So I spent some time trying to enumerate some more, like spin up gobuster or fool
around with (likely) RPC ports, but later I tried to use some drupalgeddon exploits
and [this one](https://www.exploit-db.com/exploits/44449) worked great providing
me with the shell. Turned out that no creds required for this deployment. I just 
uploaded meterpreter shell there, since drupalgeddon shell seems laggy, as the 
web application itself, and got the user flag as IUSR:

![user shell](/cstatic/htb-bastard/user-shell.png)

# Privilege escalation
Dumped database creds, as part of post-exploit enum:
```php
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'root',
      'password' => 'mysql123!root',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```
An easy, script-kiddo way to privesc: run `multi/recon/local_exploit_suggester`
and try some of the exploits. Find out that `exploit/windows/local/ms16_014_wmi_recv_notif`
works and spawns SYSTEM session:

![system shell](/cstatic/htb-bastard/root-shell.png)

Definitely should attend some privesc courses to feel more comfortable with PE.
