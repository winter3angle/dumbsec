Title: HTB Lame box writeup
Tags: oscp, htb
Summary: Continue writeups for retired OSCP alike machines
Date: 2020-09-03 15:00
Status: published

# Enumeration
nmap sS full TCP range:
<pre>
    Nmap 7.80 scan initiated Thu Sep  3 11:02:52 2020 as: nmap -sS -p- -oA enum/nmap-ss-all lame.htb
    Nmap scan report for lame.htb (10.10.10.3)
    Host is up (0.063s latency).
    Not shown: 65530 filtered ports
    PORT     STATE SERVICE
    21/tcp   open  ftp
    22/tcp   open  ssh
    139/tcp  open  netbios-ssn
    445/tcp  open  microsoft-ds
    3632/tcp open  distccd
    Nmap done at Thu Sep  3 11:04:46 2020 -- 1 IP address (1 host up) scanned in 114.71 seconds
</pre>
And scripted scan for open ones:
<pre>
    Nmap 7.80 scan initiated Thu Sep  3 11:05:30 2020 as: nmap -sC -A -T4 -p21,22,139,445,3632 -oA enum/nmap-scripted-open lame.htb
    Nmap scan report for lame.htb (10.10.10.3)
    Host is up (0.060s latency).
    PORT     STATE SERVICE     VERSION
    21/tcp   open  ftp         vsftpd 2.3.4
    |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to 10.10.14.13
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      vsFTPd 2.3.4 - secure, fast, stable
    |_End of status
    22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
    | ssh-hostkey: 
    |   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
    |_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
    139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
    3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%), Linux 2.6.18 (ClarkConnect 4.3 Enterprise Edition) (92%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    Host script results:
    |_clock-skew: mean: -3d00h53m34s, deviation: 2h49m44s, median: -3d02h53m36s
    | smb-os-discovery: 
    |   OS: Unix (Samba 3.0.20-Debian)
    |   Computer name: lame
    |   NetBIOS computer name: 
    |   Domain name: hackthebox.gr
    |   FQDN: lame.hackthebox.gr
    |_  System time: 2020-08-31T04:12:13-04:00
    | smb-security-mode: 
    |   account_used: <blank>
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    |_smb2-time: Protocol negotiation failed (SMB2)
    TRACEROUTE (using port 445/tcp)
    HOP RTT      ADDRESS
    1   59.71 ms 10.10.14.1
    2   59.85 ms lame.htb (10.10.10.3)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Thu Sep  3 11:06:26 2020 -- 1 IP address (1 host up) scanned in 56.85 seconds
</pre>

FTP looks interesting and even allows anonymous login, but there aren't enough permissions to upload files
and seems that there aren't any files available for listing. Moreover, this version of vsFTPd is known to
be backdoored, allowing access to OS shell for anyone capable of the trick. Unfortunately it doesn't work,
it might be that backdoor port is behind the firewall or the application was patched or author just 
tricked us using phony version number.

Another interesting service is `distccd` which had an RCE bug a long long time ago (CVE-2004 yay). There is an
exploit in MSF, but I wanted to avoid it and found [this](https://gist.githubusercontent.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855/raw/48ab4eb0bd69cac67bc97fbe182e39e5ded99f9f/distccd_rce_CVE-2004-2687.py) 
after a bit of googling.

# Exploitation
Exploit mentioned above worked flawlessly and provides a way for unprivileged shell:

![unpriv shell](/cstatic/htb-lame/unpriv-shell.png)

I was trying to run it with python 3 and have faced an error, unexpectedly wasted a bit of time for this acting stupid.

# Privilege escalation
Naive things like world-writable `/etc/passwd` or `sudo` ALL w/o password didn't work for the `daemon` user
so I ran linpeas and got a super-useful hint - we can run `nmap` which has suid bit set and owned by root:

![nmap suid](/cstatic/htb-lame/nmap-suid.png)

This is an interesting trick, that I didn't know before. Nmap could be run in interactive mode and user is
capable of dropping back to the shell, something like `:sh` vim command. This elevates our privileges to root
in a very straightforward manner:

![root shell](/cstatic/htb-lame/root-shell.png)

Actually this box could be pwned in a couple of ways, since it also runs quite dated version of smbd which is
vulnerable to CVE-2007-2447 and there's an MSF exploit for that, but this would be really kind of lame
since it will give us direct-to-root access.
