Title: HTB Blue box writeup
Tags: oscp, htb, smb, eternalblue
Summary: Laid-back windows box
Date: 2020-09-28 02:00
Status: published

# Enumeration
Spin up full TCP range scan:
```text
    Nmap 7.80 scan initiated Sun Sep 27 21:15:26 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.40
    Nmap scan report for blue.htb (10.10.10.40)
    Host is up (0.051s latency).
    Not shown: 65526 closed ports
    PORT      STATE SERVICE
    135/tcp   open  msrpc
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    49152/tcp open  unknown
    49153/tcp open  unknown
    49154/tcp open  unknown
    49155/tcp open  unknown
    49156/tcp open  unknown
    49157/tcp open  unknown
    Nmap done at Sun Sep 27 21:16:25 2020 -- 1 IP address (1 host up) scanned in 59.37 seconds
```
And follow by scripted scan of open ports:
```text
    Nmap 7.80 scan initiated Sun Sep 27 21:18:44 2020 as: nmap -sC -A -T4 -p135,139,445,49152,49153,49154,49155,49156,49157 -oA enum/nmap-sCAT4-open 10.10.10.40
    Nmap scan report for blue.htb (10.10.10.40)
    Host is up (0.051s latency).
    PORT      STATE SERVICE      VERSION
    135/tcp   open  msrpc        Microsoft Windows RPC
    139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
    445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
    49152/tcp open  msrpc        Microsoft Windows RPC
    49153/tcp open  msrpc        Microsoft Windows RPC
    49154/tcp open  msrpc        Microsoft Windows RPC
    49155/tcp open  msrpc        Microsoft Windows RPC
    49156/tcp open  msrpc        Microsoft Windows RPC
    49157/tcp open  msrpc        Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 7 Ultimate SP1 or Windows 8.1 Update 1 (96%), Microsoft Windows 8.1 (96%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
    Host script results:
    |_clock-skew: mean: -19m58s, deviation: 34m36s, median: 0s
    | smb-os-discovery: 
    |   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
    |   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
    |   Computer name: haris-PC
    |   NetBIOS computer name: HARIS-PC\x00
    |   Workgroup: WORKGROUP\x00
    |_  System time: 2020-09-27T22:19:52+01:00
    | smb-security-mode: 
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    | smb2-security-mode: 
    |   2.02: 
    |_    Message signing enabled but not required
    | smb2-time: 
    |   date: 2020-09-27T21:19:54
    |_  start_date: 2020-09-27T21:08:18
    TRACEROUTE (using port 135/tcp)
    HOP RTT      ADDRESS
    1   50.57 ms 10.10.14.1
    2   50.64 ms blue.htb (10.10.10.40)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Sun Sep 27 21:19:58 2020 -- 1 IP address (1 host up) scanned in 74.00 seconds
```
Results of smb-protocols nmap script:
```text
    Nmap 7.80 scan initiated Sun Sep 27 21:24:52 2020 as: nmap -sC -p139,445 --script=smb-protocols -oA enum/nmap-smb-protocols 10.10.10.40
    Nmap scan report for blue.htb (10.10.10.40)
    Host is up (0.100s latency).
    PORT    STATE SERVICE
    139/tcp open  netbios-ssn
    445/tcp open  microsoft-ds
    Host script results:
    | smb-protocols: 
    |   dialects: 
    |     NT LM 0.12 (SMBv1) [dangerous, but default]
    |     2.02
    |_    2.10
    Nmap done at Sun Sep 27 21:25:00 2020 -- 1 IP address (1 host up) scanned in 7.38 seconds
```

# Exploitation
Almost from the beginning I was suspecting presence of the EternalBlue/Romance/Champion vulns.
This assumption was right and [this project](https://github.com/REPTILEHAUS/Eternal-Blue) made it
quite simple to exploit and acquire SYSTEM shell directly:

![root shell](/cstatic/htb-blue/root-shell.png)

Guess it would be good to use MSF against SMB targets in the exam. This box was quite straightforward to
me and it was pwned in one step once some initial info was gathered.
