Title: HTB Optimum box writeup
Tags: oscp, htb
Summary: How to gain SYSTEM in two steps, essentials
Date: 2020-09-29 14:30
Status: published

# Enumeration
Scan revealed only one service running on TCP 80:
<pre>
    Nmap 7.80 scan initiated Mon Sep 28 21:06:22 2020 as: nmap -sS -p- -oA enum/nmap-ss-all optimum.htb
    Nmap scan report for optimum.htb (10.10.10.8)
    Host is up (0.062s latency).
    Not shown: 65534 filtered ports
    PORT   STATE SERVICE
    80/tcp open  http
    Nmap done at Mon Sep 28 21:08:35 2020 -- 1 IP address (1 host up) scanned in 132.89 seconds
</pre>
And this is Rejetto HTTP file server, which I was discovered while nmap was doing
his job:
<pre>
    Nmap 7.80 scan initiated Mon Sep 28 21:09:56 2020 as: nmap -sC -A -T4 -p80 -oA enum/nmap-sCAT4-open 10.10.10.8
    Nmap scan report for optimum.htb (10.10.10.8)
    Host is up (0.054s latency).
    PORT   STATE SERVICE VERSION
    80/tcp open  http    HttpFileServer httpd 2.3
    |_http-server-header: HFS 2.3
    |_http-title: HFS /
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   55.54 ms 10.10.14.1
    2   55.40 ms optimum.htb (10.10.10.8)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Mon Sep 28 21:10:08 2020 -- 1 IP address (1 host up) scanned in 13.03 seconds
</pre>
Note that the HFS version is 2.3. This is the only bit of information that we need to get
the user shell.

# Exploitation
I recalled a similar box in PWK labs and immediately tried to search some exploits
for HFS 2.3 and there indeed [some](https://www.exploit-db.com/exploits/39161) that
worked well. Just had to change connection parameters and spin up a web server with
`nc.exe` hosted. The exploit could be unreliable and I've got a shell from the second
try:

![user shell](/cstatic/htb-optimum/user-shell.png)

# Privilege escalation
After a bit of manual enumeration and examining output of `winpeas.bat` I decided to try
some known exploits, since box seemed pretty clean. Quick googling revealed an interesting
one (MS16-032) for which there are a couple of exploits in the EDB, even the one for metasploit.
I grabbed [this one](https://www.exploit-db.com/exploits/39719) to find out that it looks good
but doesn't elevate current shell to SYSTEM. To work around this I've made another meterpreter
executable and changed exploit code a bit to run it instead of `cmd.exe`:

![sploit diff](/cstatic/htb-optimum/39719-diff.png)

And this worked great, spawning SYSTEM meterpreter session:

![root shell](/cstatic/htb-optimum/root-shell.png)
