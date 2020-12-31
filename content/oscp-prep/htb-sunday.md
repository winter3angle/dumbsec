Title: HTB Sunday box writeup
Tags: oscp, htb, finger, sudo, gtfobins, hash cracking, wget
Summary: Struggling with extra-laggy and ancient environment
Date: 2020-10-16 00:15
Status: published

# Enumeration
This box is pretty slow so I had to set `--max-retries` to 1 to accomplish usual
nmap scan:
```text
    Nmap 7.80 scan initiated Thu Oct 15 14:19:09 2020 as: nmap -sS -p- --max-retries=1 -oA enum/nmap-ss-all -v 10.10.10.76
    Increasing send delay for 10.10.10.76 from 0 to 5 due to 17 out of 56 dropped probes since last increase.
    Warning: 10.10.10.76 giving up on port because retransmission cap hit (1).
    Nmap scan report for sunday.htb (10.10.10.76)
    Host is up (0.055s latency).
    Not shown: 34485 filtered ports, 31045 closed ports
    PORT      STATE SERVICE
    79/tcp    open  finger
    111/tcp   open  rpcbind
    22022/tcp open  unknown
    40447/tcp open  unknown
    49886/tcp open  unknown
    Read data files from: /usr/bin/../share/nmap
    Nmap done at Thu Oct 15 14:33:02 2020 -- 1 IP address (1 host up) scanned in 832.69 seconds
```
Took more than ten minutes! Yikes. Detailed:
```text
    Nmap 7.80 scan initiated Thu Oct 15 15:56:48 2020 as: nmap -sC -sV -A -T4 -p79,111,22022,40447,49886 -oA enum/nmap-sCVAT4-open 10.10.10.76
    Nmap scan report for sunday.htb (10.10.10.76)
    Host is up (0.056s latency).
    PORT      STATE SERVICE VERSION
    79/tcp    open  finger?
    |_finger: ERROR: Script execution failed (use -d to debug)
    | fingerprint-strings: 
    |   GenericLines: 
    |_    No one logged on
    111/tcp   open  rpcbind
    22022/tcp open  ssh     SunSSH 1.3 (protocol 2.0)
    | ssh-hostkey: 
    |   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
    |_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
    40447/tcp open  unknown
    49886/tcp open  unknown
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port79-TCP:V=7.80%I=7%D=10/15%Time=5F884717%P=x86_64-pc-linux-gnu%r(Gen
    SF:ericLines,12,"No\x20one\x20logged\x20on\r\n");
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Sun OpenSolaris 2008.11 (94%), Sun Solaris 10 (94%), Sun Solaris 9 or 10, or OpenSolaris 2009.06 snv_111b (94%), Sun Solaris 9 or 10 (SPARC) (92%), Sun Storage 7210 NAS device (92%), Sun Solaris 9 or 10 (92%), Oracle Solaris 11 (91%), Sun Solaris 8 (90%), Sun Solaris 9 (89%), Sun Solaris 8 (SPARC) (89%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    TRACEROUTE (using port 111/tcp)
    HOP RTT      ADDRESS
    1   55.44 ms 10.10.14.1
    2   56.18 ms sunday.htb (10.10.10.76)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Thu Oct 15 15:57:27 2020 -- 1 IP address (1 host up) scanned in 39.71 seconds
```
Well well there's SSH listening on unusual port and a finger daemon that
potentially allows to enumerate local users. I nc'd to high ports and it looks
like there's nothing useful in there. `rpcinfo` revealed nothing. Let's
enumerate finger. I was already a bit familiar with finger protocol in general
so just tried some manual enum first like `finger @10.10.10.76`. Turned out
there's no one logged on machine at the time. `finger user@10.10.10.76`
revealed a couple of standard users and suggested that the box is running 
`SunOS 4.x`. I grabbed fingerd enumeration
[script](https://github.com/pentestmonkey/finger-user-enum) from pentestermonkey
and combined with usernames list from notorious SecLists repository it provided
me with some interesting results:
```text
    root@10.10.10.76:	    root	Super-User	pts/3		sunday	
    access@10.10.10.76:	    access	No	Access	User	
    sammy@10.10.10.76:	    sammy	console	
    sunny@10.10.10.76:	    sunny	pts/3		10.10.14.4	
    network@10.10.10.76:	Login	Name	TTY	Idle	When	Wherelisten	Network	Admin	
    Admin@10.10.10.76:	    Admin
    films+pic+galeries@10.10.10.76:	Login	Name	TTY	Idle	When	Wherefilms+pic+galeries	???
    printer@10.10.10.76:	Login	Name	TTY	Idle	When	Wherelp	Line	Printer	Admin	
    daemon@10.10.10.76:	    daemon	???	
    Sammy@10.10.10.76:	    Login	Name	TTY	Idle	When	Wheresammy	sammy	console	
    line@10.10.10.76:	    Login	Name	TTY	Idle	When	Wherelp	Line	Printer	Admin	
    anonymous@10.10.10.76:	Login	Name	TTY	Idle	When	Wherenobody	NFS	Anonymous	Access	
```
Results were a bit clumsy so I changed them a bit by hand. Notice two
interesting names there - `sammy` and `sunny`, looks like regular users. I also
checked them out manually using `finger` command to ensure there's no glitches.

# Exploitation
There aren't much exploitable services running on this box so I tried to
bruteforce passwords and after a while sunny's password was revealed in rockyou:

![sunny pwd](/cstatic/htb-sunday/sunny-password.png)

Sunny could run `/root/troll` via sudo, but it doesn't look exploitable at a
glance, he's even not able to stat that file and read perms. 
Also sunny has access to unusual `/backup` dir with a file that claimed to be
backup of `/etc/shadow`:
```text
sunny@sunday:~$ cat /backup/shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```
Sammy's password found in rockyou and it is `cooldude!`:

![sammy pwd](/cstatic/htb-sunday/sammy-cracked.png)

This allows to SSH to the host and acquire user flag:

![sammy shell](/cstatic/htb-sunday/user-shell.png)

# Privilege escalation
Turned out sammy could run `wget` as root via sudo. This allows us to replace
arbitrary suid executable with our own using the `-O` option. So I just
downloaded my reverse shell over the `/usr/bin/at` and got a root session:

![root shell](/cstatic/htb-sunday/root-shell.png)

I didn't bother upgrading to interactive shell because the box was damn laggy 
and drived me nuts with constant freezes and glitches.
