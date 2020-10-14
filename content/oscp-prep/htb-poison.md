Title: HTB Poison box writeup
Tags: oscp, htb
Summary: Instant user access and unusual process below the radar of linPEAS
Date: 2020-10-14 17:00
Status: published

# Enumeration
Only two network services listening on TCP ports:
<pre>
    Nmap 7.80 scan initiated Wed Oct 14 14:09:24 2020 as: nmap -sS -p- -oA enum/nmap-ss-all -v -v 10.10.10.84
    Nmap scan report for poison.htb (10.10.10.84)
    Host is up, received echo-reply ttl 63 (0.057s latency).
    Scanned at 2020-10-14 14:09:24 MSK for 401s
    Not shown: 65533 closed ports
    Reason: 65533 resets
    PORT   STATE SERVICE REASON
    22/tcp open  ssh     syn-ack ttl 63
    80/tcp open  http    syn-ack ttl 63
    Nmap done at Wed Oct 14 14:16:05 2020 -- 1 IP address (1 host up) scanned in 400.80 seconds
</pre>
Detailed:
<pre>
    Nmap 7.80 scan initiated Wed Oct 14 14:21:22 2020 as: nmap -sC -sV -A -T4 -p22,80 -oA enum/nmap-sCVAT4-open 10.10.10.84
    Nmap scan report for poison.htb (10.10.10.84)
    Host is up (0.061s latency).
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
    | ssh-hostkey: 
    |   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
    |   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
    |_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
    |_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
    |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: FreeBSD 11.0-RELEASE - 12.0-CURRENT (97%), FreeBSD 11.0-STABLE (95%), FreeBSD 11.0-CURRENT (94%), FreeBSD 11.0-RELEASE (94%), FreeBSD 9.1-STABLE (92%), FreeBSD 7.0-RELEASE (91%), FreeBSD 9 (90%), FreeBSD 12.0-CURRENT (90%), Sony Playstation 4 or FreeBSD 10.2-RELEASE (90%), FreeBSD 9.1-RELEASE (89%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   58.53 ms 10.10.14.1
    2   60.23 ms poison.htb (10.10.10.84)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Wed Oct 14 14:21:35 2020 -- 1 IP address (1 host up) scanned in 13.59 seconds
</pre>

Web app allows to browse some file contents, for example if we type in
`listfiles.php` it will show us some intereresting files:

![list files](/cstatic/htb-poison/listfiles.png)

Content of `pwdbackup.txt` as follows:
<pre>
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. 

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU 
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS 
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW 
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs 
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy 
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G 
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw 
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa 
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k 
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk 
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT 
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz 
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW 
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO 
Ukd4RVdub3dPVU5uUFQwSwo= 
</pre>

`browse.php` is also vulnerable to trivial path traversal:

![path traversal](/cstatic/htb-poison/traversal.png)

Here's content of passwd:
<pre>
    # $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $ 
    root:*:0:0:Charlie &:/root:/bin/csh
    toor:*:0:0:Bourne-again Superuser:/root: 
    daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
    operator:*:2:5:System &:/:/usr/sbin/nologin
    bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
    tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
    kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
    games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
    news:*:8:8:News Subsystem:/:/usr/sbin/nologin
    man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
    sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
    smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
    mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
    bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
    unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
    proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
    _pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
    _dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
    uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
    pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
    auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
    www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
    _ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
    hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
    nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
    _tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
    messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
    avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
    cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
    charix:*:1001:1001:charix:/home/charix:/bin/csh 
</pre>

`pwdbackup.txt` seems to be just a text that was base64 encoded a couple of
times, it decodes back to `Charix!2#4%6&8(0`. 

# Exploitation
Since `/etc/passwd` is available it's straightworward to try to login on the
box as `charix` user with the password we've got. This is how we could get a
user shell:

![user shell](/cstatic/htb-poison/user-shell.png)

There's also some `secret.zip` file nearby the flag, it could be unpacked with
the same password as for the `charix` user and there's just some little binary
file of unknown purpose at this moment.

# Privilege escalation
There's an interesting process running as root - Xvnc server. `sockstat -4 -l`
proves this since TCP ports `5801` and `5901` are listening on localhost.
According to Xvnc man page default port is '5800' + desktop number, which
sounds like our case. I forwarded these ports to my machine using tricky 
technique of SSH control sequences (~C and `-L5801:127.0.0.1:5801`) and tried
to connect to my local kali machine using vncviewer and acquired `secret` file
as `-passwd` argument. This worked well and we have a root shell now:

![root shell](/cstatic/htb-poison/root-shell.png)
