Title: HTB Beep box writeup
Tags: oscp, htb
Summary: Yet another retired box
Date: 2020-09-01 16:00
Status: published

# Enumeration
This time I started with only top 1000 ports to scan:
<pre>
    Nmap 7.80 scan initiated Thu May 14 11:36:21 2020 as: nmap -sS --top-ports=1000 -oN enum/nmap-sS-top1k 10.10.10.7
    Nmap scan report for 10.10.10.7
    Host is up (0.064s latency).
    Not shown: 988 closed ports
    PORT      STATE SERVICE
    22/tcp    open  ssh
    25/tcp    open  smtp
    80/tcp    open  http
    110/tcp   open  pop3
    111/tcp   open  rpcbind
    143/tcp   open  imap
    443/tcp   open  https
    993/tcp   open  imaps
    995/tcp   open  pop3s
    3306/tcp  open  mysql
    4445/tcp  open  upnotifyp
    10000/tcp open  snet-sensor-mgmt
</pre>
Whoa, that's a bunch, especially compared with previous boxes. But that's okay, just keep on pushing according to methodology. Let's run script scan on open ports:
<pre>
    Nmap 7.80 scan initiated Thu May 14 11:38:42 2020 as: nmap -sC -sV -O -p 22,25,80,110,111,143,443,993,995,3306,445,10000 
      -oN enum/nmap-sCV-O-discovered-tcp 10.10.10.7
    Nmap scan report for 10.10.10.7
    Host is up (0.063s latency).
    PORT      STATE  SERVICE      VERSION
    22/tcp    open   ssh          OpenSSH 4.3 (protocol 2.0)
    | ssh-hostkey: 
    |   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
    |_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
    25/tcp    open   smtp         Postfix smtpd
    |_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
    80/tcp    open   http         Apache httpd 2.2.3
    |_http-server-header: Apache/2.2.3 (CentOS)
    |_http-title: Did not follow redirect to https://10.10.10.7/
    |_https-redirect: ERROR: Script execution failed (use -d to debug)
    110/tcp   open   pop3         Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
    |_pop3-capabilities: PIPELINING LOGIN-DELAY(0) USER AUTH-RESP-CODE RESP-CODES STLS APOP UIDL 
      IMPLEMENTATION(Cyrus POP3 server v2) EXPIRE(NEVER) TOP
    111/tcp   open   rpcbind      2 (RPC #100000)
    143/tcp   open   imap         Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
    |_imap-capabilities: URLAUTHA0001 OK Completed X-NETSCAPE STARTTLS BINARY MAILBOX-REFERRALS NAMESPACE THREAD=REFERENCES 
      CHILDREN UIDPLUS ID RENAME IDLE IMAP4 CONDSTORE NO IMAP4rev1 MULTIAPPEND LITERAL+ UNSELECT LIST-SUBSCRIBED 
      THREAD=ORDEREDSUBJECT ATOMIC SORT=MODSEQ LISTEXT CATENATE RIGHTS=kxte QUOTA SORT ANNOTATEMORE ACL
    443/tcp   open   ssl/https?
    |_ssl-date: 2020-05-14T11:41:09+00:00; +1m23s from scanner time.
    445/tcp   closed microsoft-ds
    993/tcp   open   ssl/imap     Cyrus imapd
    |_imap-capabilities: CAPABILITY
    995/tcp   open   pop3         Cyrus pop3d
    3306/tcp  open   mysql        MySQL (unauthorized)
    10000/tcp open   http         MiniServ 1.570 (Webmin httpd)
    |_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.80%E=4%D=5/14%OT=22%CT=445%CU=30442%PV=Y%DS=2%DC=I%G=Y%TM=5EBD2
    OS:E9D%P=x86_64-pc-linux-gnu)SEQ(SP=C2%GCD=3%ISR=D4%TI=Z%CI=Z%II=I%TS=A)OPS
    OS:(O1=M507ST11NW7%O2=M507ST11NW7%O3=M507NNT11NW7%O4=M507ST11NW7%O5=M507ST1
    OS:1NW7%O6=M507ST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)ECN
    OS:(R=Y%DF=Y%T=40%W=16D0%O=M507NNSNW7%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
    OS:S%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M507ST11NW7%RD=
    OS:0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=
    OS:Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=
    OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%R
    OS:IPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)
    Network Distance: 2 hops
    Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com
    Host script results:
    |_clock-skew: 1m22s
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Thu May 14 11:42:21 2020 -- 1 IP address (1 host up) scanned in 219.79 seconds
</pre>
A bit of manual inspection revealed that there is an Elastix installation on this box, looks like
that bunch of other ports are related to this one in some way. Almost immediately I have found out
that there are some vulns known to exploit-db and one including [LFI](https://www.exploit-db.com/exploits/37637).

# Exploitation
Though the version does not match, even author suggest to try to check out this on other versions since
they may have been affected. Our deployment is indeed vulnerable to this:

![LFI poc](/cstatic/htb-beep/lfi-poc.png)

In fact, the only this file allows us to get root directly, since there is some password in this configuration
file that's the same for root user. We just can use webmin or ssh to get the shell:

![root shell](/cstatic/htb-beep/root-shell.png)

This box was straightforward to me, but mostly because of some degree of luck - it looks like full of
rabbit holes, guess I was just lucky enough to find the necessary exploit on first try.
