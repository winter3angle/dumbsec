Title: HTB Nibbles box writeup
Tags: oscp, htb, nibbleblog, sudo
Summary: Another walkthrough for a linux box
Date: 2020-09-07 14:00
Status: published

# Enumeration
Started with full nmap sS scan, as always on htb:
```text
    Nmap 7.80 scan initiated Sun Sep  6 12:27:03 2020 as: nmap -sS -p- -oA nmap-ss-all 10.10.10.75
    Nmap scan report for nibbles.htb (10.10.10.75)
    Host is up (0.061s latency).
    Not shown: 65533 closed ports
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    Nmap done at Sun Sep  6 12:27:58 2020 -- 1 IP address (1 host up) scanned in 54.83 seconds
```
Not much services in there. Nevertheless it's better to get as much info as we can, so scripted scan
will be useful:
```text
    Nmap 7.80 scan initiated Sun Sep  6 12:28:25 2020 as: nmap -sC -A -T4 -p22,80 -oA nmap-open-at4 10.10.10.75
    Nmap scan report for nibbles.htb (10.10.10.75)
    Host is up (0.053s latency).
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
    |   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
    |_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   52.96 ms 10.10.14.1
    2   53.08 ms nibbles.htb (10.10.10.75)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Sun Sep  6 12:28:38 2020 -- 1 IP address (1 host up) scanned in 13.19 seconds
```

Web content at the root doesn't seem useful in general, but there's an interesting commentin source code:

![nibbleblog comment entry](/cstatic/htb-nibbles/nibbleblog-comment.png)

Gobuster'd `/nibbleblog` using big.txt wordlist from dirb:
```text
    /.htpasswd (Status: 403)
    /.htpasswd.php (Status: 403)
    /.htaccess (Status: 403)
    /.htaccess.php (Status: 403)
    /README (Status: 200)
    /admin (Status: 301)
    /admin.php (Status: 200)
    /content (Status: 301)
    /feed.php (Status: 200)
    /index.php (Status: 200)
    /install.php (Status: 200)
    /languages (Status: 301)
    /plugins (Status: 301)
    /sitemap.php (Status: 200)
    /themes (Status: 301)
    /update.php (Status: 200)
```

Also ran nikto on the same target:
```text
    Nikto v2.1.6/2.1.5
    Target Host: nibbles.htb
    Target Port: 80
    GET Cookie PHPSESSID created without the httponly flag
    GET The anti-clickjacking X-Frame-Options header is not present.
    GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    HEAD /nibbleblog: Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
    OPTIONS Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
    MBWQHZIA Web Server returns a valid response with junk HTTP methods, this may cause false positives.
    OSVDB-29786: GET /nibbleblog/admin.php?en_log_id=0&action=config: EasyNews from http://www.webrc.ca version 4.3 allows remote admin access. This PHP file should be protected.
    OSVDB-29786: GET /nibbleblog/admin.php?en_log_id=0&action=users: EasyNews from http://www.webrc.ca version 4.3 allows remote admin access. This PHP file should be protected.
    OSVDB-3268: GET /nibbleblog/admin/: Directory indexing found.
    OSVDB-3092: GET /nibbleblog/admin.php: This might be interesting...
    OSVDB-3092: GET /nibbleblog/admin/: This might be interesting...
    OSVDB-3092: GET /nibbleblog/README: README file found.
    OSVDB-3092: GET /nibbleblog/install.php: install.php file found.
    OSVDB-3092: GET /nibbleblog/LICENSE.txt: License file found may identify site software.
```

Nibbleblog version determined:

![nibbleblog version](/cstatic/htb-nibbles/nibbleblog-ver.png)

# Exploitation
This version of nibbleblog seems to be vulnerable to [arbitrary file upload](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html).
Unfortunately, login credentials needed for this to work. Turned out that admin console is at `/nibbleblog/admin.php`. By the trial and error it turned out
that creds are `admin:nibbles`. This allows us to execute code as `nibbler`:

![unpriv web shell](/cstatic/htb-nibbles/unpriv-shell.png)

# Privilege escalation
nibbler could run `/home/nibbler/personal/stuff/monitor.sh` as root using sudo, no password required. Since it's our home directory, we could
do everything here, so I just moved out old `/monitor.sh` which was packed in `personal.zip` and changed it content to shebang and simple
`/bin/bash -i`, this opens a door for a root shell:

![root shell](/cstatic/htb-nibbles/root-shell.png)
