Title: HTB Nineveh box writeup
Tags: oscp, htb
Summary: CTFey box writeup
Date: 2020-09-08 15:00
Status: published

# Enumeration
Nmap `-sS` all TCP range:
<pre>
    Nmap 7.80 scan initiated Tue Sep  8 11:57:11 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.43
    Nmap scan report for nineveh.htb (10.10.10.43)
    Host is up (0.056s latency).
    Not shown: 65533 filtered ports
    PORT    STATE SERVICE
    80/tcp  open  http
    443/tcp open  https
    Nmap done at Tue Sep  8 11:59:11 2020 -- 1 IP address (1 host up) scanned in 120.34 seconds
</pre>
Nmap `-A -T4 -sC` open ports:
<pre>
    Nmap 7.80 scan initiated Tue Sep  8 12:00:57 2020 as: nmap -sC -A -T4 -p80,443 -oA enum/nmap-SCAT4-open 10.10.10.43
    Nmap scan report for nineveh.htb (10.10.10.43)
    Host is up (0.056s latency).
    PORT    STATE SERVICE  VERSION
    80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    | ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
    | Not valid before: 2017-07-01T15:03:30
    |_Not valid after:  2018-07-01T15:03:30
    |_ssl-date: TLS randomness does not represent time
    | tls-alpn: 
    |_  http/1.1
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   55.01 ms 10.10.14.1
    2   55.08 ms nineveh.htb (10.10.10.43)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Tue Sep  8 12:01:18 2020 -- 1 IP address (1 host up) scanned in 21.50 seconds
</pre>
Different web resources are on http and https, seems like https server is a way to go since there's only
a stub page on tcp 80:

![http stub](/cstatic/htb-nineveh/http-stub-page.png)

Gobustered HTTP root:
<pre>
    /.htaccess (Status: 403)
    /.htpasswd (Status: 403)
    /department (Status: 301)
    /server-status (Status: 403)
</pre>

Gobustered HTTPS root:
<pre>
    /.htaccess (Status: 403)
    /.htpasswd (Status: 403)
    /db (Status: 301)
    /server-status (Status: 403)
</pre>

Interesting comment at the page `/department`:

![dept comment](/cstatic/htb-nineveh/dept-amrois.png)

Custom form at `/department` allows to enumerate registered users:

![dept users enum](/cstatic/htb-nineveh/dept-user-enum.png)

Turned out, that there's an `admin` user:

![dept admin attempt](/cstatic/htb-nineveh/dept-admin-enum.png)

# Exploitation
I was able to bruteforce admin password using [this wordlist](https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords-1000.txt):

![dept admin bruted](/cstatic/htb-nineveh/dept-admin-bruted.png)

phpLiteAdmin password also bruteforced:

![db admin bruted](/cstatic/htb-nineveh/db-admin-bruted.png)

`manage.php` in `/department` has LFI, but it seems to be constrained to contain `ninevehNotes`:

![dept lfi](/cstatic/htb-nineveh/dept-lfi.png)

phpMyAdmin could be leveraged to drop arbitrary php code for us to include:

![lfi chained](/cstatic/htb-nineveh/dept-lfi-chained.png)

This allows us to execute code as www-data:

![unpriv shell](/cstatic/htb-nineveh/unpriv-shell.png)

In the notes in `/department` some dude mentioned that we should try to find secret notes somewhere
on the host, it was easier with user shell:

![secure notes](/cstatic/htb-nineveh/secure-notes.png)

Now the stupid CTF part which I hate most. It doesn't seem to be likely encountered in real life experience,
but picture at `https://nineveh.htb/secure_notes/nineveh.png` contained some sensitive info. One could probably
guess that since we are browsing 'secure notes' and picture looks pretty large:

![note key](/cstatic/htb-nineveh/note-key.png)

This keypair is for `amrois` user, also noticed in the picture dump. Though SSH seems to be filtered,
it could be used locally to get user shell:

![amrois shell](/cstatic/htb-nineveh/amrois-shell.png)

# Privilege escalation
There's an interesting unusual folder in root - `/report`. It contains some logs from some util that might be
running in a scheduled manner at every minute. Also amrois has crontab job configured to clean up this directory
every 10 minutes. I googled for some fragments of these logs and it looks like they're being produced by
`chkrootkit`. Some versions of `chkrootkit` were vulnerable to trivial [code execution](https://www.exploit-db.com/exploits/33899)
vulnerability and this one is vulnerable too. PE is simple - we have to place proper executable in `/tmp/update` and
it would be run as root every time `chkrootkit` starts by schedule. I've put there a simple bash script that establish
back connection to my box and got a root shell:

![root shell](/cstatic/htb-nineveh/root-shell.png)
