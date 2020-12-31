Title: HTB Sense writeup
Tags: oscp, htb, dirbusting, pfsense
Summary: When an outdated security solution is a gate to adversary
Date: 2020-09-20 15:00
Status: published

# Enumeration
Full range TCP scan revealed only a couple of open ports:
```text
    Nmap 7.80 scan initiated Sat Sep 12 22:07:56 2020 as: nmap -sS -p- -oA enum/nmap-ss-all sense.htb
    Nmap scan report for sense.htb (10.10.10.60)
    Host is up (0.065s latency).
    Not shown: 65533 filtered ports
    PORT    STATE SERVICE
    80/tcp  open  http
    443/tcp open  https
    Nmap done at Sat Sep 12 22:10:03 2020 -- 1 IP address (1 host up) scanned in 127.58 seconds
```
Actually, I tried to browse to this host either by IP and by name (`shocker.htb`, added entry to `/etc/hosts` as
always) and already discovered them. Also tried to scan top 1000 UDP ports with `-sU` switch, no luck, all of
them rendered useless.
Looks like lighthttpd used with pfsense:

![webserver version](/cstatic/htb-sense/webserver-ver.png)

Gobuster on `/` probably will be useful, though the app is well-known:
```text
    /classes (Status: 301)
    /css (Status: 301)
    /favicon.ico (Status: 200)
    /includes (Status: 301)
    /installer (Status: 301)
    /javascript (Status: 301)
    /themes (Status: 301)
    /tree (Status: 301)
    /widgets (Status: 301)
    /wizards (Status: 301)
    /~sys~ (Status: 403)
```
It might be that something unusual is hosted at `/tree`:

![silverstripe tree](/cstatic/htb-sense/tree.png)

The version shown is quite old - `SilverStripe Tree Control: v0.1, 30 Oct 2005`. If this is related to pfsense,
it might be very old as well.
Nikto shown no additional useful info:
```text
    Nikto v2.1.6/2.1.5
    Target Host: 10.10.10.60
    Target Port: 443
    GET Cookie cookie_test created without the secure flag
    GET Cookie cookie_test created without the httponly flag
    GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    GET The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
    GET The site uses SSL and Expect-CT header is not present.
    GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    GET Multiple index files found: /index.php, /index.html
    GET Hostname '10.10.10.60' does not match certificate's names: Common
    OPTIONS Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
```
Here I stuck for the moment, the only web service seems to be outdated, but we need creds to proceed. Some additional gobustering revealed hint, it was necessary to try some other wordlists and various extensions (redirects and known entries are omitted):
```text
/changelog.txt (Status: 200)
/system-users.txt (Status: 200)
```
Those are quite inetersting files. `system-users.txt` contain hint about working creds:

![system users](/cstatic/htb-sense/system-users.png)

And `changelog.txt` has a tip that some vuln has not been pathched there yet:

![changelog](/cstatic/htb-sense/changelog.png)

# Exploitation
Tried manually some creds and `rohit:pfsense` worked. Version of pfSense is right on the index page:

![pfsense version](/cstatic/htb-sense/pfsense-version.png)

From second try [this exploit](https://www.exploit-db.com/exploits/43560) was found and it indeed worked great, providing us directly with the root shell:

![root shell](/cstatic/htb-sense/root-shell.png)

Most challenging part was to find proper credentials for pfsense, never give up trying various wordlists or parameters while trying to actively enumerate the target.
