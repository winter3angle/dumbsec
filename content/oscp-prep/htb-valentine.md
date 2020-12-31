Title: HTB Valentine box writeup
Tags: oscp, htb, heartbleed, openssl, tmux, gtfobins
Summary: Rather interesting PE and notorious branded vulnerability walk into a bar...
Date: 2020-10-14 01:50
Status: published

# Enumeration
Not much network services available there:
```text
    Nmap 7.80 scan initiated Tue Oct 13 22:39:38 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.79
    Nmap scan report for valentine.htb (10.10.10.79)
    Host is up (0.055s latency).
    Not shown: 65532 closed ports
    PORT    STATE SERVICE
    22/tcp  open  ssh
    80/tcp  open  http
    443/tcp open  https
    Nmap done at Tue Oct 13 22:40:15 2020 -- 1 IP address (1 host up) scanned in 37.15 seconds
```
Detailed information:
```text
    Nmap 7.80 scan initiated Tue Oct 13 22:40:39 2020 as: nmap -sC -A -T4 -p22,80,443 -oA enum/nmap-sCAT4-open 10.10.10.79
    Nmap scan report for valentine.htb (10.10.10.79)
    Host is up (0.052s latency).
    PORT    STATE SERVICE  VERSION
    22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
    |   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
    |_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
    80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
    |_http-server-header: Apache/2.2.22 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
    |_http-server-header: Apache/2.2.22 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    | ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
    | Not valid before: 2018-02-06T00:45:25
    |_Not valid after:  2019-02-06T00:45:25
    |_ssl-date: 2020-10-13T19:41:00+00:00; 0s from scanner time.
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose|phone|media device
    Running (JUST GUESSING): Linux 3.X|2.6.X (95%), Nokia embedded (95%), Google Android 4.0.X|4.2.X (93%), Yamaha embedded (92%)
    OS CPE: cpe:/o:linux:linux_kernel:3.0 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:2.6.32 cpe:/h:nokia:n9 cpe:/o:google:android:4.0.4 cpe:/o:google:android:4.2.1 cpe:/o:google:android:4.2.2 cpe:/h:yamaha:rx-v481d
    Aggressive OS guesses: Linux 3.0 (95%), Linux 2.6.32 - 3.5 (95%), Nokia N9 phone (Linux 2.6.32) (95%), Linux 3.2 (95%), Linux 2.6.38 - 3.0 (94%), Linux 2.6.38 - 2.6.39 (94%), Linux 2.6.39 (94%), Linux 3.5 (93%), Linux 2.6.32 - 3.10 (93%), Linux 2.6.32 - 3.9 (93%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   51.05 ms 10.10.14.1
    2   52.62 ms valentine.htb (10.10.10.79)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Tue Oct 13 22:41:00 2020 -- 1 IP address (1 host up) scanned in 21.37 seconds
```

Nikto was running in parallel:
```text
    Nikto v2.1.6/2.1.5
    Target Host: valentine.htb
    Target Port: 80
    GET Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.26
    GET The anti-clickjacking X-Frame-Options header is not present.
    GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    GET Uncommon header 'tcn' found, with contents: list
    GET Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
    HEAD Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
    BDOTXUTF Web Server returns a valid response with junk HTTP methods, this may cause false positives.
    OSVDB-12184: GET /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
    OSVDB-12184: GET /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
    OSVDB-12184: GET /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
    OSVDB-12184: GET /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
    OSVDB-3268: GET /dev/: Directory indexing found.
    OSVDB-3092: GET /dev/: This might be interesting...
    GET Server may leak inodes via ETags, header found with file /icons/README, inode: 534222, size: 5108, mtime: Tue Aug 28 14:48:10 2007
    OSVDB-3233: GET /icons/README: Apache default file found.
```

Along with gobuster:
```text
    /.htpasswd (Status: 403)
    /.htaccess (Status: 403)
    /cgi-bin/ (Status: 403)
    /decode (Status: 200)
    /dev (Status: 301)
    /encode (Status: 200)
    /index (Status: 200)
    /server-status (Status: 403)
```

There's an interesting picture right in the index page. It reminds me of 
notorious Heartbleed bug in OpenSSL, it has been branded with this logo:

![heartbleed yell](/cstatic/htb-valentine/heartbleed.png)

There's an NSE to check whether host is vulnerable, it seems that heartbleed
hypothesis is right:
```text
    Nmap 7.80 scan initiated Tue Oct 13 22:54:16 2020 as: nmap -sC -p443 --script=ssl-heartbleed -oA enum/nmap-sc-heartbleed valentine.htb
    Nmap scan report for valentine.htb (10.10.10.79)
    Host is up (0.050s latency).
    PORT    STATE SERVICE
    443/tcp open  https
    | ssl-heartbleed: 
    |   VULNERABLE:
    |   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
    |     State: VULNERABLE
    |     Risk factor: High
    |       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
    |           
    |     References:
    |       http://www.openssl.org/news/secadv_20140407.txt 
    |       http://cvedetails.com/cve/2014-0160/
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
    Nmap done at Tue Oct 13 22:54:17 2020 -- 1 IP address (1 host up) scanned in 0.88 seconds
```

Some interesting files under the `/dev` path, including some RSA private key
encoded in hex:
```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

There's a passphrase so we couldn't just get and generate pubkey from this one.

`/encode.php` and `/decode.php` aren't secure at all since they just encode
data back and forth using base64 which is obviously not suitable for encryption.

# Exploitation
Given these facts:

 1. Private key with passphrase
 2. Weak encoding/decoding functionality in webapp
 3. Server vulnerable to heartbleed

I just spinned up some known exploit, in my case it was
[32745](https://www.exploit-db.com/exploits/32745)
and found that passphrase is there, base64 encoded:

![key passphrase](/cstatic/htb-valentine/key-pass.png)

It allows to SSH to the machine as `hype` user (hype's key, right?):

![user shell](/cstatic/htb-valentine/user-shell.png)

# Privilege escalation
Privilege escalation was rather easy but yet unknown to me. After running some
very basic checks like `sudo -l` I ran `linpeas.sh` and noticed that there's
an active tmux session for root. Elevating privileges to root was as simple as
running `tmux -S /.devs/dev_sess`:

![root shell](/cstatic/htb-valentine/root-shell.png)
