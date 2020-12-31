Title: HTB Granny box writeup
Tags: oscp, htb, webdav, cadaver, iis, asp
Summary: Unusual service on antediluvian box
Date: 2020-10-06 00:40
Status: published

# Enumeration
Only single TCP port considered open:
```text
    Nmap 7.80 scan initiated Thu Oct  1 11:37:21 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.15
    Nmap scan report for granny.htb (10.10.10.15)
    Host is up (0.060s latency).
    Not shown: 65534 filtered ports
    PORT   STATE SERVICE
    80/tcp open  http
    Nmap done at Thu Oct  1 11:39:10 2020 -- 1 IP address (1 host up) scanned in 109.05 seconds
```
Looks like it supports WebDAV:
```text
    Nmap 7.80 scan initiated Thu Oct  1 11:47:08 2020 as: nmap -sC -A -T4 -p80 -oA enum/nmap-sCAT4-80 10.10.10.15
    Nmap scan report for granny.htb (10.10.10.15)
    Host is up (0.053s latency).
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Microsoft IIS httpd 6.0
    | http-methods: 
    |_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
    |_http-server-header: Microsoft-IIS/6.0
    |_http-title: Under Construction
    | http-webdav-scan: 
    |   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
    |   Server Type: Microsoft-IIS/6.0
    |   WebDAV type: Unknown
    |   Server Date: Thu, 01 Oct 2020 11:47:39 GMT
    |_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
    OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
    Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2003 SP2 (89%), Microsoft Windows XP (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%), Microsoft Windows 2000 SP4 (85%), Microsoft Windows XP SP2 or Windows Server 2003 SP2 (85%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   54.03 ms 10.10.14.1
    2   54.80 ms granny.htb (10.10.10.15)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Thu Oct  1 11:47:44 2020 -- 1 IP address (1 host up) scanned in 43.67 seconds
```
Unusual header spotted in webserver response, it might be Microsoft Frontpage:

![unusual header](/cstatic/htb-granny/mso-header.png)

We are able to upload files using WebDAV (cadaver used as a client):

![webdav upload](/cstatic/htb-granny/cadaver-upload.png)

Meanwhile nikto finished scanning:
```text
    Nikto v2.1.6/2.1.5
    Target Host: granny.htb
    Target Port: 80
    GET Retrieved microsoftofficewebserver header: 5.0_Pub
    GET Retrieved x-powered-by header: ASP.NET
    GET The anti-clickjacking X-Frame-Options header is not present.
    GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    GET Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
    GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    GET Retrieved x-aspnet-version header: 1.1.4322
    OSVDB-397: PUT HTTP method 'PUT' allows clients to save files on the web server.
    OSVDB-5646: DELETE HTTP method 'DELETE' allows clients to delete files on the web server.
    OPTIONS Retrieved dasl header: <DAV:sql>
    OPTIONS Retrieved dav header: 1, 2
    OPTIONS Retrieved ms-author-via header: MS-FP/4.0,DAV
    OPTIONS Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
    OPTIONS Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
    OSVDB-5646: GET HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
    OSVDB-397: GET HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
    OSVDB-5647: GET HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
    OPTIONS Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
    OSVDB-5646: GET HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
    OSVDB-397: GET HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
    OSVDB-5647: GET HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
    OPTIONS WebDAV enabled (PROPPATCH SEARCH PROPFIND COPY MKCOL LOCK UNLOCK listed as allowed)
    OSVDB-13431: PROPFIND PROPFIND HTTP verb may show the server's internal IP address: http://granny/_vti_bin/_vti_aut/author.dll
    OSVDB-396: GET /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
    OSVDB-3233: GET /postinfo.html: Microsoft FrontPage default file found.
    OSVDB-3233: GET /_private/: FrontPage directory found.
    OSVDB-3233: GET /_vti_bin/: FrontPage directory found.
    OSVDB-3233: GET /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
    OSVDB-3300: GET /_vti_bin/: shtml.exe/shtml.dll is available remotely. Some versions of the Front Page ISAPI filter are vulnerable to a DOS (not attempted).
    OSVDB-3500: GET /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. CVE-1999-1376. BID-2252.
    OSVDB-67: POST /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
    GET /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
```
Proves some hypotheses about target environment. 

# Exploitation
Attempt to directly upload some `aspx` shells failed with HTTP 403, but a
workaround had been found - it is possible to upload shell with txt extension
and just rename it after using DAV client:

![shell uploaded](/cstatic/htb-granny/shell-uploading.png)

And this one indeed could be executed, we're in:

![service shell](/cstatic/htb-granny/service-shell.png)

# Privilege escalation
Turned out this box is pretty old, chances are that there are many exploits or
less convoluted ways to privesc. I've just grabbed 
[this one](https://www.exploit-db.com/exploits/37755) and after a bit of tuning
it worked flawlessly. All that's needed is to change executable binary to our
meterpreter shell and catch a root session. For reasons unknown `shell` command
doesn't work in this session, it just drops back to meterpreter prompt, but I
guess it's eligible:

![root shell](/cstatic/htb-granny/root-shell.png)
