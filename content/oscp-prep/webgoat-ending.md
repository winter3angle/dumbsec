Title: Road to OSCP: WebGoat client side tasks & challenges solutions
Summary: Short notes about these ones
Category: OSCP
Tags: webgoat, websec
Date: 2020-03-16 16:00
Status: published

#### Bypass front-end restrictions
Laid-back tasks that focused on a simple concept that every security concerned 
developer should know - every input should be considered tampered and unsafe.
First two tasks are solvable using this principle. All you have to do to pass - 
to change form values using devtools or intercepting proxy, I did it using burp.
-------------------------------------------------------------------------------
#### Client-side filtering
In _Salary manager_ assignment we just have to examine page sources to find out
that all the records are delivered into client-side, but some of them just 
hidden. Hence it's possible to read data as-is and reveal CEO's salary that is
`450000`.
-------------------------------------------------------------------------------
I stuck a little at part where it's necessary to 'buy' brand new Samsung Galaxy
S8 for free. I was thinking that its another kind of DOM-related solution and
indeed there was two interesting parts in page sources:

  1. A comment with three discount codes, neither of them gives 100% discount  
  2. A hidden input with current discount value  

So I've tried to tamper that hidden input field and as turned out it's useless.
Proper way to discover super-code is to examine ajax requests that done after 
typing in a discount code and moving cursor out (a `blur` event). Request made
will look like `/WebGoat/clientSideFiltering/challenge-store/coupons/owasp`
with discount code at the end of the path. Application proudly provides us with
all the codes if we strip off trailing code from it. Super-coupon for 100% 
discount is *get_it_for_free*.
-------------------------------------------------------------------------------
#### HTML Tampering
Not sure if it's intended way to solve the task (it's just too straightforward)
but it could be easily solved after tampering 'checkout' request. It contains
just two parameters, `QTY` and `Total`, setting `Total` to zero will be
accepted as expected answer.
-------------------------------------------------------------------------------
#### Admin lost password
Dodgy one, after vainly viewing at page sources and trying to bruteforce 
password using some widespread passwords I tried to find some sort of injection
bug by modifying parameters and headers. As turned out, 
password was hidden in a plain sight, in the PNG image contained within a page.
Actually it was unusual to see it there (at least I was suspecting that it's 
related to solution since I started to solve it). To pass this we have to
download the picture and examine it's content in any viewer (I used `xxd`
utility) - password stored in plaintext within it. 
-------------------------------------------------------------------------------
#### Without password
This one seemed to be simpler to me, comparing with previous one. There is just
'classic' SQL injection in `password` request parameter. Login form could be
bypassed using `'+or+1=1+--+` parameter value.
-------------------------------------------------------------------------------
#### Admin password reset
At last my efforts to inspect page sources were successful. There is an 
interesting comment:
```html
<!--
Revision history (automatically added by: /challenge/7/.git/hooks)
2e29cacb85ce5066b8d011bb9769b666812b2fd9 Updated copyright to 2017
ac937c7aab89e042ca32efeb00d4ca08a95b50d6 Removed hardcoded key
f94008f801fceb8833a30fe56a8b26976347edcf First version of WebGoat Cloud website
-->
```
This looks like commit identifiers from git. Quick googling of
`ac937c7aab89e042ca32efeb00d4ca08a95b50d6` revealed just a couple of pages, two
of them being repositories. After some time digging into these a remarkable 
zip archive was found
[there](https://gitlab.i2p.online/cmaurer/test/tree/develop/webgoat-lessons/
challenge/src/main/resources/challenge7).
Content of this archive is a git repository on it's own, with only one branch
and three commits mentioned above. It also seems that not all of the changes
are already committed because `git status` reports that there are some deleted
files. Using `git restore *` to revert removal and find out that there are some 
compiled java classes. At first I used jd-gui to decompile 
`PasswordResetLink.class` to find out that it seems to really generate some
kind of a part of password reset link, but it requires two parameters to
proceed - username and a key. Username is `admin` but what's the key? Remember
that there is some noticeable commit with a message *Removed hardcoded key*?
To proceed we have to checkout this revision using `git checkout <HASH>`.
It will revert changes in `PasswordResetLink.class` and we have to use jd-gui
again to find out that key is `!!keykeykey!!`. Now I checked out latest master
back and run `java PasswordResetLink admin '!!keykeykey!!'` to find out that
required URI part is `375afe1104f4a487a73823c50a9292a2`. Next step is to fire
password reset request to WebWolf account, or to use some already generated.
All we have to do is to change end of the URI path to the hash from above.
This will allow us to pass this task and acquire the flag. 
-------------------------------------------------------------------------------
#### Without account
All right, now we have to take part in some sort of online poll without having
an account. The poll is not anonymous so unregistered user could not vote.
Page sources inspection gives nothing useful, all that I was able to find is
a javascript function that makes a vote request and loads breakdown and
average results. I've used burp to play with these endpoints, one unusual
details was almost immediately caught my attention - vote request is done using
GET method, that's strange because semanticaly POST is more expected to be
there IMO. I spent some time playing with headers and request parameters trying
to provide something like `admin=true`, `logged=1`, `debug` and so on. None of
these ended up in success. Then I tried to check one assumption about GET
request - to use HEAD instead. HEAD should behave exactly like GET, but telling
server not to return any response body. Surprisingly it worked! Applicaton
gently proceeded with it and returned flag in `X-Flag` header (of course
because body is missing).
