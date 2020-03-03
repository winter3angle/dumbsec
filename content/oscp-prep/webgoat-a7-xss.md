Title: Road to OSCP: WebGoat A7 XSS assignments
Category: OSCP
Tags: websec, webgoat, xss
Date: 2020-03-02 14:00
Status: published
Summary: A very short 'writeup' on XSS tasks from WebGoat 8

#### What is XSS?
Not a challenge at all, it could be passed even without following steps. The answer is 'yes' since URIs are equal. 

#### Identify potential for DOM-Based XSS
To find leftover route we have to use browser devtools. `GoatRouter.js` script is easily spotted, within you may find a route called `testRoute` that echoes parameter passed in RESTful manner back in the page. To find appropriate answer was a trickier part, since base route should be included as well. Solution is `start.mvc#test`.

#### Try It! DOM-based XSS
Since that test route just echoes content back we should exploit this flaw here. To test exploitability I used notorious `alert("1");` sequence. The only caveat here is the backslash in closing tag, since we should construct a URI with script fragment, we should encode it to `%2f`. Once we navigate to `WebGoat/start.mvc#test/<script>webgoat.customjs.phoneHome()<%2fscript>` we'll see output in our devtools console. There will be a number which is the answer to the assignment.  

Honestly, I expected more practical challenges here.
