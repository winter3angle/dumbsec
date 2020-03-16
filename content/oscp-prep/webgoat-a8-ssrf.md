Title: Road to OSCP: WebGoat A8: SSRF
Summary: Super short notes about two SSRF tasks
Category: OSCP
Tags: webgoat, websec, ssrf
Date: 2020-03-14 00:30
Status: published

#### Change the URL to display Jerry
Task name literally points how to solve it. There is an `url` request parameter that by default is set to `images%2Ftom.png`, to complete this it's necessary to change `tom` to `jerry`.

#### Change the URL to display the Interface Configuration with ifconfig.pro
Yet again the name is the answer. Request is quite similar with the one in the previous assignment, all that is needed is to change it's value to `http://ifconfig.pro` using intercepting proxy or some other suitable tool. For example curl invocations is as follows `curl -d 'url=http://ifconfig.pro' -b 'JSESSIONID=<YOUR_SESSION_ID>' http://localhost:8080/WebGoat/SSRF/task2`
