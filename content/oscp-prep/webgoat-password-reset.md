Title: Road to OSCP: WebGoat password reset
Date: 2020-02-26 14:00
Category: OSCP
Tags: websec, webgoat
Summary: Laid back challenges about password reset app feature in WebGoat 8

#### First assignment: reset your own password 
Not a challenge at all, just type `your-webgoat-username@any-domain.org` and get a plaintext password on your WebWolf instance, at localhost:9090/WebWolf in my case.  

#### Second assignment: abuse guessable security question  
We provided with three account names - "tom", "larry" and "admin". We've got a password reset form which contain security question about favourite color. Ours answer for user "webgoat" is "red".  
To solve this you just need a little guesswork to be done.  
I've started with Tom and provided it with colours from RGB and CMYK. No luck there. Ok, let's try them for "admin".  
In a couple of tries it turned out that his answer is "green". Solved.  

#### Third assignment: abuse password reset link expiration flaw  
We have to reset password for Tom (tom@webgoat-cloud.org) using a form that generates password reset link that being sent to user's e-mail.  
As far as I do not have access to Tom's email, I have to work around this.  
Let's try to reset our own password a couple of time, I've did about ten attempts and examined generated links.  
Links were in format of `http://localhost:8080/WebGoat/PasswordReset/reset/reset-password/e12c0607-606f-4e6f-811d-062c850b509c` and seemed to be guessproof as they contain random UUID.  
Three important details could be noticed here:  

 1. The link is always valid, even after you have reset password using it, hence you could use one link for many requests
 2. WebWolf have capability to log incoming requests and provide you with details such as URI, timestamp, user agent and so on
 3. Tom immediately resets its password after getting link on e-mail

--------------------------------------------------------------------
Given these facts we could try to abuse broken expiration mechanism, all we need to do is to log request issued by Tom.  
To achieve this we have to fool around a little with intercepting proxy.  
As far as we could not interfere with UUID generation pattern, we could try to hijack the host itself.  
By changing `Host` header in request for password reset link we could achieve this - it used in the link generation process and seemed to be pasted as is into the resultant URI.  
Given our ability to log requests via WebWolf, let's hijack it in that way so password reset link will point at WebWolf. This indeed worked!  
Almost immediately we see that Tom clicked on it and we've got all the details, most juicy is the URI itself.  
Using that URI we could change Tom's password again and complete the assignment.  
