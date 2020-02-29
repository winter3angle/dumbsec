Title: Road to OSCP: WebGoat A5 section: IDOR
Category: OSCP
Tags: webgoat, websec, idor
Summary: Solutions to IDOR assignments from (A5) broken access control section
Date: 29/02/2020 15:30
Status: published

#### Observing differences & behaviors
We have to examine request to user profile info endpoint and list two attributes that didn't show on page. No-brainer at all, just view response in browser devtools. These attributes are `role` and `userId`.

---------------------------------------

#### Guessing & predicting patterns
Task definition gives us a hint that URI is very similar to the one used in the previous assignment. Use `userId` from it to construct an URI path that is `WebGoat/IDOR/profile/<USERID>`.

---------------------------------------

#### Playing with the patterns
We have to find some user's profile and to change their `color` to red and lower the `role` attribute. Since I knew my own id, I tried to guess some other nearby. My identifier was `2342384` and I tried values from `2342380` to `2342389`. Voila! Other id is `2342388`. I decided to write my own script to enumerate possible IDs in case of a failure, but that wasn't necessary. Using that ID we have to change user's profile (by the way his name is Buffalo Bill, seems like we've messing up with a cool guy). Again, there is a hint right in the task description, it states that RESTful application often use different HTTP methods to manipulate the resource which path stay constant. I've tried to use POST request, but that didn't work, somewhat expected because many RESTful applications use POST to create a new resource, not to modify it. For modifying purposes PUT and PATCH are often used, the first one worked flawlessly. To complete this assignment we have to PUT such a body to `/WebGoat/IDOR/profile/2342388` (do not forget to change value of the `Content-Type` header to `application/json`):
```json
{
  "role": 1,
  "color": "red",
  "size": "large",
  "name": "Buffalo Bill",
  "userId": 2342388
}
```
Actually, user id in URI may be of any value - the one in JSON body matters. You may provide anything you want, it will work anyway. 
