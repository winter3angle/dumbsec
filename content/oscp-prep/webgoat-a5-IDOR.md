Title: Road to OSCP: WebGoat A5 section
Category: OSCP
Tags: webgoat, websec, idor
Summary: Solutions to assignments from (A5) broken access control section
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

---------------------------------------

### A couple of tasks from second section

#### Relying on obscurity
Direct hints are given in the task definition itself:
> There are usually hints to finding functionality the UI does not openly expose in …  
>   HTML or javascript comments  
>   Commented out elements  
>   Items hidden via css controls/classes  

Use browser devtools to find out that there are a couple of hidden controls (links) named `Users` and `Config`.

---------------------------------------

#### Just try it
We have to acquire our own password hash to pass this. It was clearly stated that we will need some of the links from previous task, `Users` looks to be most promising. Given that WebGoat application located not in the root, but `/WebGoat` path we need to add `users` at the end (since link in previous task was relative and pointed to `/users`). Resultant path is `/WebGoat/users`. It may be tricky to construct a proper request, especially if you intercepted some to WebGoat and trying to just substitute the path. Tricky part is in `Content-Type` header, intercepted request will likely have value of `application/x-www-form-urlencoded` and application will throw an error upon GETting this endpoint. There is a hint - if you try to POST data to it using some invalid `Content-Type` it will give you a useful error message about it. By the trial and error it was figured out that proper value for the header is `application/json`. After successful attempt I've got an answer similar to this:
```json
[ {
  "username" : "theuser",
  "admin" : false,
  "userHash" : "lH4dS2lr21B1zHkMSEZyDHfXd24wf7BBUxTGk16zTPY="
} ]
```
Use the `userHash` member to complete the task.
