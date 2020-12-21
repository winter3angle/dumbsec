Title: How to fail first OSCP attempt, essentials
Category: OSCP
Tags: exam, failure, oscp
Summary: Post-mortem of failed exam attempt
Date: 17/12/2020 23:00
Status: published

# Long story short
I thought that I was good at Linux LPE, but turned out it doesn't hold true.
Got 1 full access on Windows and three users on Linux boxes, only the easiest
one left untouched. Failed to escalate privileges and hence failed the exam.
Final score was 25 + 25/2 + 20/2 + 20/2 which is obviously not enough to pass.
Below is the story.

# How it started
Exam was scheduled to start at 1:00 PM. I've took a day off before it to take
some rest and to get some snacks and meals for a long night. I slept well, had
a good morning stroll with my beloved doggo, took some breakfast and started to
play with proctoring software. Here's the nightmare begins. After a bit of 
formal things like checking my ID it was clear that proctoring software causing
noticeable lags on my system. It was lagging so damn hard so that when I was typing
something, the letters showed up after five seconds or so. I do not have sort of
expensive hardware, just a good old Thinkpad T420 with 16 gigabytes of RAM, SSD
and Intel i5-2520M CPU. Not the top notch PC, but not an antediluvian box
either. But nevertheless the host machine was lagging as hell and it was almost
impossible to do something with it, not to say to use a virtual machine with
Kali. Task manager showed that _System interrupts_ process is causing 100% CPU
utilization and I immediately came with hypothesis that it was an external
display (hoped to take exam using notebook with display plugged in) that
caused such lags. Things went smoother with unplugged display, but not that
great as I expected. Next step was to try to use Google Chrome for proctoring
session and however Offensive Security recommends to use Firefox (which is my
go-to browser usually) Chrome worked much better than it. I was told that there
are some bugs and newest Chrome doesn't work well with proctoring software, but
I didn't notice anything wrong with it as well as my remote proctor. This weird
troubleshooting session took about 40 minutes and I was kind of upset of such a
dumb start and time waste right from the beginning.  

# The first one
So I decided to start with buffer overflow machine which costs 25 points and
how rumours say is the easiest one. Turned out this is true. You're provided
with debugging machine with all the needed software and just have to stick with
trivial manual BO exploitation methodology and you're fine. It took like a hour
and a half to have working local exploit with `windows/exec` msfvenom payload.
For some reason it was necessary to play with encoders since some of the were
causing immediate crashes on target service, despite the countermeasures like
nop sleds and amount of memory for shellcode was totally ok. The main caveat
here was the reverse shell payload which didn't work at all for some unknown
reason. Firewall configuration was OK since I was able to ping back from
debugging machine to my Kali VM using TCP 53 and PowerShell, also reverse shell
didn't pop out with firewall disabled. Tried lots of payloads and none worked
except that local `windows/exec`. Was thinking that I just try to start reverse
shell using exec and SMB share, but threw this idea away later. After a bit
of trying I decided to fire up meterpreter on this box and pwned it instantly
with corresponding payload.

# The second one
I didn't focus entirely on BO machine and ran some scans on another boxes at the
same time. Next target was the 20 points box with some unusual services running.
After about a hour of googling and playing with required toolset locally I was
able to get user there. It was not that hard and mentally I marked this machine
as 'privesc-oriented', deployed some enumeration tools, ran them and switched
over to another target.

# The third and the fourth
Next targets were 25 and 20 points boxes. They turned out to be sneaky ones and
I didn't manage to get user in a straightforward manner, it took me long time,
switches between the targets and some rest to get there. One machine turned out
to be 'enum-oriented' and was indeed fun, required a lot of attention to
details and thorough enumeration. I found it somewhat similar to Compromised box
from HTB, the latter just seems more CTFey and exam box looked like more real
life example. Another box was tricky but googleable, it was kind of full of
rabbit holes and I spent about three hours trying to get around those.
It was so intriguing and captive so that when I decided to take a nap around
2:00 AM I couldn't sleep since was thinking about some hypotheses. Nap time
was delayed, I got back to work and managed to get user in next two hours.

# The fails
As said earlier I did some enumeration in parallel and hence collected some
results from pwned machines, like linpeas output or pspy history. Turned out
that there aren't any easy privesc boxes like some that were on HTB, you know,
something like when you could sudo a gtfobinary or misconfigs like suid enabled
nmap owned by root. Privesc turned to be hard and full of enumeration. I was
sure about PE vectors on two machines, but none of mine attempts resulted in
success. Third machine was nicely patched and I barely found the right
vector for privilege escalation. I tried in vain right to the end of the exam,
but unfortunately didn't succeed.

# The easy box
This little one was left almost untouched. I didn't manage to get user in there
but it seemed like a direct-to-root machine. The vector was 100% clear and poc
was easily composed but shell turned to be stubborn. Spent a lot of reverts on
this, almost 20 in total. Sure that this box might be easily pwned with MSF,
but this tool was forbidden since I already used meterpreter payload on a buffer
overflow machine. Nevertheless this box wouldn't let me pass the exam since I
would end up with 67.5 points in total which is not enough.

# What worked good
You will find this in almost every happy blogpost from the one who passed the
exam:

 * Take breaks. I was going out with my dog for three times and it was great.
   Every time I was returing refreshed and full of ideas to try.
 * Take naps. This is necessary but hard for me. Difficult to fall asleep when
   I'm thinking about some nasty task. Sleeped just about 3.5 hours in total.
 * Eat well and healthy. Hunger likely is not the expected feeling while taking
   the tough exam.
 * Switch between machines. Proved to be great technique to get out from the
   rabbit holes and wrong hypotheses.
 * Multitask. Obvious advice. You'll likely end up short if you won't do tasks
   such as scans or bruteforcing in parallel. There aren't much time for this.

# What didn't work good
Some pitfalls, glitches and wrong directions:

 * Lagging proctoring software. Already discussed
 * Privilege escalation. Get some courses, really! I took just winpe tib3rius
   course on Udemy and failed
 * Outdated hardware. Bruteforcing some heavy hash almost knocked out my box
   for a good hour. Had to take a break and go out in the meanwhile. Or was this
   a good choice?

# What to do next
My plans:

 * Get some rest. Already did. Finally played Last of Us II, was waiting for me
   for about six months. Catalogued my entire e-book library which is really
   huge.
 * Study some PE. tib3rius LPE course is necessary. Extended mindmap and notes
   are to be done. Should get more practice, HTB boxes didn't seem that
   PE-oriented (got about 43 boxes in total, almost all the active ones and
   lots from TJ Null's list). Seek for FOSS resources like some awesome list
   repository on github.
 * Study some assembly and shellcode making. Try to investigate why reverse
   shell payload was crashing as well as some encoders. Guess that spending
   metasploit on a BO machine was overkill.
