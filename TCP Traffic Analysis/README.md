# tcpTrafficAnalysis

tcpTrafficAnalysis is a tool that, when given a TCP trace file, will find out:
<ol>
        <li>The state of the connection</li>
        <li>The starting time, ending time, and duration of each complete connection</li>
        <li>the number of packets sent in each direction on each complete connection, as well as the totalpackets </li>
        <li>the number of data bytes sent in each direction on each complete connection, as well as the total bytes (Excluding TCP and IP headers).</li>
        <li>The number of reset TCP connections observed in a trace</li>
        <li>The number of TCP connectons steill open at the end of the trace capture</li>
        <li>The number of complete TCP connections</li>
        <li>The minimum, mean, and maximum timedurations, RTT values, packet numbers sent, and window sizes from the complete connections</li>
</ol>

## Usage
To compile and run the program,
<ol>
    <li>Open a bash terminal,</li>
    <li>In the terminal, in the folder where tcpTrafficAnalysis.py is kept, write: </li>
</ol>

```
python3 tcpTrafficAnalysis.py tcptrace.cap
```

### Input
tcpTrafficAnalysis will only accept inputs that are cap files

### Output
Upon the running of this program, information about connections will be printed out. A summary of the information found out will appear at the very bottom of the result.

For example*:
```
--- B: Connections' Details ---

 --- Connection 1 --- 

Source Address: 192.168.1.164

Destination Address: 142.104.5.64

Source Port: 1200

Destination Port: 80

Status: {'ACK': 130, 'RST': 1, 'SYN': 2, 'FIN': 1}
Status: S2F1

Start Time: 0.0 seconds

End Time: 45.054007 seconds

Duration: 45.054007 seconds

Number of packets sent from Source to Destination: 54

Number of packets sent from Destination to Source: 77

Total Number of Packets: 131
Number of data bytes sent from Source to Destination: 3063

Number of data bytes sent from Destination to Source: 100545

Total Number of Data Bytes: 103608
END


--- HIDDEN FOR READABILITY ---


 --- Connection 8 --- 

Source Address: 192.168.1.164

Destination Address: 142.104.105.208

Source Port: 1207

Destination Port: 80

Status: {'ACK': 7, 'RST': 1, 'SYN': 2, 'FIN': 0}
Status: S2F0

 --- Connection was NOT Completed and is still Open --- 
END


--- HIDDEN FOR READABILITY --- 


--- A: Total Number of Connections: 48---

--- C: General ---

     Total number of complete TCP connections: 32

     Total Number of reset TCP connections: 34

     Total Number of open TCP connections: 16

--- D: Complete TCP Connections ---

     ------

     Minimum time duration: 0.014006 seconds

     Mean time duration: 7.191411 seconds

     Maximum time duration: 45.054007 seconds


     ------

     Minimum RTT Value: 1.5999999988025593e-05

     Mean RTT Value: 0.015043

     Maximum RTT Value: 0.144447


     ------

     Minimum number of packets including both send and received: 8

     Mean number of packets including both send and received: 37.3125

     Maximum number of packets including both send and received: 239


     ------

     Minimum receive window size including both send and received: 0

     Mean receive window size including both send and received: 15277.688442

     Maximum receive window size including both send and received: 64240


```

*In the example, certain parts of the output have been hidden for readbility purposes

