# Traceroute IP Datagram Analysis

This Python program is designed to analyze trace data of IP datagrams generated by Traceroute. It performs various analyses and extracts information from the trace file. Below are the functionalities and instructions on how to use the program.

## Functionalities

### 1. Extracting IP Addresses
- Lists the IP addresses of the source node, ultimate destination node, and intermediate destination nodes ordered by hop count to the source node in increasing order.

### 2. Protocol Field Values
- Lists the set of values found in the protocol field of the IP headers.

### 3. Fragmentation Analysis
- Counts the number of fragments created from the original datagram.
- Displays the offset of the last fragment in bytes. (0 if the datagram is not fragmented)

### 4. Round-Trip Time (RTT) Calculation
- Calculates the average and standard deviation of RTT between the source node and intermediate/ultimate destination nodes.

## Usage
1. Ensure you have Python installed.
2. Run the program by providing the trace file as a command-line argument.

Example:
```bash
python traceroute.py trace_file.pcap
```

## Output Format
The program generates output similar to the following format

```bash
The IP address of the source node: 192.168.1.12
The IP address of the ultimate destination node: 12.216.216.2
The IP addresses of the intermediate destination nodes:
Router 1: 24.218.01.102
Router 2: 24.221.10.103
Router 3: 12.216.118.1

The values in the protocol field of IP headers:
1: ICMP
17: UDP

The number of fragments created from the original datagram is: 3
The offset of the last fragment is: 3680

Average RTT between 192.168.1.12 and 24.218.01.102: 50 ms, s.d.: 5 ms
Average RTT between 192.168.1.12 and 24.221.10.103: 100 ms, s.d.: 6 ms
Average RTT between 192.168.1.12 and 12.216.118.1: 150 ms, s.d.: 5 ms
Average RTT between 192.168.1.12 and 12.216.216.2: 200 ms, s.d.: 15 ms

```