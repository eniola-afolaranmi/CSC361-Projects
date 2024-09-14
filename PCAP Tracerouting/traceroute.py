import struct
import sys
import math
import struct
from statistics import mean, stdev

class IP_Header:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>
    protocol = None  # <type 'int'>
    ttl = None  # <type 'int'>
    identification = None  # <type 'int'>
    fragmented = False  # <type 'bool'>
    fragment_offset = None  # <type 'int'>

    def __init__(self, buffer):
        self.get_IP(buffer[12:16], buffer[16:20])
        self.ip_header_len = (buffer[0] & 0x0F) * 4  # *32 / 8 = # of bytes
        self.total_len = (buffer[2] << 8) + buffer[3]
        self.protocol = buffer[9]
        self.ttl = buffer[8]
        self.identification = (buffer[4] << 8) + buffer[5]

        flags_offset = (buffer[6] << 8) + buffer[7]
        self.fragment_offset = flags_offset & 0x1FFF  # Extracting offset from the flags
        self.fragmented = (flags_offset & 0x2000) != 0  # Check fragmentation bit

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        s_ip = str(src_addr[0]) + '.' + str(src_addr[1]) + '.' + str(src_addr[2]) + '.' + str(src_addr[3])
        d_ip = str(dst_addr[0]) + '.' + str(dst_addr[1]) + '.' + str(dst_addr[2]) + '.' + str(dst_addr[3])
        self.ip_set(s_ip, d_ip)

class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self, buffer, order):
        self.src_port = (buffer[0] << 8) + buffer[1]
        self.dst_port = (buffer[2] << 8) + buffer[3]
        self.seq_num = struct.unpack(">I",buffer[4:8])[0]
        self.ack_num = struct.unpack(">I",buffer[8:12])[0]
        self.data_offset = (buffer[12] >> 4) * 4
        value = struct.unpack("B",buffer[13:14])[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4

        self.flags = {"ACK": ack,
                      "RST": rst,
                      "SYN": syn,
                      "FIN": fin}
        self.window_size = struct.unpack('H',buffer[15:16]+buffer[14:15])[0]
        self.checksum = int.from_bytes(buffer[16:18], byteorder=order)
        self.ugp = int.from_bytes(buffer[18:20], byteorder=order)
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)

        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   
class packet:
    def __init__(self, buffer, order, ph):
        self.Packet_Header = ph
        self.Ethernet_Header = buffer[:14]
        self.IP_header = IP_Header(buffer[14:])
        offset = self.IP_header.ip_header_len + 14
        self.TCP_header = TCP_Header(buffer[offset:], order)
        self.payload_length = self.IP_header.total_len - self.IP_header.ip_header_len - self.TCP_header.data_offset
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.fragment_offsets = {}
        self.icmp_timestamps = {}

    def timestamp_set(self, buffer1, buffer2, orig_time):
        self.timestamp = round(buffer1 + buffer2 * 0.000001 - orig_time, 6)

    def packet_No_set(self, number):
        self.packet_No = number

    def associate_icmp_timestamp(self, icmp_timestamp, fragment_offset):
        self.icmp_timestamps[fragment_offset] = icmp_timestamp

    def get_RTT_values(self):
        rtt_values = {}
        for fragment_offset, frag_timestamp in self.icmp_timestamps.items():
            if fragment_offset in self.fragment_offsets:
                rtt = frag_timestamp - self.fragment_offsets[fragment_offset]
                rtt_values[fragment_offset] = round(rtt, 8)
        return rtt_values

    @staticmethod
    def find_related_icmp_packet(fragment_packet, packet_dictionary):
        for key, packets in packet_dictionary.items():
            for packet in packets:
                if (
                    packet.IP_header.protocol == 1
                    and packet.IP_header.src_ip == fragment_packet.IP_header.dst_ip
                    and packet.IP_header.dst_ip == fragment_packet.IP_header.src_ip
                ):
                    return packet
        return None

    def associate_icmp_with_fragments(self, packet_dictionary):
        for packets in packet_dictionary.values():
            for packet_obj in packets:
                if packet_obj.IP_header.fragmented:
                    icmp_packet = packet.find_related_icmp_packet(packet_obj, packet_dictionary)
                    if icmp_packet:
                        packet_obj.icmp_timestamps = packet_obj.icmp_timestamps or {}
                        packet_obj.fragment_offsets = packet_obj.fragment_offsets or {}
                        packet_obj.icmp_timestamps[packet_obj.IP_header.fragment_offset] = icmp_packet.timestamp
                        packet_obj.fragment_offsets[packet_obj.IP_header.fragment_offset] = packet_obj.timestamp

class Global_Header:
    magic_number = 0
    version_major = 0
    version_minor = 0
    thiszone = 0
    sigfigs = 0
    snaplen = 0
    network = 0

    def __init__(self, buffer) -> None:
        (magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network) = struct.unpack("iihhiii", buffer)

class Packet_Header:
    ts_sec = 0
    ts_usec = 0
    incl_len = 0
    orig_len = 0
    
    def __init__(self, buffer, endianness):
       (self.ts_sec, self.ts_usec, self.incl_len, self.orig_len) = struct.unpack(endianness+"iiii", buffer)


    def ts_sec_set(self, buffer):
        self.ts_sec = buffer

    def ts_usec_set(self, buffer):
        self.ts_usec = buffer

    def incl_len_set(self, buffer):
        self.incl_len = buffer

    def orig_len_set(self, buffer):
        self.orig_len = buffer
      


def extract_ip_addresses(packet_dictionary):
    protocol_names = {
        1: "ICMP",
        # Add more mappings as needed
    }
    source_node = None
    ultimate_destination = {}
    intermediate_nodes = {}
    skip = 0
    # Iterate through packet_dictionary to identify source and destination nodes
    for key, packets in packet_dictionary.items():
        for packet in packets:
            src_ip = packet.IP_header.src_ip
            dst_ip = packet.IP_header.dst_ip
            protocol = packet.IP_header.protocol

            if source_node is None:
                source_node = packet
                ult_dest = dst_ip

            if src_ip == ult_dest:
                if src_ip not in ultimate_destination:
                    ultimate_destination[src_ip] = [packet]
                else:
                    ultimate_destination[src_ip].append(packet)

            # Check if the packet meets the protocol conditions
            if src_ip != dst_ip and protocol in protocol_names and src_ip != source_node.IP_header.src_ip and src_ip != source_node.IP_header.dst_ip:
                if src_ip not in intermediate_nodes:
                    intermediate_nodes[src_ip] = [packet]
                else:
                    intermediate_nodes[src_ip].append(packet)
    
    return ultimate_destination, source_node, intermediate_nodes

def extract_protocol_values(packet_dictionary):
    unique_protocols = {}

    protocol_names = {
        17: "UDP",
        1: "ICMP",
        # Add more mappings as needed
    }

    # Iterate through packet_dictionary to extract unique protocol values
    for key, packets in packet_dictionary.items():
        for packet in packets:
            # Extract protocol value from each packet
            protocol_value = packet.IP_header.protocol
            if protocol_value not in unique_protocols and protocol_value in protocol_names:
                # Add the protocol value to the dictionary with a placeholder name
                unique_protocols[protocol_value] = protocol_names[protocol_value]

    return dict(sorted(unique_protocols.items()))

def count_fragments(packet_dictionary):
    fragments_created = 0
    last_fragment_offset = 0

    # Iterate through packets to count fragments and find the last fragment's offset
    for key, packets in packet_dictionary.items():
        for packet in packets:
            # Check if the packet is fragmented
            if packet.IP_header.fragmented:
                fragments_created += 1
                # Set last_fragment_offset if the current fragment offset is greater
                if packet.IP_header.fragment_offset > last_fragment_offset:
                    last_fragment_offset = packet.IP_header.fragment_offset

    return fragments_created, last_fragment_offset


def calculate_rtt(source_node, intermediate_nodes, ultimate_destination):
    rtt_values = {}
    intermediate_nodes.update(ultimate_destination)
    orig_time = source_node.Packet_Header.ts_sec + source_node.Packet_Header.ts_usec * 0.000001

    for intermediate_node, packets in intermediate_nodes.items():
        for packet in packets:
            time1 = packet.Packet_Header.ts_sec + packet.Packet_Header.ts_usec * 0.000001
            time = round(abs(time1 - orig_time), 6)  # Taking absolute value

            if (source_node.IP_header.src_ip, packet.IP_header.src_ip) not in rtt_values:
                rtt_values[(source_node.IP_header.src_ip, packet.IP_header.src_ip)] = [time]
            else:
                rtt_values[(source_node.IP_header.src_ip, packet.IP_header.src_ip)].append(time)

    return rtt_values


def format_output(source_node, ultimate_destination, intermediate_nodes, protocol_values, fragments_created, last_fragment_offset, rtt):
    output = []

    # IP addresses of source, ultimate destination, and intermediate nodes
    output.append(f" --- The IP address of the source node: {source_node.IP_header.src_ip} --- ")
    output.append(f" --- The IP address of the ultimate destination node: {source_node.IP_header.dst_ip} ---")
    output.append(" --- The IP addresses of the intermediate destination nodes: --- ")
    for i, node in enumerate(list(intermediate_nodes), 1):
        output.append(f"    Router {i}: {node}")

    # Protocol field values
    output.append("\n --- The values in the protocol field of IP headers: --- ")
    for protocol, protocol_name in protocol_values.items():
        output.append(f"    {protocol}: {protocol_name}")

    # Number of fragments and last fragment offset
    if fragments_created:
        output.append(f"\n --- The number of fragments created from the original datagram is: {fragments_created} ---")
        output.append(f" --- The offset of the last fragment is: {last_fragment_offset} --- ")
    else:
        output.append(f"\n --- No fragments found! ---")

    # RTT values
    output.append("\n --- The RTT values between nodes: ---")
    for node_pair, (avg_rtt, std_dev) in rtt.items():
        src_node, dst_node = node_pair
        output.append(f"    The avg RTT between {src_node} and {dst_node} is: {avg_rtt:.2f} ms, the s.d. is: {std_dev:.2f} ms")

    return "\n".join(output)

def analyze_trace(packet_dictionary):
    for packets in packet_dictionary.values():
        for packet_obj in packets:
            packet_obj.associate_icmp_with_fragments(packet_dictionary)
    
    ultimate_dest, source_node, intermediate_nodes = extract_ip_addresses(packet_dictionary)
    protocols = extract_protocol_values(packet_dictionary)
    fragments, fragments_offset = count_fragments(packet_dictionary)
    rtt = calculate_rtt(source_node, intermediate_nodes, ultimate_dest)
    for node_pair, rtt_list in rtt.items():
        avg_rtt = mean(rtt_list)
        std_dev_rtt = stdev(rtt_list) if len(rtt_list) > 1 else 0
        rtt[node_pair] = (avg_rtt, std_dev_rtt)
    output = format_output(source_node, ultimate_dest, intermediate_nodes, protocols, fragments, fragments_offset, rtt)
    print(output)

def read_packets(filename):
    protocol_names = {
        17: "UDP",
        1: "ICMP",
    }

    packet_dictionary = {}
    packet_count = 0
    f = open(filename, "rb")
    global_header = Global_Header(f.read(24))

    if struct.pack("l", global_header.magic_number).startswith(bytes(b"\xa1")):
        endianness = ">"  # Big endian
        order = 'big'
    else:
        endianness = "<"  # Little Endian
        order = "little"

    header = f.read(16)
    ph = Packet_Header(header, endianness)
    while (ph.incl_len != 0 and header != ""):
        data = packet(f.read(ph.incl_len), order, ph)
        if data == b"":
            break

        packet_count = packet_count + 1
        data.packet_No_set(packet_count)
        # if (data.packet_No == 1):
        #     orig_time = ph.ts_sec + ph.ts_usec * 0.000001
        # data.timestamp_set(ph.ts_sec, ph.ts_usec, orig_time)
        forward = (data.IP_header.src_ip, data.TCP_header.src_port, data.IP_header.dst_ip, data.TCP_header.dst_port)
        reverse = (data.IP_header.dst_ip, data.TCP_header.dst_port, data.IP_header.src_ip, data.TCP_header.src_port)

        if data.IP_header.protocol in protocol_names:
            if forward not in packet_dictionary and reverse not in packet_dictionary:
                packet_dictionary[forward] = [data]
            elif forward in packet_dictionary:
                packet_dictionary[forward].append(data)
            else:
                packet_dictionary[reverse].append(data)

        header = f.read(16)  # get next header

        if header == b"":
            break
        ph = Packet_Header(header, endianness)

 
    analyze_trace(packet_dictionary)

def main():
    if (len(sys.argv) < 2) :
        print("No file given!")
        sys.exit()
    else:
        tracefile = sys.argv[1]
    read_packets(tracefile)


main()