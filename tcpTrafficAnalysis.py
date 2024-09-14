import struct
import sys

import struct

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self, buffer):
        self.get_IP(buffer[12:16], buffer[16:20])
        self.ip_header_len = (buffer[0] & 0x0F) * 4 #*32 / 8 = # of bytes
        self.total_len = (buffer[2] << 8) + buffer[3]
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
 
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
   
class packet():
    
    Ethernet_Header =  None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    payload_length = 0
    
    
    def __init__(self, buffer, order):

        self.Ethernet_Header = buffer[:14]
        self.IP_header = IP_Header(buffer[14:])
        offset = self.IP_header.ip_header_len+14
        self.TCP_header = TCP_Header(buffer[offset:], order)
        self.payload_length = self.IP_header.total_len - self.IP_header.ip_header_len - self.TCP_header.data_offset
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        self.timestamp = round(buffer1+buffer2*0.000001-orig_time,6)

    def packet_No_set(self,number):
        self.packet_No = number
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)


class Global_Header:
    magic_number = 0
    version_major = 0
    version_minor = 0
    thiszone = 0
    sigfigs = 0
    snaplen = 0
    network = 0

    def __init__(self, buffer) -> None:
        (magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network) = struct.unpack("llhhlll", buffer)


class Packet_Header:
    ts_sec = 0
    ts_usec = 0
    incl_len = 0
    orig_len = 0
    
    def __init__(self, buffer, endianness):
       (self.ts_sec, self.ts_usec, self.incl_len, self.orig_len) = struct.unpack(endianness+"llll", buffer)


    def ts_sec_set(self, buffer):
        self.ts_sec = buffer

    def ts_usec_set(self, buffer):
        self.ts_usec = buffer

    def incl_len_set(self, buffer):
        self.incl_len = buffer

    def orig_len_set(self, buffer):
        self.orig_len = buffer

def rtt_finder(packets_list):
    syn_packets = {}  
    rtt_values = []  

    for packet in packets_list:
        if packet.TCP_header.flags.get("SYN") == 1:
            syn_packets[packet.TCP_header.seq_num+1] = packet.timestamp

        if packet.TCP_header.flags.get("ACK") == 1:
            ack_seq_num = packet.TCP_header.ack_num
            if ack_seq_num in syn_packets:
                rtt = packet.timestamp - syn_packets[ack_seq_num]
                rtt_values.append(rtt)

    return rtt_values

def get_window_sizes(packets_list):
    window = []
    for packet in packets_list:
        window.append(packet.TCP_header.window_size)

    return window

def packet_data_reader(packet_dictionary):
    total_connections = len(packet_dictionary)
    complete_connections = 0
    reset_connections = 0
    open_connections = 0
    complete_connection_dictionary = {}
    connection_no = 0
    state_dictionary = {'ACK': 0, 'RST': 0, 'SYN': 0, 'FIN': 0}
    duration_list = []
    rtt_list = []
    packets_list = []
    window_size_list = []

    print("--- B: Connections' Details ---\n")

    for connection in packet_dictionary:
        source_packet_count = 0
        dest_packet_count = 0
        source_data_count = 0
        dest_data_count = 0
        connection_no = connection_no + 1

        source_add= packet_dictionary[connection][0].IP_header.src_ip
        dest_add = packet_dictionary[connection][0].IP_header.dst_ip
        source_port = packet_dictionary[connection][0].TCP_header.src_port
        dest_port = packet_dictionary[connection][0].TCP_header.dst_port

        print(" --- Connection " + str(connection_no) + " --- \n")
        print("Source Address: " + str(source_add) + "\n")
        print("Destination Address: " + str(dest_add) + "\n")
        print("Source Port: " + str(source_port) + "\n")
        print("Destination Port: " + str(dest_port) + "\n")

        for packets in packet_dictionary[connection]:
            if packets.IP_header.src_ip == source_add:
                source_packet_count = source_packet_count+1
                source_data_count = source_data_count + packets.payload_length
            else:
                dest_packet_count = dest_packet_count+1
                dest_data_count = dest_data_count + packets.payload_length

            for key in packets.TCP_header.flags:
                state_dictionary[key] = state_dictionary[key] + packets.TCP_header.flags[key]

        print("Status: " + str(state_dictionary))
        print("Status: S" + str(state_dictionary["SYN"]) + "F" + str(state_dictionary["FIN"]) + "\n")
        
        if state_dictionary["SYN"] > 0 and state_dictionary["FIN"] >0:
            complete_connection_dictionary[connection] = packet_dictionary[connection]
            
            start = round(packet_dictionary[connection][0].timestamp, 6)
            end = round(packet_dictionary[connection][len(packet_dictionary[connection])-1].timestamp, 6)
            duration = round(end-start, 6)
            duration_list.append(duration)

            print("Start Time: " + str(start) + " seconds\n")
            print("End Time: " + str(end) + " seconds\n")
            print("Duration: " + str(duration) + " seconds\n")

            print("Number of packets sent from Source to Destination: " + str(source_packet_count) + "\n" )
            print("Number of packets sent from Destination to Source: " + str(dest_packet_count) + "\n" )
            print("Total Number of Packets: " + str(len(packet_dictionary[connection])))
            packets_list.append(len(packet_dictionary[connection]))
            print("Number of data bytes sent from Source to Destination: " + str(source_data_count) + "\n" )
            print("Number of data bytes sent from Destination to Source: " + str(dest_data_count) + "\n" )
            print("Total Number of Data Bytes: " + str(source_data_count + dest_data_count))

            rtt = rtt_finder(packet_dictionary[connection])
            rtt_list.extend(rtt)

            window = get_window_sizes(packet_dictionary[connection])
            window_size_list.extend(window)
        else:
            print(" --- Connection was NOT Completed and is still Open --- ")
        
        if state_dictionary["RST"] > 0:
            reset_connections = reset_connections + 1

        state_dictionary = {'ACK': 0, 'RST': 0, 'SYN': 0, 'FIN': 0}
        print("END\n\n")
        

    complete_connections = len(complete_connection_dictionary)
    open_connections = total_connections - complete_connections       
    print("--- A: Total Number of Connections: " +str(total_connections)+ "---\n")
 

    print("--- C: General ---\n")
    print("     Total number of complete TCP connections: " + str(complete_connections) + "\n")
    print("     Total Number of reset TCP connections: " + str(reset_connections) + "\n")
    print("     Total Number of open TCP connections: " + str(open_connections)+"\n")

    print("--- D: Complete TCP Connections ---\n")

    print("     ------\n")
    print("     Minimum time duration: " + str(min(duration_list)) + " seconds\n")
    print("     Mean time duration: "+str(round(sum(duration_list)/len(duration_list), 6))+" seconds\n")
    print("     Maximum time duration: " + str(max(duration_list)) + " seconds\n\n")

    print("     ------\n")
    print("     Minimum RTT Value: {}\n".format(min(rtt_list)))
    print("     Mean RTT Value: {}\n".format(round(abs(sum(rtt_list)/len(rtt_list)),6)))
    print("     Maximum RTT Value: {}\n\n".format(round(max(rtt_list), 6)))

    print("     ------\n")
    print("     Minimum number of packets including both send and received: {}\n".format(min(packets_list)))
    print("     Mean number of packets including both send and received: {}\n".format(round(sum(packets_list)/len(packets_list), 6)))
    print("     Maximum number of packets including both send and received: {}\n\n".format(max(packets_list)))
    
    print("     ------\n")
    print("     Minimum receive window size including both send and received: {}\n".format(min(window_size_list)))
    print("     Mean receive window size including both send and received: {}\n".format(round(sum(window_size_list) / len(window_size_list), 6)))
    print("     Maximum receive window size including both send and received: {}\n".format(max(window_size_list)))

def read_packets(filename):
    packet_dictionary = {}
    packet_count = 0
    f = open(filename, "rb")
    global_header = Global_Header(f.read(24))

    if struct.pack("l", global_header.magic_number).startswith(bytes(b"\xa1")):
        endianness = ">" # Big endian
        order = 'big'

    else :
        endianness = "<" # Little Endian
        order = "little"

    header = f.read(16)
    ph = Packet_Header(header, endianness)
    while (ph.incl_len != 0 and header != ""):
        data = packet(f.read(ph.incl_len), order)
        if data == b"":
            break

        packet_count = packet_count+1
        data.packet_No_set(packet_count)
        if (data.packet_No == 1):
            orig_time = ph.ts_sec+ph.ts_usec*0.000001
        data.timestamp_set(ph.ts_sec, ph.ts_usec, orig_time)
        forward = (data.IP_header.src_ip, data.TCP_header.src_port, data.IP_header.dst_ip, data.TCP_header.dst_port)
        reverse = (data.IP_header.dst_ip, data.TCP_header.dst_port, data.IP_header.src_ip, data.TCP_header.src_port)
        
        if forward not in packet_dictionary and reverse not in packet_dictionary:
            packet_dictionary[forward] = [data]
        elif forward in packet_dictionary:
            packet_dictionary[forward].append(data)
        else:
            packet_dictionary[reverse].append(data)
        
        header = f.read(16) # get next header

        if header == b"":
            break
        ph = Packet_Header(header, endianness)

    packet_data_reader(packet_dictionary)


def main():
    if (len(sys.argv) < 2) :
        print("No file given!")
        sys.exit()
    else:
        tracefile = sys.argv[1]
    read_packets(tracefile)


main()