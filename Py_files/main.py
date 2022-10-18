import socket
import dpkt
import datetime
import pandas as pd

from dpkt import compat_ord

filename = '/home/eii/Documents/Strathclyde/Strath_Project/Dataset_test/smallFlows.pcap'  # smaller data for test
# filename = '/home/eii/Documents/Strathclyde/Strath_Project/Dataset/Thursday-WorkingHours2.pcap'    #real dataset


def parse_pcap(i):

    # Create a Dataframe
    cols = ['time', 'IPtos', 'IPlen', 'IPid', 'IPoff', 'IPttl', 'IPsrc', 'IPdst',
            'TCPsrc', 'TCPdst', 'TCPack', 'TCPflags']
    df = pd.DataFrame(columns=cols)


    # Open pcap file
    f = open(filename, 'rb')

    # Loop to parse the file on each packet
    for timestamp, buf in dpkt.pcap.Reader(f):
        if i == 0:
            break
        else:
            i -= 1

        new_row = []
        # Print out the timestamp in UTC
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet frame contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Get the timestamp of the frame
        new_row.append(str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Now unpack the data within the Ethernet frame (the IP packet)
        ip = eth.data
        # new_row.append(str(ip.version))
        # new_row.append(str(ip.ihl))
        new_row.append(str(ip.tos))
        new_row.append(str(ip.len))
        new_row.append(str(ip.id))
        # new_row.append(str(ip.flags))
        new_row.append(str(ip.offset))
        new_row.append(str(ip.ttl))
        # new_row.append(str(ip.proto))
        # new_row.append(str(ip.hc))
        new_row.append(socket.inet_ntoa(ip.src))
        new_row.append(socket.inet_ntoa(ip.dst))


        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        # Unpack the data within the IP frame (TCP packet)
        TCP = ip.data
        # 'TCPsrc', 'TCPdst', 'TCPseq', 'TCPack', 'TCPdo', 'TCPrsv', 'TCPflags', 'TCPwindow', 'TCPchecksum', 'TCPup']
        new_row.append(TCP.sport)
        new_row.append(TCP.dport)
        # new_row.append(TCP.sequence)
        new_row.append(TCP.ack)
        # new_row.append(TCP.do)
        # new_row.append(TCP.rsv)
        new_row.append(TCP.flags)
        # new_row.append(TCP.window)
        # new_row.append(TCP.checksum)
        # new_row.append(TCP.up)

        new_df = pd.DataFrame([new_row], columns=cols)
        df = pd.concat([df, new_df], ignore_index=True)

    return df


df = parse_pcap(20000)
print(df)
