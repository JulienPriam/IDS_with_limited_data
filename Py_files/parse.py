import socket
import dpkt
import datetime

import numpy as np
import pandas as pd

# filename = '/home/eii/Documents/Strathclyde/Strath_Project/Dataset_test/smallFlows.pcap'  # smaller data for test
# filename = '/home/eii/Documents/Strathclyde/Strath_Project/Dataset/Thursday-WorkingHours2.pcap'    #real dataset
filename = '/home/eii/Documents/Strathclyde/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'


def parse_pcap(i):
    # Create a Dataframe
    cols = ['time', 'IP_tos', 'IP_len', 'IP_id', 'IP_df', 'IP_mf', 'IP_frag_offset', 'IP_off', 'IP_ttl',
            'TCP_src', 'TCP_dst', 'TCP_ack', 'TCP_flags']
    df = pd.DataFrame(index=np.arange(i), columns=cols)

    # Open pcap file
    f = open(filename, 'rb')

    # Loop to parse the file on each packet
    j = 0
    for timestamp, buf in dpkt.pcap.Reader(f):
        eth = dpkt.ethernet.Ethernet(buf)
        # Make sure the Ethernet frame contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        if j == i:
            break

        new_row = []

        # Get the timestamp of the frame
        new_row.append(str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Get the IP Header information
        # new_row.append(str(ip.version))
        # new_row.append(str(ip.ihl))
        new_row.append(str(ip.tos))
        new_row.append(str(ip.len))
        new_row.append(str(ip.id))
        new_row.append(str(bool(ip.offset & dpkt.ip.IP_DF)))
        new_row.append(str(bool(ip.offset & dpkt.ip.IP_MF)))
        new_row.append(str(ip.offset & dpkt.ip.IP_OFFMASK))
        # new_row.append(str(ip.flags))
        new_row.append(str(ip.offset))
        new_row.append(str(ip.ttl))
        # new_row.append(str(ip.proto))
        # new_row.append(str(ip.hc))

        # Unpack the data within the IP frame (TCP packet)
        TCP = ip.data
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

        df.loc[j] = new_row
        j += 1

    f.close()
    return df


def parse_pcap_csv():
    df = pd.read_csv(filename)
    return df
