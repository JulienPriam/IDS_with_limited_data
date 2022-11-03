import socket
import dpkt
import datetime

import time
import numpy as np
import pandas as pd
from dpkt.utils import inet_to_str

start_time = time.time()

# file_path = '/home/eii/Documents/Strathclyde/Project_test/Dataset/smallFlows.pcap'
file_path = '/home/eii/Documents/Strathclyde/Strath_Project/Dataset/Thursday-WorkingHours2.pcap'
global_t0 = 0


def get_mean(l):
    if len(l) == 0:
        return 0
    elif len(l) == 1:
        return l[0]
    else:
        return np.absolute(np.diff(np.sort(l))).mean()


pkt_num_list = []
time_list = []
ip_src_list = []
ip_dst_list = []
ip_len_list = []
proto_list = []
prt_src_list = []
prt_dst_list = []
tcp_psh_flag_list = []
tcp_rst_flag_list = []
tcp_urg_flag_list = []

packet_dict = {'pkt_num': pkt_num_list,
               'time': time_list,
               'ip_src': ip_src_list,
               'ip_dst': ip_dst_list,
               'ip_len': ip_len_list,
               'proto': proto_list,
               'prt_src': prt_src_list,
               'prt_dst': prt_dst_list,
               'tcp_psh': tcp_psh_flag_list,
               'tcp_rst': tcp_rst_flag_list,
               'tcp_urg': tcp_urg_flag_list}

# Open pcap file
f = open(file_path, 'rb')
pcap_file = dpkt.pcap.Reader(f)

# Loop to parse the file on each packet
count = 1
udpcount = 0
tcpcount = 0
for timestamp, buf in pcap_file:
    if count == 1:
        global_t0 = datetime.datetime.utcfromtimestamp(timestamp)


    eth = dpkt.ethernet.Ethernet(buf)
    # Make sure the Ethernet frame contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        continue

    # Now unpack the data within the Ethernet frame (the IP packet)
    ip = eth.data
    if isinstance(ip.data, dpkt.icmp.ICMP):
        continue

    if isinstance(ip.data, dpkt.igmp.IGMP):
        continue

    if not isinstance(ip.data, dpkt.tcp.TCP) and not isinstance(ip.data, dpkt.udp.UDP):
        continue

    pkt_num_list.append(count)
    time_list.append(timestamp)
    ip_src_list.append(inet_to_str(ip.src))
    ip_dst_list.append(inet_to_str(ip.dst))
    ip_len_list.append(len(eth.data))

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        tcpcount += 1
        proto_list.append('TCP')
        prt_src_list.append(tcp.sport)
        prt_dst_list.append(tcp.dport)
        # syn_flag = ( l4.flags & dpkt.tcp.TH_SYN ) != 0
        rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
        psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
        # ack_flag = ( l4.flags & dpkt.tcp.TH_ACK ) != 0
        urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
        tcp_psh_flag_list.append(psh_flag)
        tcp_rst_flag_list.append(rst_flag)
        tcp_urg_flag_list.append(urg_flag)

    if isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        udpcount += 1
        proto_list.append('UDP')
        prt_src_list.append(udp.sport)
        prt_dst_list.append(udp.dport)
        # Need to add a value to these to maintain consistent rows across lists - will add zeros
        tcp_psh_flag_list.append(False)
        tcp_rst_flag_list.append(False)
        tcp_urg_flag_list.append(False)

    count += 1

f.close()
pkt_dict_time = time.time()
print('\nDictionary of packets created in {} seconds'.format(pkt_dict_time - start_time))
print('Number of TCP & UDP packets : {}'.format(len(packet_dict['pkt_num'])))


tuplist_flowid = {}
flow_count = 0

flow_list_dict = {}
tcpflowcount = 0
udpflowcount = 0

for index in range(len(packet_dict['pkt_num'])):
    mytup = (packet_dict['ip_src'][index], packet_dict['ip_dst'][index], packet_dict['prt_src'][index],
             packet_dict['prt_dst'][index], packet_dict['proto'][index])

    str_temp = "_".join(str(v) for v in mytup)
    if str_temp not in tuplist_flowid:
        tuplist_flowid[str_temp] = flow_count
        flow_list_dict[flow_count] = []
        flow_count += 1

    current_flow_id = tuplist_flowid[str_temp]
    flow_tup = (
        packet_dict['ip_src'][index], packet_dict['ip_dst'][index], packet_dict['prt_src'][index],
        packet_dict['prt_dst'][index], packet_dict['proto'][index], packet_dict['pkt_num'][index],
        packet_dict['time'][index], packet_dict['ip_len'][index], packet_dict['tcp_psh'][index],
        packet_dict['tcp_rst'][index], packet_dict['tcp_urg'][index], current_flow_id)

    flow_list_dict[current_flow_id].append(flow_tup)

    if len(flow_list_dict[current_flow_id]) == 1:
        if flow_list_dict[current_flow_id][0][4] == 'TCP':
            tcpflowcount += 1
        if flow_list_dict[current_flow_id][0][4] == 'UDP':
            udpflowcount += 1

del tuplist_flowid

"""
flow_list_dict = identify_flows()
print(flow_list_dict[0][1])
print(flow_list_dict[1][0])
print(flow_list_dict[0])
print(flow_list_dict[1])
"""

meta_list_time_0 = []

ip_src_list = []
ip_dst_list = []
prt_src_list = []
prt_dst_list = []
proto_list = []
num_pkts_list = []
mean_iat_list = []
std_iat_list = []
min_iat_list = []
max_iat_list = []
mean_offset_list = []
mean_pkt_len_list = []
std_pkt_len_list = []
min_pkt_len_list = []
max_pkt_len_list = []
num_bytes_list = []
num_psh_flags_list = []
num_rst_flags_list = []
num_urg_flags_list = []
processed_list = []

uniflow_dict = {'ip_src': ip_src_list,
                'ip_dst': ip_dst_list,
                'prt_src': prt_src_list,
                'prt_dst': prt_dst_list,
                'proto': proto_list,
                'num_pkts': num_pkts_list,
                'mean_iat': mean_iat_list,
                'std_iat': std_iat_list,
                'min_iat': min_iat_list,
                'max_iat': max_iat_list,
                'mean_offset': mean_offset_list,
                'mean_pkt_len': mean_pkt_len_list,
                'std_pkt_len': std_pkt_len_list,
                'min_pkt_len': min_pkt_len_list,
                'max_pkt_len': max_pkt_len_list,
                'num_bytes': num_bytes_list,
                'num_psh_flags': num_psh_flags_list,
                'num_rst_flags': num_rst_flags_list,
                'num_urg_flags': num_urg_flags_list,
                'processed': processed_list}

for index in flow_list_dict:
    flow_list = flow_list_dict[index]
    pkt = flow_list[0]

    length_list = []
    time_list = []
    psh_list = []
    rst_list = []
    urg_list = []
    for packet in flow_list_dict[index]:
        length_list.append(packet[7])
        time_list.append(packet[6])
        psh_list.append(packet[8])
        rst_list.append(packet[9])
        urg_list.append(packet[10])

    ip_src_list.append(flow_list_dict[index][0][0])
    ip_dst_list.append(flow_list_dict[index][0][1])
    prt_src_list.append(flow_list_dict[index][0][2])
    prt_dst_list.append(flow_list_dict[index][0][3])
    proto_list.append(flow_list_dict[index][0][4])
    num_pkts = len(flow_list_dict[index])
    num_pkts_list.append(num_pkts)
    mean_pkt_len_list.append(sum(length_list) / num_pkts)
    pkt_len_arry = np.array(length_list)
    std_pkt_len_list.append(float(np.std(pkt_len_arry)))
    min_pkt_len_list.append(float(min(pkt_len_arry)))
    max_pkt_len_list.append(float(max(pkt_len_arry)))
    num_bytes_list.append(sum(length_list))
    num_psh_flags_list.append(sum(psh_list))
    num_rst_flags_list.append(sum(rst_list))
    num_urg_flags_list.append(sum(urg_list))
    processed_list.append(False)

    if num_pkts > 1:
        time_list.sort(reverse=True)  # put times in descending order
        t_diff = abs(np.diff(time_list))
        mean_iat_list.append(sum(t_diff) / (num_pkts - 1))
        std_iat_list.append(np.std(t_diff))  # std dev of IAT
        min_iat_list.append(min(t_diff))
        max_iat_list.append(max(t_diff))
        # Kenzi's apparently good feature is the mean time between the first
        # packet and each sucessive packet: (t2-t1) + (t3-t1) + (t4-t1) / n
        time_list.sort()  # sort into ascending order now
        t0 = time_list[0]
        time_total = 0.0
        for f in range(1, num_pkts):
            time_total += abs(t0 - time_list[f])
        mean_offset_list.append(time_total / (num_pkts - 1))

    else:
        mean_iat_list.append(0.0)
        std_iat_list.append(0.0)
        min_iat_list.append(0.0)
        max_iat_list.append(0.0)
        mean_offset_list.append(0.0)

    meta_list_time_0.append((datetime.datetime.utcfromtimestamp(pkt[6]) - global_t0).seconds)

uniflow_dict_time = time.time()
print('\nDictionary of uniflows created in {} seconds'.format(uniflow_dict_time - pkt_dict_time))
print('Number of uniflows : {}'.format(len(uniflow_dict['ip_src'])))


ip_src_list = []
ip_dst_list = []
prt_src_list = []
prt_dst_list = []
proto_list = []
fwd_num_pkts_list = []
bwd_num_pkts_list = []
fwd_mean_iat_list = []
bwd_mean_iat_list = []
fwd_std_iat_list = []
bwd_std_iat_list = []
fwd_min_iat_list = []
bwd_min_iat_list = []
fwd_max_iat_list = []
bwd_max_iat_list = []
fwd_mean_offset_list = []
bwd_mean_offset_list = []
fwd_mean_pkt_len_list = []
bwd_mean_pkt_len_list = []
fwd_std_pkt_len_list = []
bwd_std_pkt_len_list = []
fwd_min_pkt_len_list = []
bwd_min_pkt_len_list = []
fwd_max_pkt_len_list = []
bwd_max_pkt_len_list = []
fwd_num_bytes_list = []
bwd_num_bytes_list = []
fwd_num_psh_flags_list = []
bwd_num_psh_flags_list = []
fwd_num_rst_flags_list = []
bwd_num_rst_flags_list = []
fwd_num_urg_flags_list = []
bwd_num_urg_flags_list = []
sec_1_ip_src_list = []
sec_2_ip_src_list = []
sec_3_ip_src_list = []
sec_4_ip_src_list = []
sec_5_ip_src_list = []
"""
num_src_flows_60_list = []
num_src_flows_120_list = []
num_src_flows_180_list = []
num_src_flows_240_list = []
num_src_flows_300_list = []
src_ip_dst_prt_delta_60_list = []
src_ip_dst_prt_delta_120_list = []
src_ip_dst_prt_delta_180_list = []
src_ip_dst_prt_delta_240_list = []
src_ip_dst_prt_delta_300_list = []
num_src_flows_list = []
src_ip_dst_prt_delta_list = []
"""

biflow_dict = {'ip_src': ip_src_list,
               'ip_dst': ip_dst_list,
               'prt_src': prt_src_list,
               'prt_dst': prt_dst_list,
               'proto': proto_list,
               'fwd_num_pkts': fwd_num_pkts_list,
               'bwd_num_pkts': bwd_num_pkts_list,
               'fwd_mean_iat': fwd_mean_iat_list,
               'bwd_mean_iat': bwd_mean_iat_list,
               'fwd_std_iat': fwd_std_iat_list,
               'bwd_std_iat': bwd_std_iat_list,
               'fwd_min_iat': fwd_min_iat_list,
               'bwd_min_iat': bwd_min_iat_list,
               'fwd_max_iat': fwd_max_iat_list,
               'bwd_max_iat': bwd_max_iat_list,
               'fwd_mean_offset': fwd_mean_offset_list,
               'bwd_mean_offset': bwd_mean_offset_list,
               'fwd_mean_pkt_len': fwd_mean_pkt_len_list,
               'bwd_mean_pkt_len': bwd_mean_pkt_len_list,
               'fwd_std_pkt_len': fwd_std_pkt_len_list,
               'bwd_std_pkt_len': bwd_std_pkt_len_list,
               'fwd_min_pkt_len': fwd_min_pkt_len_list,
               'bwd_min_pkt_len': bwd_min_pkt_len_list,
               'fwd_max_pkt_len': fwd_max_pkt_len_list,
               'bwd_max_pkt_len': bwd_max_pkt_len_list,
               'fwd_num_bytes': fwd_num_bytes_list,
               'bwd_num_bytes': bwd_num_bytes_list,
               'fwd_num_psh_flags': fwd_num_psh_flags_list,
               'bwd_num_psh_flags': bwd_num_psh_flags_list,
               'fwd_num_rst_flags': fwd_num_rst_flags_list,
               'bwd_num_rst_flags': bwd_num_rst_flags_list,
               'fwd_num_urg_flags': fwd_num_urg_flags_list,
               'bwd_num_urg_flags': bwd_num_urg_flags_list,
               'sec_1_ip_src': sec_1_ip_src_list,
               'sec_2_ip_src': sec_2_ip_src_list,
               'sec_3_ip_src': sec_3_ip_src_list,
               'sec_4_ip_src': sec_4_ip_src_list,
               'sec_5_ip_src': sec_5_ip_src_list}
"""
'num_src_flows_60': num_src_flows_60_list,
'src_ip_dst_prt_delta_60': src_ip_dst_prt_delta_60_list,
'num_src_flows_120': num_src_flows_120_list,
'src_ip_dst_prt_delta_120': src_ip_dst_prt_delta_120_list,
'num_src_flows_180': num_src_flows_180_list,
'src_ip_dst_prt_delta_180': src_ip_dst_prt_delta_180_list,
'num_src_flows_240': num_src_flows_240_list,
'src_ip_dst_prt_delta_240': src_ip_dst_prt_delta_240_list,
'num_src_flows_300': num_src_flows_300_list,
'src_ip_dst_prt_delta_300': src_ip_dst_prt_delta_300_list,
'num_src_flows': num_src_flows_list,
'src_ip_dst_prt_delta': src_ip_dst_prt_delta_list}
"""


num_flow_processed = 0
num_flow = len(uniflow_dict['ip_src'])

sibilings_counts = {}
delta_avg = {}
bi_flow_time = {}

for i in range(5):
    current_time_window = (i + 1) * 60
    sibilings_counts[current_time_window] = {}
    delta_avg[current_time_window] = {}
    bi_flow_time[current_time_window] = {}

for i in range(num_flow_processed, num_flow):
    # print(uniflow_dict['ip_src'][i], biflow[0])

    if uniflow_dict['processed'][i] == False:
        num_flow_processed = i

        for j in range(i, num_flow):
            if (uniflow_dict['ip_src'][j] == uniflow_dict['ip_dst'][i]) and \
                    (uniflow_dict['ip_dst'][j] == uniflow_dict['ip_src'][i]) and \
                    (uniflow_dict['prt_src'][j] == uniflow_dict['prt_dst'][i]) and \
                    (uniflow_dict['prt_dst'][j] == uniflow_dict['prt_src'][i]) and \
                    (uniflow_dict['proto'][j] == uniflow_dict['proto'][i]):
                # index i is fwd flow, j is bwd flow

                ip_src_list.append(uniflow_dict['ip_src'][i])
                ip_dst_list.append(uniflow_dict['ip_dst'][i])
                prt_src_list.append(uniflow_dict['prt_src'][i])
                prt_dst_list.append(uniflow_dict['prt_dst'][i])
                proto_list.append(uniflow_dict['proto'][i])
                fwd_num_pkts_list.append(uniflow_dict['num_pkts'][i])
                bwd_num_pkts_list.append(uniflow_dict['num_pkts'][j])
                fwd_mean_iat_list.append(uniflow_dict['mean_iat'][i])
                bwd_mean_iat_list.append(uniflow_dict['mean_iat'][j])
                fwd_std_iat_list.append(uniflow_dict['std_iat'][i])
                bwd_std_iat_list.append(uniflow_dict['std_iat'][j])
                fwd_min_iat_list.append(uniflow_dict['min_iat'][i])
                bwd_min_iat_list.append(uniflow_dict['min_iat'][j])
                fwd_max_iat_list.append(uniflow_dict['max_iat'][i])
                bwd_max_iat_list.append(uniflow_dict['max_iat'][j])
                fwd_mean_offset_list.append(uniflow_dict['mean_offset'][i])
                bwd_mean_offset_list.append(uniflow_dict['mean_offset'][j])
                fwd_mean_pkt_len_list.append(uniflow_dict['mean_pkt_len'][i])
                bwd_mean_pkt_len_list.append(uniflow_dict['mean_pkt_len'][j])
                fwd_std_pkt_len_list.append(uniflow_dict['std_pkt_len'][i])
                bwd_std_pkt_len_list.append(uniflow_dict['std_pkt_len'][j])
                fwd_min_pkt_len_list.append(uniflow_dict['min_pkt_len'][i])
                bwd_min_pkt_len_list.append(uniflow_dict['min_pkt_len'][j])
                fwd_max_pkt_len_list.append(uniflow_dict['max_pkt_len'][i])
                bwd_max_pkt_len_list.append(uniflow_dict['max_pkt_len'][j])
                fwd_num_bytes_list.append(uniflow_dict['num_bytes'][i])
                bwd_num_bytes_list.append(uniflow_dict['num_bytes'][j])
                fwd_num_psh_flags_list.append(uniflow_dict['num_psh_flags'][i])
                bwd_num_psh_flags_list.append(uniflow_dict['num_psh_flags'][j])
                fwd_num_rst_flags_list.append(uniflow_dict['num_rst_flags'][i])
                bwd_num_rst_flags_list.append(uniflow_dict['num_rst_flags'][j])
                fwd_num_urg_flags_list.append(uniflow_dict['num_urg_flags'][i])
                bwd_num_urg_flags_list.append(uniflow_dict['num_urg_flags'][j])

                sec_1_ip_src_list.append(str(meta_list_time_0[i] // 60) + '_' + uniflow_dict['ip_src'][i])
                sec_2_ip_src_list.append(str(meta_list_time_0[i] // 120) + '_' + uniflow_dict['ip_src'][i])
                sec_3_ip_src_list.append(str(meta_list_time_0[i] // 180) + '_' + uniflow_dict['ip_src'][i])
                sec_4_ip_src_list.append(str(meta_list_time_0[i] // 240) + '_' + uniflow_dict['ip_src'][i])
                sec_5_ip_src_list.append(str(meta_list_time_0[i] // 300) + '_' + uniflow_dict['ip_src'][i])

                """
                for t in range(5):
                    current_time_window = (t + 1) * 60
                    if uniflow_dict['ip_src'][i] not in sibilings_counts[current_time_window]:
                        sibilings_counts[current_time_window][uniflow_dict['ip_src'][i]] = 0
                        delta_avg[current_time_window][uniflow_dict['ip_src'][i]] = []
                        bi_flow_time[current_time_window][uniflow_dict['ip_src'][i]] = []
                    else:
                        min_time = meta_list_time_0[t] - current_time_window
                        del_counter = 0
                        for temp in bi_flow_time[current_time_window][uniflow_dict['ip_src'][i]]:
                            if temp < min_time:
                                del_counter += 1

                        sibilings_counts[current_time_window][uniflow_dict['ip_src'][i]] -= del_counter
                        del delta_avg[current_time_window][uniflow_dict['ip_src'][i]][0:del_counter]
                        del bi_flow_time[current_time_window][uniflow_dict['ip_src'][i]][0:del_counter]

                    sibilings_counts[current_time_window][uniflow_dict['ip_src'][i]] += 1
                    delta_avg[current_time_window][uniflow_dict['ip_src'][i]].append(uniflow_dict['prt_dst'][i])
                    bi_flow_time[current_time_window][uniflow_dict['ip_src'][i]].append(meta_list_time_0[i])

                    if meta_list_time_0[i] >= current_time_window:
                        num_src_flows_list.append(
                            int(sibilings_counts[current_time_window][uniflow_dict['ip_src'][i]]))
                        src_ip_dst_prt_delta_list.append(
                            get_mean(delta_avg[current_time_window][uniflow_dict['ip_src'][i]]))
                    else:
                        # time < sliding window --> not sliding
                        num_src_flows_list.append('')
                        src_ip_dst_prt_delta_list.append('')
                """

                uniflow_dict['processed'][i] = True
                uniflow_dict['processed'][j] = True

                break

biflow_dict_time = time.time()
print('\nDictionary of biflow created in {} seconds'.format(biflow_dict_time - uniflow_dict_time))

# print(biflow_dict)
df = pd.DataFrame(biflow_dict)
print(df)

print('\nParsing the file took {} seconds'.format(time.time() - start_time))

