import dpkt
import datetime

import time
import numpy as np
import pandas as pd
from dpkt.utils import inet_to_str
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE

# SCRIPT PARAMETERS ____________________________________________________________________________________________________
run_features_extraction = True
run_label_dataset = False
run_binarize_dataset = False
run_balance_binary_dataset = False
run_balance_multiclass_dataset = False

save_on_external_storage = True
dataset_path = '/media/external_wd/jpriam/'  # path to pcap files
ext_storage_path = '/media/external_wd/jpriam/'
# days_list = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']  # days to consider
days_list = ['Monday']  # days to consider
# ______________________________________________________________________________________________________________________


start_time = time.time()
print('Starting create_dataset script\n')

# EXTRACTING FEATURES FROM PCAP FILES __________________________________________________________________________________
if run_features_extraction:
    global_t0 = 0
    offset = 10800


    def get_mean(l):
        if len(l) == 0:
            return 0
        elif len(l) == 1:
            return l[0]
        else:
            return np.absolute(np.diff(np.sort(l))).mean()


    for day in days_list:
        start_time_file = time.time()
        print('Start parsing {} file'.format(day))

        input_file_path = dataset_path + day + '-WorkingHours.pcap'
        if save_on_external_storage:
            output_file_path = ext_storage_path + day + '.csv'
        else:
            output_file_path = day + '.csv'

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
        f = open(input_file_path, 'rb')
        pcap_file = dpkt.pcap.Reader(f)

        # Loop to parse the file on each packet
        count = 1
        udpcount = 0
        tcpcount = 0
        for timestamp, buf in pcap_file:
            if count == 1:
                global_t0 = datetime.datetime.utcfromtimestamp(timestamp - offset)
            if count % 1000000 == 0:
                print('{} packets have been processed in {}.pcap file'.format(count, day))

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
            time_list.append(timestamp - offset)
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
        print('\nDictionary of packets created in {} seconds'.format(pkt_dict_time - start_time_file))
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

        meta_list_time_0 = []

        t_start_list_uni = []
        t_end_list_uni = []
        ip_src_list_uni = []
        ip_dst_list_uni = []
        prt_src_list_uni = []
        prt_dst_list_uni = []
        proto_list_uni = []
        flow_duration_list_uni = []
        flow_bytes_sec_list_uni = []
        flow_pkt_sec_list_uni = []
        num_pkts_list_uni = []
        mean_iat_list_uni = []
        std_iat_list_uni = []
        min_iat_list_uni = []
        max_iat_list_uni = []
        mean_offset_list_uni = []
        mean_pkt_len_list_uni = []
        std_pkt_len_list_uni = []
        min_pkt_len_list_uni = []
        max_pkt_len_list_uni = []
        num_bytes_list_uni = []
        num_psh_flags_list_uni = []
        num_rst_flags_list_uni = []
        num_urg_flags_list_uni = []
        processed_list_uni = []

        uniflow_dict = {'t_start': t_start_list_uni,
                        't_end': t_end_list_uni,
                        'ip_src': ip_src_list_uni,
                        'ip_dst': ip_dst_list_uni,
                        'prt_src': prt_src_list_uni,
                        'prt_dst': prt_dst_list_uni,
                        'proto': proto_list_uni,
                        'flow_duration': flow_duration_list_uni,
                        'flow_bytes_sec': flow_bytes_sec_list_uni,
                        'flow_pkt_sec': flow_pkt_sec_list_uni,
                        'num_pkts': num_pkts_list_uni,
                        'mean_iat': mean_iat_list_uni,
                        'std_iat': std_iat_list_uni,
                        'min_iat': min_iat_list_uni,
                        'max_iat': max_iat_list_uni,
                        'mean_offset': mean_offset_list_uni,
                        'mean_pkt_len': mean_pkt_len_list_uni,
                        'std_pkt_len': std_pkt_len_list_uni,
                        'min_pkt_len': min_pkt_len_list_uni,
                        'max_pkt_len': max_pkt_len_list_uni,
                        'num_bytes': num_bytes_list_uni,
                        'num_psh_flags': num_psh_flags_list_uni,
                        'num_rst_flags': num_rst_flags_list_uni,
                        'num_urg_flags': num_urg_flags_list_uni,
                        'processed': processed_list_uni}

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

            ip_src_list_uni.append(flow_list_dict[index][0][0])
            ip_dst_list_uni.append(flow_list_dict[index][0][1])
            prt_src_list_uni.append(flow_list_dict[index][0][2])
            prt_dst_list_uni.append(flow_list_dict[index][0][3])
            proto_list_uni.append(flow_list_dict[index][0][4])
            # pkt_len_list_uni.append(flow_list_dict[index][0][7])
            num_pkts = len(flow_list_dict[index])
            num_pkts_list_uni.append(num_pkts)
            mean_pkt_len_list_uni.append(sum(length_list) / num_pkts)
            pkt_len_arry = np.array(length_list)
            std_pkt_len_list_uni.append(float(np.std(pkt_len_arry)))
            min_pkt_len_list_uni.append(float(min(pkt_len_arry)))
            max_pkt_len_list_uni.append(float(max(pkt_len_arry)))
            num_bytes_list_uni.append(sum(length_list))
            num_psh_flags_list_uni.append(sum(psh_list))
            num_rst_flags_list_uni.append(sum(rst_list))
            num_urg_flags_list_uni.append(sum(urg_list))
            processed_list_uni.append(False)

            if num_pkts > 1:
                time_list.sort(reverse=True)  # put times in descending order
                t_end_list_uni.append(time_list[0])
                t_diff = abs(np.diff(time_list))
                mean_iat_list_uni.append(sum(t_diff) / (num_pkts - 1))
                std_iat_list_uni.append(np.std(t_diff))  # std dev of IAT
                min_iat_list_uni.append(min(t_diff))
                max_iat_list_uni.append(max(t_diff))
                # Kenzi's apparently good feature is the mean time between the first
                # packet and each sucessive packet: (t2-t1) + (t3-t1) + (t4-t1) / n
                time_list.sort()  # sort into ascending order now
                t_start_list_uni.append(time_list[0])
                flow_duration_list_uni.append(t_end_list_uni[-1] - t_start_list_uni[-1])
                t0 = time_list[0]
                time_total = 0.0
                for f in range(1, num_pkts):
                    time_total += abs(t0 - time_list[f])
                mean_offset_list_uni.append(time_total / (num_pkts - 1))

            else:
                t_start_list_uni.append(time_list[0])
                t_end_list_uni.append(time_list[0])
                mean_iat_list_uni.append(0.0)
                std_iat_list_uni.append(0.0)
                min_iat_list_uni.append(0.0)
                max_iat_list_uni.append(0.0)
                mean_offset_list_uni.append(0.0)
                flow_duration_list_uni.append(0.0)

            meta_list_time_0.append((datetime.datetime.utcfromtimestamp(pkt[6]) - global_t0).seconds)

        uniflow_dict_time = time.time()
        print('\nDictionary of uniflows created in {} seconds'.format(uniflow_dict_time - pkt_dict_time))
        print('Number of uniflows : {}'.format(len(uniflow_dict['ip_src'])))

        t_start_list_bi = []
        t_end_list_bi = []
        ip_src_list_bi = []
        ip_dst_list_bi = []
        prt_src_list_bi = []
        prt_dst_list_bi = []
        proto_list_bi = []
        flow_duration_list_bi =[]
        fwd_num_pkts_list_bi = []
        bwd_num_pkts_list_bi = []
        fwd_mean_iat_list_bi = []
        bwd_mean_iat_list_bi = []
        fwd_std_iat_list_bi = []
        bwd_std_iat_list_bi = []
        fwd_min_iat_list_bi = []
        bwd_min_iat_list_bi = []
        fwd_max_iat_list_bi = []
        bwd_max_iat_list_bi = []
        fwd_mean_offset_list_bi = []
        bwd_mean_offset_list_bi = []
        fwd_mean_pkt_len_list_bi = []
        bwd_mean_pkt_len_list_bi = []
        fwd_std_pkt_len_list_bi = []
        bwd_std_pkt_len_list_bi = []
        fwd_min_pkt_len_list_bi = []
        bwd_min_pkt_len_list_bi = []
        fwd_max_pkt_len_list_bi = []
        bwd_max_pkt_len_list_bi = []
        fwd_num_bytes_list_bi = []
        bwd_num_bytes_list_bi = []
        fwd_num_psh_flags_list_bi = []
        bwd_num_psh_flags_list_bi = []
        fwd_num_rst_flags_list_bi = []
        bwd_num_rst_flags_list_bi = []
        fwd_num_urg_flags_list_bi = []
        bwd_num_urg_flags_list_bi = []
        """
        sec_1_ip_src_list_bi = []
        sec_2_ip_src_list_bi = []
        sec_3_ip_src_list_bi = []
        sec_4_ip_src_list_bi = []
        sec_5_ip_src_list_bi = []     
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

        biflow_dict = {'t_start': t_start_list_bi,
                       't_end': t_end_list_bi,
                       'ip_src': ip_src_list_bi,
                       'ip_dst': ip_dst_list_bi,
                       'prt_src': prt_src_list_bi,
                       'prt_dst': prt_dst_list_bi,
                       'proto': proto_list_bi,
                       'flow_duration': flow_duration_list_bi,
                       'fwd_num_pkts': fwd_num_pkts_list_bi,
                       'bwd_num_pkts': bwd_num_pkts_list_bi,
                       'fwd_mean_iat': fwd_mean_iat_list_bi,
                       'bwd_mean_iat': bwd_mean_iat_list_bi,
                       'fwd_std_iat': fwd_std_iat_list_bi,
                       'bwd_std_iat': bwd_std_iat_list_bi,
                       'fwd_min_iat': fwd_min_iat_list_bi,
                       'bwd_min_iat': bwd_min_iat_list_bi,
                       'fwd_max_iat': fwd_max_iat_list_bi,
                       'bwd_max_iat': bwd_max_iat_list_bi,
                       'fwd_mean_offset': fwd_mean_offset_list_bi,
                       'bwd_mean_offset': bwd_mean_offset_list_bi,
                       'fwd_mean_pkt_len': fwd_mean_pkt_len_list_bi,
                       'bwd_mean_pkt_len': bwd_mean_pkt_len_list_bi,
                       'fwd_std_pkt_len': fwd_std_pkt_len_list_bi,
                       'bwd_std_pkt_len': bwd_std_pkt_len_list_bi,
                       'fwd_min_pkt_len': fwd_min_pkt_len_list_bi,
                       'bwd_min_pkt_len': bwd_min_pkt_len_list_bi,
                       'fwd_max_pkt_len': fwd_max_pkt_len_list_bi,
                       'bwd_max_pkt_len': bwd_max_pkt_len_list_bi,
                       'fwd_num_bytes': fwd_num_bytes_list_bi,
                       'bwd_num_bytes': bwd_num_bytes_list_bi,

                       'fwd_num_psh_flags': fwd_num_psh_flags_list_bi,
                       'bwd_num_psh_flags': bwd_num_psh_flags_list_bi,
                       'fwd_num_rst_flags': fwd_num_rst_flags_list_bi,
                       'bwd_num_rst_flags': bwd_num_rst_flags_list_bi,
                       'fwd_num_urg_flags': fwd_num_urg_flags_list_bi,
                       'bwd_num_urg_flags': bwd_num_urg_flags_list_bi}
        """
        'sec_1_ip_src': sec_1_ip_src_list_bi,
        'sec_2_ip_src': sec_2_ip_src_list_bi,
        'sec_3_ip_src': sec_3_ip_src_list_bi,
        'sec_4_ip_src': sec_4_ip_src_list_bi,
        'sec_5_ip_src': sec_5_ip_src_list_bi}
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

                        t_start_list_bi.append(min(uniflow_dict['t_start'][i], uniflow_dict['t_start'][j]))
                        t_end_list_bi.append(max(uniflow_dict['t_end'][i], uniflow_dict['t_end'][j]))
                        ip_src_list_bi.append(uniflow_dict['ip_src'][i])
                        ip_dst_list_bi.append(uniflow_dict['ip_dst'][i])
                        prt_src_list_bi.append(uniflow_dict['prt_src'][i])
                        prt_dst_list_bi.append(uniflow_dict['prt_dst'][i])
                        proto_list_bi.append(uniflow_dict['proto'][i])
                        flow_duration_list_bi.append(uniflow_dict['flow_duration'][i])
                        fwd_num_pkts_list_bi.append(uniflow_dict['num_pkts'][i])
                        bwd_num_pkts_list_bi.append(uniflow_dict['num_pkts'][j])
                        fwd_mean_iat_list_bi.append(uniflow_dict['mean_iat'][i])
                        bwd_mean_iat_list_bi.append(uniflow_dict['mean_iat'][j])
                        fwd_std_iat_list_bi.append(uniflow_dict['std_iat'][i])
                        bwd_std_iat_list_bi.append(uniflow_dict['std_iat'][j])
                        fwd_min_iat_list_bi.append(uniflow_dict['min_iat'][i])
                        bwd_min_iat_list_bi.append(uniflow_dict['min_iat'][j])
                        fwd_max_iat_list_bi.append(uniflow_dict['max_iat'][i])
                        bwd_max_iat_list_bi.append(uniflow_dict['max_iat'][j])
                        fwd_mean_offset_list_bi.append(uniflow_dict['mean_offset'][i])
                        bwd_mean_offset_list_bi.append(uniflow_dict['mean_offset'][j])
                        fwd_mean_pkt_len_list_bi.append(uniflow_dict['mean_pkt_len'][i])
                        bwd_mean_pkt_len_list_bi.append(uniflow_dict['mean_pkt_len'][j])
                        fwd_std_pkt_len_list_bi.append(uniflow_dict['std_pkt_len'][i])
                        bwd_std_pkt_len_list_bi.append(uniflow_dict['std_pkt_len'][j])
                        fwd_min_pkt_len_list_bi.append(uniflow_dict['min_pkt_len'][i])
                        bwd_min_pkt_len_list_bi.append(uniflow_dict['min_pkt_len'][j])
                        fwd_max_pkt_len_list_bi.append(uniflow_dict['max_pkt_len'][i])
                        bwd_max_pkt_len_list_bi.append(uniflow_dict['max_pkt_len'][j])
                        fwd_num_bytes_list_bi.append(uniflow_dict['num_bytes'][i])
                        bwd_num_bytes_list_bi.append(uniflow_dict['num_bytes'][j])
                        fwd_num_psh_flags_list_bi.append(uniflow_dict['num_psh_flags'][i])
                        bwd_num_psh_flags_list_bi.append(uniflow_dict['num_psh_flags'][j])
                        fwd_num_rst_flags_list_bi.append(uniflow_dict['num_rst_flags'][i])
                        bwd_num_rst_flags_list_bi.append(uniflow_dict['num_rst_flags'][j])
                        fwd_num_urg_flags_list_bi.append(uniflow_dict['num_urg_flags'][i])
                        bwd_num_urg_flags_list_bi.append(uniflow_dict['num_urg_flags'][j])

                        """
                        sec_1_ip_src_list_bi.append(str(meta_list_time_0[i] // 60) + '_' + uniflow_dict['ip_src'][i])
                        sec_2_ip_src_list_bi.append(str(meta_list_time_0[i] // 120) + '_' + uniflow_dict['ip_src'][i])
                        sec_3_ip_src_list_bi.append(str(meta_list_time_0[i] // 180) + '_' + uniflow_dict['ip_src'][i])
                        sec_4_ip_src_list_bi.append(str(meta_list_time_0[i] // 240) + '_' + uniflow_dict['ip_src'][i])
                        sec_5_ip_src_list_bi.append(str(meta_list_time_0[i] // 300) + '_' + uniflow_dict['ip_src'][i])
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

        df = pd.DataFrame(biflow_dict)
        print(df.head())
        for col in df.columns:
            print(col)
        # df.to_csv(output_file_path)

        print('\nParsing {} file took {} seconds'.format(day, time.time() - start_time_file))

    print('\nExtracting features took {} seconds'.format(time.time() - start_time))
# FEATURES EXTRACTED ___________________________________________________________________________________________________


# ADDING LABEL TO DATASET ______________________________________________________________________________________________
if run_label_dataset:
    label_start_time = time.time()
    print("\n\nStarting label_dataset script")

    ip_attack_1 = '192.168.10.50'
    ip_attack_2 = '172.16.0.1'
    ip_attack_3 = '192.168..10.51'
    ip_attack_4 = '172.16.0.11'
    ip_attack_5 = '205.174.165.73'
    ip_attack_6 = '192.168.10.8'


    def sec_to_hms(sec):
        return time.strftime('%H:%M:%S', time.gmtime(sec))


    def hms_to_sec(hms):
        h, m, s = hms.split(':')
        return int(h) * 3600 + int(m) * 60 + float(s)


    def flow_included_in_window(w_start, w_end, flow_start, flow_end):
        if (w_start % 86400 <= flow_start % 86400 <= w_end % 86400) or \
                (w_start % 86400 <= flow_end % 86400 <= w_end % 86400) or \
                (flow_start % 86400 <= w_start % 86400 and w_end % 86400 <= flow_end % 86400):
            return True

        else:
            return False


    flow_count = 0
    count_benign = 0    # 0
    count_ftp_patator = 0   # 1
    count_ssh_patator = 0   # 2
    count_DoS_slowloris = 0 # 3
    count_DoS_slowhttptest = 0  # 4
    count_DoS_hulk = 0  # 5
    count_DoS_goldeneye = 0 # 6
    count_Ddos_loit = 0 # 7
    count_brute_force = 0   # 8
    count_xss = 0   # 9
    count_port_scan = 0 # 10
    count_infiltration = 0  # 11
    count_botnet_ares = 0   # 12
    count_sql_injection = 0 # 13
    count_heartbleed = 0    # 14

    for day in days_list:

        print('\nStarting to label {} file'.format(day))

        if save_on_external_storage:
            input_file = ext_storage_path + day + '.csv'
            output_file = ext_storage_path + day + '.csv'
        else:
            input_file = day + '.csv'
            output_file = day + '.csv'

        df = pd.read_csv(input_file)
        df.drop('Unnamed: 0', axis=1, inplace=True)

        label = []

        # ADD LABEL IF MATCHING WITH ATTACKER IP ______________________
        for index in df.index:
            t_start = df['t_start'][index]
            t_end = df['t_end'][index]
            ip_src = df['ip_src'][index]
            ip_dst = df['ip_dst'][index]

            if day == 'Monday':
                label.append(0) #BENIGN
                count_benign += 1

            elif day == 'Tuesday':
                if ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                    (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('9:20:00'), hms_to_sec('10:20:00'), t_start, t_end)):
                    label.append(1) #FTP-Patator
                    count_ftp_patator += 1

                elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                      (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('14:00:00'), hms_to_sec('15:00:00'), t_start, t_end)):
                    label.append(2) #SSH-Patator
                    count_ssh_patator += 1

                else:
                    label.append(0) #BENIGN
                    count_benign += 1

            elif day == 'Wednesday':
                if ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                    (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('9:47:00'), hms_to_sec('10:10:00'), t_start, t_end)):
                    label.append(3) #DOS-SLOWLORIS
                    count_DoS_slowloris += 1

                elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                      (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('10:14:00'), hms_to_sec('10:35:00'), t_start, t_end)):
                    label.append(4) #DOS-SLOWHTTPTEST
                    count_DoS_slowhttptest += 1

                elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                      (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('10:43:00'), hms_to_sec('11:00:00'), t_start, t_end)):
                    label.append(5) #DOS-HULK
                    count_DoS_hulk += 1

                elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                      (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('11:10:00'), hms_to_sec('11:23:00'), t_start, t_end)):
                    label.append(6) #DOS-GOLDENEYE
                    count_DoS_goldeneye += 1

                elif ((ip_src == ip_attack_3) or (ip_dst == ip_attack_3) or
                      (ip_src == ip_attack_4) or (ip_dst == ip_attack_4)) and \
                        (flow_included_in_window(hms_to_sec('15:12:00'), hms_to_sec('15:32:00'), t_start, t_end)):
                    label.append(14) #HEARTBLEED
                    count_heartbleed += 1

                else:
                    label.append(0) #BENIGN
                    count_benign += 1

            elif day == 'Thursday':
                if ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                    (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('9:20:00'), hms_to_sec('10:00:00'), t_start, t_end)):
                    label.append(8) #BRUTE-FORCE
                    count_brute_force += 1

                elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                      (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('10:15:00'), hms_to_sec('10:35:00'), t_start, t_end)):
                    label.append(9) #XSS
                    count_xss += 1

                elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                      (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                        (flow_included_in_window(hms_to_sec('10:40:00'), hms_to_sec('10:42:00'), t_start, t_end)):
                    label.append(13) #SQL-INJECTION
                    count_sql_injection += 1

                elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5)) and \
                        (flow_included_in_window(hms_to_sec('14:19:00'), hms_to_sec('14:21:00'), t_start, t_end)):
                    label.append(11) #INFILTRATION
                    count_infiltration += 1

                elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5)) and \
                        (flow_included_in_window(hms_to_sec('14:33:00'), hms_to_sec('14:35:00'), t_start, t_end)):
                    label.append(11) #INFILTRATION
                    count_infiltration += 1

                elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5)) and \
                        (flow_included_in_window(hms_to_sec('14:53:00'), hms_to_sec('15:00:00'), t_start, t_end)):
                    label.append(11) #INFILTRATION
                    count_infiltration += 1

                elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5) or
                      (ip_src == ip_attack_6) or (ip_dst == ip_attack_6)) and \
                        (flow_included_in_window(hms_to_sec('15:04:00'), hms_to_sec('115:45:00'), t_start, t_end)):
                    label.append(11) #INFILTRATION
                    count_infiltration += 1

                else:
                    label.append(0) #BENIGN
                    count_benign += 1

            else:
                if (ip_src == ip_attack_2) or (ip_dst == ip_attack_2) and \
                        (flow_included_in_window(hms_to_sec('10:02:00'), hms_to_sec('11:02:00'), t_start, t_end)):
                    label.append(12) #BOTNET ARES
                    count_botnet_ares += 1

                elif (ip_src == ip_attack_2) or (ip_dst == ip_attack_2) and \
                        (flow_included_in_window(hms_to_sec('13:55:00'), hms_to_sec('15:29:00'), t_start, t_end)):
                    label.append(10) #PORT SCAN
                    count_port_scan += 1

                elif (ip_src == ip_attack_2) or (ip_dst == ip_attack_2) and \
                        (flow_included_in_window(hms_to_sec('15:56:00'), hms_to_sec('16:16:00'), t_start, t_end)):
                    label.append(7) #DDOS LOIT
                    count_Ddos_loit += 1

                else:
                    label.append(0) #BENIGN
                    count_benign += 1

            flow_count += 1

        df['label'] = label
        print(df)
        df.to_csv(output_file)

    print('\nNb of flows : {}'.format(flow_count))
    print('Nb of ftp-patator attacks : {}'.format(count_ftp_patator))
    print('Nb of ssh-patator attacks : {}'.format(count_ssh_patator))
    print('Nb of DoS slowris attacks : {}'.format(count_DoS_slowloris))
    print('Nb of DoS slowhttptest attacks : {}'.format(count_DoS_slowhttptest))
    print('Nb of DoS hulk attacks : {}'.format(count_DoS_hulk))
    print('Nb of DoS goldeneye attacks : {}'.format(count_DoS_goldeneye))
    print('Nb of heartbleed attacks : {}'.format(count_heartbleed))
    print('Nb of brute force attacks : {}'.format(count_brute_force))
    print('Nb of xss attacks : {}'.format(count_xss))
    print('Nb of sql injection attacks : {}'.format(count_sql_injection))
    print('Nb of infiltration attacks : {}'.format(count_infiltration))
    print('Nb of Botenet Ares attacks : {}'.format(count_botnet_ares))
    print('Nb of port scan attacks : {}'.format(count_botnet_ares))
    print('Nb of Ddos Loit attacks : {}'.format(count_Ddos_loit))
    print('Nb of benign flows : {}'.format(count_benign))

    # CONCATENATE LABEL CSV FILES
    files_list = []
    for day in days_list:
        if save_on_external_storage:
            files_list.append(ext_storage_path + day + '.csv')
        else:
            files_list.append(day + '.csv')

    global_dataset = pd.concat([pd.read_csv(f) for f in files_list])
    global_dataset.drop('Unnamed: 0', axis=1, inplace=True)

    if save_on_external_storage:
        global_dataset.to_csv(ext_storage_path + 'dataset.csv')
    else:
        global_dataset.to_csv('dataset.csv')

    print('\nAdding label to dataset took {} seconds'.format(time.time() - label_start_time))
# LABEL ADDED TO DATASET _______________________________________________________________________________________________


# BINARIZE DATASET & REMOVE UNUSEFUL FEATURES __________________________________________________________________________
if run_binarize_dataset:

    if save_on_external_storage:
        df = pd.read_csv(ext_storage_path + 'dataset.csv')
    else:
        df = pd.read_csv('dataset.csv')

    df.drop('Unnamed: 0', axis=1, inplace=True)

    print(df['label'].value_counts())
    for index in df.index:
        if index % 100000 == 0:
            print('{} rows processed'.format(index))

        if df['label'][index] != 0:
            df.at[index, 'label'] = 1

    print(df['label'].value_counts())

    if save_on_external_storage:
        df.to_csv(ext_storage_path + 'dataset_bin.csv')
    else:
        df.to_csv('dataset_bin.csv')
# DATASET UPDATED ______________________________________________________________________________________________________


# BALANCE BINARY DATASET & PERFORM ONE-HOT ENCODING ____________________________________________________________________
if run_balance_binary_dataset:
    if save_on_external_storage:
        df = pd.read_csv(ext_storage_path + 'dataset_bin.csv')
    else:
        df = pd.read_csv('dataset_bin.csv')

    df.drop('Unnamed: 0', axis=1, inplace=True)

    X = df.iloc[:, 0:-1]
    Y = df['label']  # Labels

    X = pd.get_dummies(X, columns=['proto'])
    print("One-hot encoding performed")
    
    print('\nNumber of samples per class before RandomUnderSampler: \n', df['label'].value_counts())
    under = RandomUnderSampler(sampling_strategy=1)
    new_df, new_df_label = under.fit_resample(X, Y)
    new_df['label'] = new_df_label
    print('Number of samples per class after RandomUnderSampler: \n', new_df['label'].value_counts())
    
    if save_on_external_storage:
        new_df.to_csv(ext_storage_path + 'dataset_bin.csv')
    else:
        new_df.to_csv('dataset_bin.csv')
    
# DATASET UPDATED ______________________________________________________________________________________________________


# BALANCE MULTI-CLASS DATASET & PERFORM ONE-HOT ENCODING _______________________________________________________________
if run_balance_multiclass_dataset:
    
    if save_on_external_storage:
        df = pd.read_csv(ext_storage_path + 'dataset.csv')
    else:
        df = pd.read_csv('dataset.csv')

    df.drop('Unnamed: 0', axis=1, inplace=True)
    df.drop('t_start', axis=1, inplace=True)
    df.drop('t_end', axis=1, inplace=True)
    df.drop('ip_src', axis=1, inplace=True)
    df.drop('ip_dst', axis=1, inplace=True)
    df.drop('prt_src', axis=1, inplace=True)
    df.drop('prt_dst', axis=1, inplace=True)

    print(df)

    print(df['label'].value_counts())
    
    
    print("\nStarting to rename label and remove samples")
    for index in df.index:
        if index % 100000 == 0:
            print('{} rows processed'.format(index))

        if (df['label'][index] == 13) or (df['label'][index] == 14):
            df.drop(labels=index, axis=0, inplace=True)



    X = df.iloc[:, 0:-1]
    Y = df['label']  # Labels

    X = pd.get_dummies(X, columns=['proto'])
    print("One-hot encoding performed")
    print(X)
    
    print('\nNumber of samples per class before RandomUnderSampler: \n', df['label'].value_counts())    
    sampling_strategy = {0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100, 6: 100, 7: 100, 8: 100, 9: 100, 10: 100, 11: 100, 12: 100}

    under = RandomUnderSampler(sampling_strategy=sampling_strategy)
    X, Y = under.fit_resample(X, Y)
    X['label'] = Y
    print('Number of samples per class after RandomUnderSampler: \n', Y.value_counts())
    print(Y)
    
    """
    # define oversampling strategy
    smote = SMOTE()
    X, Y = smote.fit_resample(X, Y)
    X['label'] = Y
    print("After oversampling: ", X['label'].value_counts())
    print(X)
    """
    
    if save_on_external_storage:
        X.to_csv(ext_storage_path + 'dataset_multi.csv')
    else:
        X.to_csv('dataset_multi.csv')


    
# DATASET UPDATED ______________________________________________________________________________________________________

print('\nCreating dataset took {} seconds'.format(time.time() - start_time))
