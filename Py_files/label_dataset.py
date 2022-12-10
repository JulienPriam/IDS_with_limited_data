import pandas as pd

# import pcap_parser
import time
import os

start_time = time.time()
print("\n\nStarting label_dataset script")

ip_attack_1 = '192.168.10.50'
ip_attack_2 = '172.16.0.1'
ip_attack_3 = '192.168..10.51'
ip_attack_4 = '172.16.0.11'
ip_attack_5 = '205.174.165.73'
ip_attack_6 = '192.168.10.8'
week_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']


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
count_benign = 0
count_ftp_patator = 0
count_ssh_patator = 0
count_DoS_slowloris = 0
count_DoS_slowhttptest = 0
count_DoS_hulk = 0
count_DoS_goldeneye = 0
count_heartbleed = 0
count_brute_force = 0
count_xss = 0
count_sql_injection = 0
count_infiltration = 0
count_botnet_ares = 0
count_port_scan = 0
count_Ddos_loit = 0

for day in week_days:

    print('\nStarting to label {} file'.format(day))

    input_file = '/media/external_wd/jpriam/' + day + '.csv'
    output_file = '/media/external_wd/jpriam/' + day + '_label.csv'

    df = pd.read_csv(input_file)
    label = []

    # ADD LABEL IF MATCHING WITH ATTACKER IP ______________________
    for index in df.index:
        t_start = df['t_start'][index]
        t_end = df['t_end'][index]
        ip_src = df['ip_src'][index]
        ip_dst = df['ip_dst'][index]

        if day == 'Monday':
            label.append('BENIGN')
            count_benign += 1

        elif day == 'Tuesday':
            if ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('9:20:00'), hms_to_sec('10:20:00'), t_start, t_end)):
                label.append('FTP-Patator')
                count_ftp_patator += 1

            elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                  (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('14:00:00'), hms_to_sec('15:00:00'), t_start, t_end)):
                label.append('SSH-Patator')
                count_ssh_patator += 1

            else:
                label.append('BENIGN')
                count_benign += 1

        elif day == 'Wednesday':
            if ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('9:47:00'), hms_to_sec('10:10:00'), t_start, t_end)):
                label.append('DOS-SLOWLORIS')
                count_DoS_slowloris += 1

            elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                  (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('10:14:00'), hms_to_sec('10:35:00'), t_start, t_end)):
                label.append('DOS-SLOWHTTPTEST')
                count_DoS_slowhttptest += 1

            elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                  (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('10:43:00'), hms_to_sec('11:00:00'), t_start, t_end)):
                label.append('DOS-HULK')
                count_DoS_hulk += 1

            elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                  (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('11:10:00'), hms_to_sec('11:23:00'), t_start, t_end)):
                label.append('DOS-GOLDENEYE')
                count_DoS_goldeneye += 1

            elif ((ip_src == ip_attack_3) or (ip_dst == ip_attack_3) or
                  (ip_src == ip_attack_4) or (ip_dst == ip_attack_4)) and \
                    (flow_included_in_window(hms_to_sec('15:12:00'), hms_to_sec('15:32:00'), t_start, t_end)):
                label.append('HEARTBLEED')
                count_heartbleed += 1

            else:
                label.append('BENIGN')
                count_benign += 1

        elif day == 'Thursday':
            if ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('9:20:00'), hms_to_sec('10:00:00'), t_start, t_end)):
                label.append('BRUTE-FORCE')
                count_brute_force += 1

            elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                  (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('10:15:00'), hms_to_sec('10:35:00'), t_start, t_end)):
                label.append('XSS')
                count_xss += 1

            elif ((ip_src == ip_attack_1) or (ip_dst == ip_attack_1) or
                  (ip_src == ip_attack_2) or (ip_dst == ip_attack_2)) and \
                    (flow_included_in_window(hms_to_sec('10:40:00'), hms_to_sec('10:42:00'), t_start, t_end)):
                label.append('SQL-INJECTION')
                count_sql_injection += 1

            elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5)) and \
                    (flow_included_in_window(hms_to_sec('14:19:00'), hms_to_sec('14:21:00'), t_start, t_end)):
                label.append('INFILTRATION')
                count_infiltration += 1

            elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5)) and \
                    (flow_included_in_window(hms_to_sec('14:33:00'), hms_to_sec('14:35:00'), t_start, t_end)):
                label.append('INFILTRATION')
                count_infiltration += 1

            elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5)) and \
                    (flow_included_in_window(hms_to_sec('14:53:00'), hms_to_sec('15:00:00'), t_start, t_end)):
                label.append('INFILTRATION')
                count_infiltration += 1

            elif ((ip_src == ip_attack_5) or (ip_dst == ip_attack_5) or
                  (ip_src == ip_attack_6) or (ip_dst == ip_attack_6)) and \
                    (flow_included_in_window(hms_to_sec('15:04:00'), hms_to_sec('115:45:00'), t_start, t_end)):
                label.append('INFILTRATION')
                count_infiltration += 1

            else:
                label.append('BENIGN')
                count_benign += 1

        else:
            if (ip_src == ip_attack_2) or (ip_dst == ip_attack_2) and \
                    (flow_included_in_window(hms_to_sec('10:02:00'), hms_to_sec('11:02:00'), t_start, t_end)):
                label.append('BOTNET ARES')
                count_botnet_ares += 1

            elif (ip_src == ip_attack_2) or (ip_dst == ip_attack_2) and \
                    (flow_included_in_window(hms_to_sec('13:55:00'), hms_to_sec('15:29:00'), t_start, t_end)):
                label.append('PORT SCAN')
                count_port_scan += 1

            elif (ip_src == ip_attack_2) or (ip_dst == ip_attack_2) and \
                    (flow_included_in_window(hms_to_sec('15:56:00'), hms_to_sec('16:16:00'), t_start, t_end)):
                label.append('DDOS LOIT')
                count_Ddos_loit += 1

            else:
                label.append('BENIGN')
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

# CONCATENATE LABEL CSV FILES _______________________________
files_list = []
for day in week_days:
    files_list.append('/media/external_wd/jpriam/' + day + '_label.csv')
    global_dataset = pd.concat([pd.read_csv(f) for f in files_list])
    global_dataset.to_csv('/media/external_wd/jpriam/dataset_with_label.csv')

print('\nAdding label to dataset took {} seconds'.format(time.time() - start_time))
