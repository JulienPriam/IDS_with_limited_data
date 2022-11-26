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
week_days = ['monday', 'tuesday', 'wednesday', 'thursday']


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


"""
# GET DATAFRAME FROM PCAP_PARSER FILE ___________________
df = pcap_parser.df
print(df)
df.to_csv('thursday.csv')
"""

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

for day in week_days:

    test_count = 0

    input_file = day + '.csv'
    output_file = day + '_label.csv'
    print(input_file, output_file)

    df = pd.read_csv(input_file)

    if day == 'monday':
        real_start_time = hms_to_sec('8:56:38')
    elif day == 'tuesday':
        real_start_time = hms_to_sec('8:54:00')
    elif day == 'wednesday':
        real_start_time = hms_to_sec('8:42:00')
    elif day == 'thursday':
        real_start_time = hms_to_sec('8:59:00')
    else:
        real_start_time = hms_to_sec('9:00:00')

    offset = abs(df['t_start'][0] - real_start_time)
    label = []

    # ADD LABEL IF MATCHING WITH ATTACKER IP ______________________
    for index in df.index:
        t_start = df['t_start'][index] - offset
        t_end = df['t_end'][index] - offset
        ip_src = df['ip_src'][index]
        ip_dst = df['ip_dst'][index]

        if test_count < 20:
            print(ip_src, ip_dst, sec_to_hms(t_start))
            test_count += 1

        if day == 'monday':
            label.append('BENIGN')
            count_benign += 1



        elif day == 'tuesday':
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



        elif day == 'wednesday':
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



        elif day == 'thursday':
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

# CONCATENATE LABEL CSV FILES _______________________________
files = ['monday_label.csv', 'tuesday_label.csv', 'wednesday_label.csv', 'thursday_label.csv']
global_dataset = pd.concat([pd.read_csv(f) for f in files])
global_dataset.to_csv('dataset.csv')

print('\nAdding label to dataset took {} seconds'.format(time.time() - start_time))
