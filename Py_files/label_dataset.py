import pandas as pd

# import pcap_parser
import time
import os

start_time = time.time()
print("\n\nStarting label_dataset script")

ip_attack_192 = '192.168.10.50'
ip_attack_172 = '172.16.0.1'


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
os.remove('out.csv')
df.to_csv('out.csv')
"""

df = pd.read_csv('out.csv')

offset = hms_to_sec('2:53:44')
label = []
# ADD LABEL IF MATCHING WITH ATTACKER IP ______________________
for index in df.index:
    t_start = df['t_start'][index] - offset
    t_end = df['t_end'][index] - offset
    ip_src = df['ip_src'][index]
    ip_dst = df['ip_dst'][index]

    if ((ip_src == ip_attack_192) or (ip_dst == ip_attack_192) or
        (ip_src == ip_attack_172) or (ip_dst == ip_attack_172)) and \
            (flow_included_in_window(hms_to_sec('9:20:00'), hms_to_sec('10:20:00'), t_start, t_end)):
        label.append('FTP-Patator')
    elif ((ip_src == ip_attack_192) or (ip_dst == ip_attack_192) or
        (ip_src == ip_attack_172) or (ip_dst == ip_attack_172)) and \
            (flow_included_in_window(hms_to_sec('14:00:00'), hms_to_sec('15:00:00'), t_start, t_end)):
        label.append('SSH-Patator')

    else:
        label.append('BENIGN')

df['label'] = label
print(df)

print('\nAdding label to dataset took {} seconds'.format(time.time() - start_time))
