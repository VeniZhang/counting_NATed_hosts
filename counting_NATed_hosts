#!/usr/bin/env python2
import pyshark
import matplotlib.pyplot as plt
import sys
import getopt
ip = ""
file_ = ""
try:
    opts, args = getopt.getopt(sys.argv[1:],"hi:p:",["file=", "ip="])
except getopt.GetoptError:
        print "./zhangqiang -i <inputfile> -p <ip>"
for opt, arg in opts:
    if opt == "-h":
        print "./zhangqiang -i <inputfile> -p <ip>"
        sys.exit(2)
    elif opt in ("-i", "--file"):
        file_ = arg
    elif opt in ("-p", "--ip"):
        ip = arg
    else:
        print "./zhangqiang -i <inputfile> -p <ip>"
        sys.exit(1)
if file_ == "":
    file_ = "src-10.1.50.21-ssh-ftp-http.pcap"
if ip == "":
    ip = "10.1.50.21"
fig = plt.figure()
TIMELIM =1 #s
GAPLIM = 64
TIMEFAC = 1#s
GAPFAC = 7
FSIZE = 10
pcaps = pyshark.FileCapture(file_)
times = []
ip_ids = []
for pcap in pcaps:
    if hasattr(pcap, 'ip')  and str(pcap.ip.src) == ip :#and \
    #        str(pcap.ip.dst) == "151.101.73.183":
        frame_info = pcap.frame_info
        time_relative = frame_info.time_relative
        ip_id = pcap.ip.id.hex_value
        time_relative = float(time_relative)
        times.append((time_relative))
        ip_ids.append(int(ip_id))
list_ = []
time_ = []
print "len of package:", len(times)
og = fig.add_subplot(131)
og.plot(times, ip_ids, "+")
og.set_title("origin")
og.set_xlabel("time_arrive(second)")
og.set_ylabel("ip_id")
for i in range(len(times)):
    isAdd = False
    for l in range(len(list_)):
        if len(list_[l]) > 0:
            if ip_ids[i] - list_[l][-1] < GAPLIM and ip_ids[i] - list_[l][-1] > 0 :
                list_[l].append(ip_ids[i])
                time_[l].append(times[i])
                isAdd = True
    if not isAdd:
       list_.append([ip_ids[i]])
       time_.append([times[i]])
print len(list_)
um = fig.add_subplot(132)
um.set_title("unmerge")
um.set_xlabel("time_arrive(second)")
um.set_ylabel("ip_id")

for l in range(len(list_)):
    um.plot(time_[l], list_[l], chr(ord("+")+l))
    print "***"
delete_ = set()
for l in range(len(list_) - 1):
        for ll in range(l+1, len(list_)  ):
            del_time =  time_[l][-1] -  time_[ll][0]
            del_ip_id = list_[l][-1] - list_[ll][0] 
            if del_time > -TIMELIM*TIMEFAC and del_time < 0:
                if del_ip_id > -GAPLIM*GAPFAC and del_ip_id < 0 or del_ip_id > 65535 - GAPLIM*GAPFAC:
                    time_[l].extend(time_[ll])
                    list_[l].extend(list_[ll])
                    delete_.add(ll)
merged = fig.add_subplot(133)
merged.set_title("merged")
merged.set_xlabel("time_arrive(second)")
merged.set_ylabel("ip_id")
for l in range(len(list_)):
    if len(list_[l]) < FSIZE:
        delete_.add(l)
    if l in delete_:
        continue
    merged.plot(time_[l], list_[l], chr(ord("+")+l))
fig.subplots_adjust(wspace=0.3)
fig.suptitle("%d host(s) behind NAT" % (len(list_) - len(delete_)))
plt.show()
