# import multiprocessing 
# import threading
import os
import random
import time
import sys
import re
import dpkt
import socket

start = time.time()

splitpcap = sys.argv[1]
pcapsuffix = re.compile(r'(\.pcap|\.\\)')
rst = re.sub(pcapsuffix,"",splitpcap)
cwd = os.getcwd()
foldername = os.path.join(cwd,rst)
if not os.path.exists(rst):
    os.mkdir(rst)


pcapf = open(splitpcap,"rb")
dpcapf = dpkt.pcap.Reader(pcapf)
packetlist = dpcapf.readpkts()

def getippair(packet):
    if not packet:
        return None
    buf = packet[1]
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return None
    ip = eth.data
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return None
    ippair = b""
    if ip.src < ip.dst:
        ippair = ippair + ip.src + ip.dst
    else:
        ippair = ippair + ip.dst + ip.src
    return ippair
def ippair2address(ippair):
    return f"{socket.inet_ntoa(ippair[:4])}"+"="+\
    f"{socket.inet_ntoa(ippair[4:])}"

# pcap数组中所有packet写入filename
def write2file(pcap,foldername,filename=None):
    if not filename:
        filename = ippair2address(getippair(pcap[0])) + ".pcap"
    filepath = os.path.join(foldername,filename)
    with open(filepath,"wb") as pcapfile:
        writer = dpkt.pcap.Writer(pcapfile)
        for pkt in pcap:
            writer.writepkt(pkt[1],ts=pkt[0])
# 从packetlist去除非ip的包,得到ipList
ipNum = 0
ipList = []
print(f"originallen: {len(packetlist)}")
for i in range(len(packetlist)):
    if getippair(packetlist[i]):
        ipList.append(packetlist[i])
        ipNum += 1
print(f"ippktslen: {len(ipList)}")

# 排序
def merge(left,right):
    result = []
    i = 0
    j = 0
    while i < len(left) and j < len(right):
        if getippair(left[i]) <= getippair(right[j]):
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    if i < len(left):
        result.extend(left[i:])
    if j < len(right):
        result.extend(right[j:])
    return result
def mergesort(iplist):
    n = len(iplist)
    if n <= 1:
        return iplist
    mid = n//2
    left = mergesort(iplist[:mid])
    right = mergesort(iplist[mid:])
    return merge(left,right)
# ip排序后生成sorted.pcap
sortstart = time.time()
sortedList = mergesort(ipList)
sortend = time.time()
print(f"sort time: {sortend - sortstart}")
writestart = time.time()
write2file(sortedList,foldername,"sorted.pcap")
writeend = time.time()
print(f"write time: {writeend - writestart}")
def split(ipList):
    lastippair = getippair(ipList[0])
    lastpcap = [ipList[0]]
    for i in range(len(ipList)):
        if getippair(ipList[i]) != lastippair:
            write2file(lastpcap,foldername)
            lastippair = getippair(ipList[i])
            lastpcap = [ipList[i]]
        else:
            lastpcap.append(ipList[i])
        if i == len(ipList) - 1:
            write2file(lastpcap,foldername)
# (optional)对排序后的ipList分ip分流
# split(sortedList)
end = time.time()
print(f"total time: {end-start}")

