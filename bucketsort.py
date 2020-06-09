import sys
import dpkt
import os
import time
import socket

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

class ipcvst:
    def __init__(self,pkt):
        self.ip = getippair(pkt)
        self._iterable = [pkt]
        self.tcpdict = {}
    def append(self,pkt):
        self._iterable.append(pkt)
    def __iter__(self):
        index = 0
        while True:
            try:
                yield self._iterable[index]
            except IndexError:
                break
            index += 1
# 直接写入新的pcap
# def addpkt2file(pkt,filename):
#     s = bytes(pkt[1])
#     n = len(s)
#     sec = int(pkt[0])
#     usec = int(round(pkt[0] % 1 * 10 ** 6))
#     if sys.byteorder == 'little':
#         ph = dpkt.pcap.LEPktHdr(tv_sec=sec,
#             tv_usec=usec,
#             caplen=n, len=n)
#     else:
#         ph = dpkt.pcap.PktHdr(tv_sec=sec,
#             tv_usec=usec,
#             caplen=n, len=n)
#     bytes4write = bytes(ph) + s
#     with open(filename,"ab") as pktpcapf:
#         pktpcapf.write(bytes4write)

# # 输入文件名及文件夹
pcapfilename = sys.argv[1]
pcapfilenamewo = os.path.split(pcapfilename)[-1]
pcapfolder = pcapfilenamewo.split(".")[0]

start = time.time() # 排序计时

pcapfile = open(pcapfilename,"rb")
reader =  dpkt.pcap.Reader(pcapfile)
pkt = next(reader)
ipcvstdict = {}
# 新建一个不同元素个数大小的字典
pktNum = 0
while pkt:
    iphere = getippair(pkt)
    # 非tcp/ip包
    if iphere == None :
        pkt = next(reader,None)
        pktNum += 1
        continue
    if ipcvstdict.get(iphere):
        ipcvstdict[iphere].append(pkt)
    else:
        newipcvst = ipcvst(pkt)
        ipcvstdict[iphere] = newipcvst
    pkt = next(reader,None)
    pktNum += 1
    # print(f"packet number: {pktNum}")
print(len(ipcvstdict))

end = time.time() # 排序计时
print(f"order time: {end - start}")

# 创建文件夹
outputstart = time.time()

cwd = os.getcwd()
folderpath = os.path.join(cwd,pcapfolder)
if not  os.path.exists(folderpath):
    os.mkdir(folderpath)
os.chdir(folderpath)

# 输出为新pcap

newpcap = open("new1.pcap","wb")
writer = dpkt.pcap.Writer(newpcap)
for ip,ipcon in ipcvstdict.items():
    for pkt in ipcon:
        writer.writepkt(pkt[1],pkt[0])



outputend = time.time()
print(f"outputtime: {outputend - outputstart}")




