import sys
import dpkt
import os
import time
import socket
import re
import mimetypes
import zlib
import struct

# SMTP首行命令元组 0 data之后才传输邮件首部和正文 1-2 信封 3-5 有文件 6- 无文件
SMTPfirstline = ('DATA',
    'MAIL','RCPT',
    'STOR','APPE','RETR',
    'HELO','EHLO','AUTH','SEND','SOML','SAML','EXPN','TURN','8BITMIME','ATRN','CHUNKING',
    'DSN','ETRN','PIPELINING','SIZE','STARTTLS','SMTPUTF8','UTF8SMTP','USER','PASS','REIN',
    'QUIT','DELE','REST','ABOR','CWD','CDUP','LIST','MKD','PWD','RMD','RNFR','RNTO','NLST',
    'SYST','STAT','ACCT','SMNT','MODE','STRU','ALLO','NOOP','HELP')
# FTP首行命令元组 0-1 主被动模式 2 文件传输类型 A文本I二进制 3-5 必须在PORT/PASV之后在数据连接中传输而且传输的是文件 
# 6-8 必须在PORT/PASV之后在数据连接中传输但是传输的不是文件 9- 在控制连接中，无文件
# 3 唯一数据从服务端发出且有文件 4-6 从服务端发出但无文件  
FTPfirstline = ('PORT','PASV','TYPE',
    'RETR','APPE','STOR',
    'LIST','NLST','REST',
    'USER','PASS','REIN','QUIT','DELE','ABOR','CWD','CDUP','MKD','PWD','RMD','FEAT',
    'RNFR','RNTO','SYST','STAT','ACCT','SMNT','MODE','STRU','ALLO','NOOP','HELP')
# HTTP首行方法或者协议版本元组 0-1 response头 2-6 request头有实体 7- request头无实体
HTTPfirstline = ('HTTP/1.0','HTTP/1.1',
    'PUT','POST','UPDATE','CONNECT','OPTIONS',
    'GET','ICY','COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL','BCOPY','BMOVE', 'MKCOL', 
    'TRACE', 'LABEL', 'MERGE','DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'NOTIFY',
    'BDELETE', 'CHECKIN','PROPFIND', 'CHECKOUT', 'CCM_POST','SUBSCRIBE', 
    'PROPPATCH', 'BPROPFIND','BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
    'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT','VERSION-CONTROL','BASELINE-CONTROL')
# 根据tcp标志(seq,ack,syn,fin)判断新tcpses
def getFlags(pkt):    
    eth = dpkt.ethernet.Ethernet(pkt[1])
    ip = eth.data
    tcp = ip.data
    ack = tcp.ack
    syn = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
    fin = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
    rst = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
    seq = tcp.seq
    datalen = len(tcp.data)
    return {"seq":seq,"ack":ack,"rst":rst,"syn":syn,"fin":fin,"len":datalen}
def getportpair(packet):
    buf = packet[1]
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    portpair = struct.pack('>H',tcp.sport) + struct.pack('>H',tcp.dport)
    return portpair
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
def getfileprefix(pkt):
    buf = pkt[1]
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    return f"{socket.inet_ntoa(ip.src)}"+"="+\
    f"{socket.inet_ntoa(ip.dst)}"+","+\
    f"{tcp.sport}"+"="+f"{tcp.dport}"+","

def getFirstWord(appmsg):
    try:
        dataInLine = appmsg[:15].decode(encoding='utf-8').splitlines(keepends=True)
        firstLine = dataInLine[0]
        # print(firstLine)
        firstWord = str(firstLine.split()[0])
    except (UnicodeDecodeError, IndexError):
        firstWord = None
    # print(f"firstword:{firstWord}")
    return firstWord
def getIsZip(r):
    if 'content-encoding'in r.headers and r.headers['content-encoding']=='gzip':
        return True
    else:
        return False
def httpparser(tcp1v,folderpath):
    # 得到message
    httpmessage = {'response':[],'request':[]}
    # mime类型猜测函数，添加自定义的类型和后缀名
    MIMEguesser = mimetypes.MimeTypes()
    MIMEguesser.add_type("application/x-javascript",".js") 
    fileprefix = getfileprefix(next(iter(tcp1v)))

    tcp1vNextSeq = 0
    lastack = 0
    lastlen = 0
    lastseq = 0

    reqrespSwitch = -1
    pktloop = 0
    badtcpcnt = 0

    for pkt in tcp1v:
        buf = pkt[1]
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        http = tcp.data
        # 用于排除差错tcp
        ack = tcp.ack
        syn = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
        # fin = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
        rst = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
        seq = tcp.seq
        datalen = len(tcp.data)
        if pktloop == 0:
            lastack = ack
            lastseq = seq
            lastlen = datalen
            tcp1vNextSeq = seq + syn + datalen
            # print("first tcp")
            pktloop += 1
            # print(f'ack: {ack}/lastack: {lastack}, tcp1vNextSeq:{tcp1vNextSeq}/seq: {seq}/lastseq: {lastseq}, datalen: {datalen}/lastlen: {lastlen} ')
            continue
        # print(f'ack: {ack}/lastack: {lastack}, tcp1vNextSeq:{tcp1vNextSeq}/seq: {seq}/lastseq: {lastseq}, datalen: {datalen}/lastlen: {lastlen} ')
        pktloop += 1
        if rst or seq!=tcp1vNextSeq or (ack==lastack and lastlen==datalen and lastseq==seq):
            badtcpcnt += 1
            print("bad")
            continue
        
        tcp1vNextSeq = tcp1vNextSeq + syn + datalen
        lastack = ack
        lastlen = datalen
        lastseq = seq


        firstword = getFirstWord(http)
        # ftp smtp首单词响应码
        # pattern = re.compile(r'^[1-6]\d{2}')
        # result = pattern.findall(firstword)
        # isResponse = bool(result)
        if firstword in HTTPfirstline[:2]:
            httpmessage['response'].append(http)
            reqrespSwitch = 0
            # print("response")
        elif firstword in HTTPfirstline[2:7]:
            httpmessage['request'].append(http)
            reqrespSwitch = 1
            # print("request")
        elif firstword in HTTPfirstline[7:]:
            reqrespSwitch = -1
            # print("skip")
        else :
            if reqrespSwitch >= 0: 
                httpmessage[list(httpmessage)[reqrespSwitch]][-1] += http
                # print("+ pkt ")
    print("bad tcp: ", badtcpcnt)
    for msgnum,msg in enumerate(httpmessage['response']):
        data = b''
        # print("<<<Response")
        try:
            r = dpkt.http.Response(msg)
            data = r.body
        except (dpkt.dpkt.NeedData):#,dpkt.dpkt.UnpackError):
            pass
            # print("主体数据不完整")
        
        if not data:
            continue
        else:
            ext = MIMEguesser.guess_extension(r.headers['content-type'])
            isZip = getIsZip(r)
            if isZip:
                content = zlib.decompress(data,wbits = zlib.MAX_WBITS | 16)
                # print("decompressed data：",content[:20])
                data = content
            # else:
                # print("not compressed")
            if not ext:
                ext = '.bin'
            filename = f'{fileprefix}{msgnum:002d}resp{ext}'
            with open(os.path.join(folderpath,filename), 'wb') as f:
                f.write(data)
                # print("writed!")
        
    for msgnum,msg in enumerate(httpmessage['request']):
        data = b''
        # print(">>>Request With Entity")
        try:
            r = dpkt.http.Request(msg)
            data = r.body
        except (dpkt.dpkt.NeedData):#,dpkt.dpkt.UnpackError):
            pass
            # print("主体数据不完整")
        
        if not data:
            continue
        else:
            ext = MIMEguesser.guess_extension(r.headers['content-type'])
            isZip= getIsZip(r)
            if isZip:
                content = zlib.decompress(data,wbits = zlib.MAX_WBITS | 16)
                # print("decompressed data：",content[:20])
                data = content
            # else:s
                # print("not compressed")
            if not ext:
                ext = '.bin'
            filename = f'{fileprefix}{msgnum:002d}req{ext}'
            with open(os.path.join(folderpath,filename), 'wb') as f:
                f.write(data)
                # print("writed!")
class IPCONVERSATION:
    def __init__(self,pkt,ippair):
        self.ip = ippair
        self._iterable = [pkt]
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
class TCPONEWAY:
    def __init__(self,pkt,portpair):
        self.port = portpair
        self._iterable = [pkt]
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
# # 输入文件名及文件夹
pcapfilename = sys.argv[1]
pcapfilenamewo = os.path.split(pcapfilename)[-1]
pcapfolder = pcapfilenamewo.split(".")[0]
print("pcapfolder: ",pcapfolder)

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
        newipcvst = IPCONVERSATION(pkt,iphere)
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
print("path: ",folderpath)
if not  os.path.exists(folderpath):
    os.mkdir(folderpath)
os.chdir(folderpath)

# 输出为新pcap
# newpcap = open("new1.pcap","wb")
# writer = dpkt.pcap.Writer(newpcap)
# for ip,ipcon in ipcvstdict.items():
#     for pkt in ipcon:
#         writer.writepkt(pkt[1],pkt[0])

# 
for ip,ipcon in ipcvstdict.items():
    tcp1vdict = {}
    ftp2vdict = {}
    ftpflag = 0
    for pkt in ipcon:
        porthere = getportpair(pkt)
        flags = getFlags(pkt)
        tcp1vhere = tcp1vdict.get(porthere,None)

        if porthere[4:]==b'\x00\x15' and flags['syn']:
            ftpflag = 1
            newftp2v = TCPONEWAY(pkt,porthere)
            ftp2vdict[porthere] = newftp2v
            continue
        if ftpflag:
            ftp2vhere = ftp2vdict.get(porthere,None)
            if porthere[2:]==b'\x00\x15' and flags['fin']:
                ftpflag = 0
                # 解析ftp......
                ftp2vdict.clear()
            elif ftp2vhere:
                ftp2vhere.append(pkt)
        
        if flags['syn']:
            newtcp1v = TCPONEWAY(pkt,porthere)
            tcp1vdict[porthere] = newtcp1v
            print("created:",struct.unpack('>H',porthere[:2]),struct.unpack('>H',porthere[2:]))
        elif flags['fin']:
            if tcp1vhere:
                print("find end:",struct.unpack('>H',port[:2]),struct.unpack('>H',port[2:]))
                if porthere[2:]==b'\x00\x50' or porthere[:2]==b'\x00\x50':
                    httpparser(tcp1vhere,folderpath)
                    
                if porthere[2:]==b'\x00\x19' or porthere[:2]==b'\x00\x19':
                    # smtp 还原文件
                    pass
                del(tcp1vdict[porthere])
            # else:
            #     print("extra fin")
        elif tcp1vhere:
            tcp1vhere.append(pkt)
        # 既没有syn过，字典中也不存在连接
        else:
            newtcp1v = TCPONEWAY(pkt,porthere)
            tcp1vdict[porthere] = newtcp1v
            print("created w/o syn:",struct.unpack('>H',porthere[:2]),struct.unpack('>H',porthere[2:]))

    # 未被fin确认的
    for port,tcp1v in tcp1vdict.items():
        print("un finned",struct.unpack('>H',port[:2]),struct.unpack('>H',port[2:]))
        if port[2:]==b'\x00\x50' or port[:2]==b'\x00\x50':
            httpparser(tcp1v,folderpath)

outputend = time.time()
print(f"outputtime: {outputend - outputstart}")




