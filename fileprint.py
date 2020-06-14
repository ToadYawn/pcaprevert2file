import sys
import dpkt
import os
import time
import socket
import re
import mimetypes
import zlib
import struct
import email.parser
import email.policy
# SMTP首行命令元组 0 data之后才传输邮件首部和正文 1-2 信封 3-5 有文件 6- 无文件
SMTPfirstline = ('DATA',
    'MAIL','RCPT',
    'STOR','APPE','RETR',
    'HELO','EHLO','AUTH','SEND','SOML','SAML','EXPN','TURN','8BITMIME','ATRN','CHUNKING',
    'DSN','ETRN','PIPELINING','SIZE','STARTTLS','SMTPUTF8','UTF8SMTP','USER','PASS','REIN',
    'QUIT','DELE','REST','ABOR','CWD','CDUP','LIST','MKD','PWD','RMD','RNFR','RNTO','NLST',
    'SYST','STAT','ACCT','SMNT','MODE','STRU','ALLO','NOOP','HELP')
# FTP首行命令元组 0 主动模式 1-3 必须在PORT/PASV之后在数据连接中传输而且传输的是文件 4 被动模式 5 文件传输类型 A文本I二进制 
# 6-8 必须在PORT/PASV之后在数据连接中传输但是传输的不是文件 9- 在控制连接中，无文件
# 3 唯一数据从服务端发出且有文件 4-6 从服务端发出但无文件  
FTPfirstline = ('PORT','RETR','APPE','STOR',
    'PASV','TYPE',
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
def portpair2address(portpair):
    return f"{struct.unpack('>H',portpair[:2])[0]}"+"="+\
    f"{struct.unpack('>H',portpair[2:])[0]}"
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
    # badtcpcnt = 0
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
            # badtcpcnt += 1
            # print("bad")
            continue
        
        tcp1vNextSeq = tcp1vNextSeq + syn + datalen
        lastack = ack
        lastlen = datalen
        lastseq = seq


        firstword = getFirstWord(http)
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
    # print("bad tcp: ", badtcpcnt)
    for msgnum,msg in enumerate(httpmessage['response']):
        data = b''
        # print("<<<Response")
        try:
            r = dpkt.http.Response(msg)
            data = r.body
        except (dpkt.dpkt.NeedData,dpkt.dpkt.UnpackError):
            continue
            # print("主体数据不完整")
        
        if not data:
            continue
        else:
            ext = b''
            try:
                ext = MIMEguesser.guess_extension(r.headers['content-type'][0])
            except(KeyError):
                continue
            isZip = getIsZip(r)
            if isZip:
                content = zlib.decompress(data,wbits = zlib.MAX_WBITS | 16)
                # print("decompressed data：",content[:20])
                data = content
            # else:
                # print("not compressed")
            if not ext:
                ext = '.bin'
            filename = f'http{fileprefix}{msgnum:002d}resp{ext}'
            with open(os.path.join(folderpath,filename), 'wb') as f:
                f.write(data)
                # print("writed!")
    for msgnum,msg in enumerate(httpmessage['request']):
        data = b''
        # print(">>>Request With Entity")
        try:
            r = dpkt.http.Request(msg)
            data = r.body
        except (dpkt.dpkt.NeedData,dpkt.dpkt.UnpackError):
            continue
            # print("主体数据不完整")
        
        if not data:
            continue
        else:
            ext = MIMEguesser.guess_extension(r.headers['content-type'][0])
            isZip= getIsZip(r)
            if isZip:
                content = zlib.decompress(data,wbits = zlib.MAX_WBITS | 16)
                # print("decompressed data：",content[:20])
                data = content
            # else:s
                # print("not compressed")
            if not ext:
                ext = '.bin'
            filename = f'http{fileprefix}{msgnum:002d}req{ext}'
            with open(os.path.join(folderpath,filename), 'wb') as f:
                f.write(data)
                # print("writed!")
def smtpparser(tcp1v,folderpath):
    fileprefix = getfileprefix(next(iter(tcp1v)))
    smtpmessage = []
    tcp1vNextSeq = 0
    lastack = 0
    lastlen = 0
    lastseq = 0
    pktloop = 0

    dataflag = 0
    for pkt in tcp1v:
        buf = pkt[1]
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        smtp = tcp.data
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
            # badtcpcnt += 1
            # print("bad")
            continue
        
        tcp1vNextSeq = tcp1vNextSeq + syn + datalen
        lastack = ack
        lastlen = datalen
        lastseq = seq

        firstword = getFirstWord(smtp)
        # ftp smtp首单词响应码
        pattern = re.compile(r'^[1-6]\d{2}')
        result = pattern.findall(str(firstword))
        isResponse = bool(result)

        if firstword == SMTPfirstline[0]:
            smtpmessage.append(b"")
            dataflag = 1
            # print(firstword)
        elif firstword in SMTPfirstline[1:] or isResponse:
            # print(f"response or not data: {firstword} ")
            dataflag = 0
            # pass
        else :
            if dataflag:
                smtpmessage[-1] += smtp
            #     print("+ pkt ")
            # else:
            #     print("- pkt")
    # print("bad tcp: ", badtcpcnt)
    MIMEguesser = mimetypes.MimeTypes()
    for i,msg in enumerate(smtpmessage):
        parsedMsg = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(msg,headersonly=False)
        # print(f"From: {parsedMsg['from']}")
        # print(f"To: {parsedMsg['to']}")
        count = 0
        for part in parsedMsg.walk():
            count += 1
            ext = MIMEguesser.guess_extension(part.get_content_type())
            filename = part.get_filename(failobj=None) # 'content-disposition'的'filename'不存在且'content-type'的'name'不存在时返回
            if not filename:
                if ext:
                    filename = f'smtp{fileprefix}mail{i:02d}part{count:03d}{ext}'
                else :
                    continue
            else:
                filename = f'smtp{fileprefix}mail{i:02d}part{count:03d} {filename}'
            with open(os.path.join(folderpath, filename), 'wb') as f:
                f.write(part.get_payload(decode=True))
def ftpparser(ftp2vdict,folderpath):
    datalinkcount = -1
    datalinkcport = []
    datalinksport = []
    datalinkfilename = {}
    # 先在服务端发来的包中占位 sport 和 cport 数组
    for port in ftp2vdict.keys():
        if port[:2]==b'\x00\x15':
            for pkt in ftp2vdict[port]:
                buf = pkt[1]
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                ftp = tcp.data
                if not ftp:
                    continue
                firstLineList = ftp.decode().splitlines()[0].split() 
                # print(f"first list here: ",firstLineList)
                firstword = firstLineList[0]
                # 主动模式 数组占位
                if firstword == '200' and firstLineList[1] == 'PORT':
                    datalinkcport.append(b'')
                    datalinksport.append(b'')
                # 被动模式 获取服务端口
                if firstword == '227':
                    # ftpmsg.append(ftp)
                    # datalinkcount += 1
                    # 227 \357\277\275\357\277\275\357\277... (192,168,10,115,243,235) 切分
                    pattern = re.compile(r'\((.*)\)')
                    match = pattern.match(firstLineList[-1])
                    addressWithoutParenthese = match.group(1)
                    addresslist = addressWithoutParenthese.split(",")
                    sport = int(addresslist[-2]) * 256 + int(addresslist[-1])
                    datalinksport.append(struct.pack('>H',sport))
                    datalinkcport.append(b'')
                    # print("done")
    # 从控制连接中得到数据连接端口和传输文件名
    for port in ftp2vdict.keys():
        clientpasvcport = 0
        if port[2:]==b'\x00\x15':
            for pkt in ftp2vdict[port]:
                buf = pkt[1]
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                ftp = tcp.data
                if not ftp:
                    continue
                firstLineList = ftp.decode().splitlines()[0].split() 
                # print(f"first list here: ",firstLineList)
                firstword = firstLineList[0]
                
                # 主动模式 获取服务端口(完整)
                if firstword in FTPfirstline[0]:
                    # PORT 192,168,233,128,213,1
                    addresslist = firstLineList[1].split(",")
                    clientportinbytes = struct.pack('>H',(int(addresslist[-2]) * 256 + int(addresslist[-1])))
                    datalinkcount += 1
                    datalinkcport[datalinkcount] = clientportinbytes
                    datalinksport[datalinkcount] = b'\x00\x14'
                    # print("done",datalinkcount)
                # 被动模式 用于ftp2v一起加count 只有服务端口，客户端口累加(可惜不是按规律来)
                elif firstword in FTPfirstline[4]:
                    datalinkcount += 1
                    if clientpasvcport == 0:
                        clientpasvcport = struct.unpack('>H',port[:2])[0] + 1
                        clientportinbytes = struct.pack('>H',clientpasvcport)
                        datalinkcport[datalinkcount] = clientportinbytes
                    else:
                        clientpasvcport += 1
                        clientportinbytes = struct.pack('>H',clientpasvcport)
                        datalinkcport[datalinkcount] = clientportinbytes
                    # print("done",datalinkcount)
                # 指示包含数据的报文文件名，并和最后一个端口的数据连接对应
                # RETR 文件从服务端发往客户端 s->c
                elif firstword in FTPfirstline[1]:
                    filename = firstLineList[1]
                    errorpattern = re.compile(r'[\\/:\*\?"<>\|]+')
                    result = re.findall(errorpattern,filename)
                    combinedport = datalinksport[datalinkcount] + datalinkcport[datalinkcount]
                    fileprefix = socket.inet_ntoa(ip.src) + "=" + socket.inet_ntoa(ip.dst)+","+portpair2address(combinedport)
                    if result:
                        filename = "errorfilename" + fileprefix + ".bin"
                    datalinkfilename[combinedport] = "ftp" + fileprefix + filename
                    # print("done data s->c here",combinedport)
                # APPE STOR 文件从客户端发往服务端 c->s
                elif firstword in FTPfirstline[2:4]:
                    filename = firstLineList[1]
                    errorpattern = re.compile(r'[\\/:\*\?"<>\|]+')
                    result = re.findall(errorpattern,filename)
                    combinedport = datalinkcport[datalinkcount] + datalinksport[datalinkcount]
                    fileprefix = socket.inet_ntoa(ip.src) + "=" + socket.inet_ntoa(ip.dst)+","+portpair2address(combinedport)
                    if result:
                        filename = "errorfilename" + fileprefix + ".bin"
                    datalinkfilename[combinedport] = "ftp" + fileprefix + filename
                    # print("done c->s datahere",combinedport)
                # LIST NLST REST 有数据非文件 从服务端发往客户端 s->c
                elif firstword in FTPfirstline[6:9]:
                    combinedport = datalinksport[datalinkcount] + datalinkcport[datalinkcount]
                    fileprefix = socket.inet_ntoa(ip.src) + "=" + socket.inet_ntoa(ip.dst)+","+portpair2address(combinedport)
                    filename = "ftp" + fileprefix + ".txt"
                    datalinkfilename[combinedport] = filename
                    # print("done listhere",combinedport)
    
    # print(datalinkcport)
    # print(datalinksport)  
    # print(datalinkfilename)
    # 再到指定的数据连接中获取数据 由于被动模式客户端口不一定是每次+1，只匹配服务端口，keyport用于和控制连接中创建datalinkfilename字典对应
    for port in ftp2vdict.keys():
        # print(f"port:{port}")
        
        for i,sport in enumerate(datalinksport):
            if sport == port[:2]:
                keyport = datalinksport[i] + datalinkcport[i]
            elif sport == port[2:]:
                keyport = datalinkcport[i] + datalinksport[i]
            else:
                continue
            if sport == b'\x00\x14' and keyport != port:
                continue
            ftpdata = b''
            # print(f"yes: {port} keyport:{keyport}")
            for pkt in ftp2vdict[port]:
                buf = pkt[1]
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                ftpdata += tcp.data
            # print(ftpdata[:30])
            if not len(ftpdata):
                # print("Null ftpdata")
                continue
            else:
                # print(f"filename: {datalinkfilename[keyport]}")
                with open(os.path.join(folderpath, datalinkfilename[keyport]), 'wb') as f:
                    f.write(ftpdata)
                    # print(f"done {datalinkfilename[keyport]}")

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
    def __len__(self):
        return len(self._iterable)
    
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
    def __len__(self):
        return len(self._iterable)
# # 输入文件名及文件夹
pcapfilename = sys.argv[1]
pcapfilenamewo = os.path.split(pcapfilename)[-1]
pcapfolder = pcapfilenamewo.split(".")[0]
# print("pcapfolder: ",pcapfolder)

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
print(f"ip conversations: {len(ipcvstdict)}")

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
            
        if porthere[2:]==b'\x00\x15' and flags['syn']:
            ftpflag = 1
            newftp2v = TCPONEWAY(pkt,porthere)
            ftp2vdict[porthere] = newftp2v
            continue
        if ftpflag:
            ftp2vhere = ftp2vdict.get(porthere,None)
            if porthere[2:]==b'\x00\x15' and flags['fin']:
                ftpflag = 0
                ftpparser(ftp2vdict,folderpath)
                ftp2vdict.clear()
            elif ftp2vhere:
                ftp2vhere.append(pkt)
            else:
                newftp2v = TCPONEWAY(pkt,porthere)
                ftp2vdict[porthere] = newftp2v
                
        
        if flags['syn']:
            newtcp1v = TCPONEWAY(pkt,porthere)
            tcp1vdict[porthere] = newtcp1v
            # print("created:",struct.unpack('>H',porthere[:2]),struct.unpack('>H',porthere[2:]))
        elif flags['fin']:
            if tcp1vhere:
                # print("find end:",struct.unpack('>H',porthere[:2]),struct.unpack('>H',porthere[2:]))
                if porthere[2:]==b'\x00\x50' or porthere[:2]==b'\x00\x50':
                    httpparser(tcp1vhere,folderpath)
                    
                if porthere[2:]==b'\x00\x19' or porthere[:2]==b'\x00\x19':
                    smtpparser(tcp1vhere,folderpath)
                del(tcp1vdict[porthere])
            # else:
            #     print("extra fin")
        elif tcp1vhere:
            tcp1vhere.append(pkt)
        # 既没有syn过，字典中也不存在连接
        else:
            newtcp1v = TCPONEWAY(pkt,porthere)
            tcp1vdict[porthere] = newtcp1v
            # print("created w/o syn:",struct.unpack('>H',porthere[:2]),struct.unpack('>H',porthere[2:]))

    # 未被fin确认的
    for port,tcp1v in tcp1vdict.items():
        # print("un finned",struct.unpack('>H',port[:2]),struct.unpack('>H',port[2:]))
        if port[2:]==b'\x00\x50' or port[:2]==b'\x00\x50':
            httpparser(tcp1v,folderpath)
        if port[2:]==b'\x00\x19' or port[:2]==b'\x00\x19':
            smtpparser(tcp1v,folderpath)

outputend = time.time()
print(f"outputtime: {outputend - outputstart}")




