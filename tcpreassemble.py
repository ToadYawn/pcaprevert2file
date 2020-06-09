import dpkt
import sys
import os
import struct #用于解析tcp的mss
import re #用于匹配firstWord是否为响应码
import sessionParser
import socket
import time

# TCPSESSION -> APPSESSION -> TCPNODE
# 同一TCP连接 -- 同一应用层报文 -- 一个包
class TCPSESSION:
    def __init__(self,ip,tcp,headApp = None):
        self.socket = (ip.src,ip.dst,tcp.sport,tcp.dport)
        self.initSeq = tcp.seq
        self.headApp = headApp
        self.sizeApp = 1
    def hasApp(self, appmessage):
        if isinstance(appmessage,APPMESSAGE):
            item = appmessage
        else:
            item = APPMESSAGE(appmessage)

        if self.headApp == None:
            self.headApp = item
        else:
            tail = self.headApp
            while tail.nextApp!=None:
                tail = tail.nextApp
            tail.nextApp = item
        self.sizeApp += 1

class APPMESSAGE:
    def __init__(self, tcpsession = None, nextApp=None, head = None,firstWord=None):
        self.tcpsession = tcpsession
        self.head = head
        self.nextSeq = head.seq + head.len
        self.nextApp = nextApp
        self.firstWord = firstWord                  
    def hasNode(self, tcpnode):
        if isinstance(tcpnode,TCPNODE):
            item = tcpnode
        else:
            item = TCPNODE(tcpnode)
        
        if self.head == None:
            self.head = item
        else:
            tail = self.head
            while tail.next!=None:
                tail = tail.next
            tail.next = item
        self.nextSeq += item.len
    def getdata(self):
        nodeIndex = 1
        data = b''
        node = self.head
        while node!=None:
            print(f"---- getting data No.{nodeIndex}({node.pktcount}) node length: {node.len}")
            data += node.tcpbytes.data
            node = node.next
            nodeIndex += 1
        return data

class TCPNODE:
    def __init__(self, tcp, appmessage=None,next=None,count=None):
        self.next = next
        self.appmessage = appmessage
        self.pktcount = count
        self.ack = tcp.ack
        self.syn = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
        self.fin = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
        self.seq = tcp.seq
        self.len = len(tcp.data)

        self.tcpbytes = tcp

# def getMss(opts):
#     if opts[0][0] == 2:
#         mss = struct.unpack('>H',opts[0][1])[0]
#     return mss

def getFirstWord(pktnode):
    try:
        nodedataInLine = pktnode.tcpbytes.data[:20].decode().splitlines(keepends=True)
        print(nodedataInLine)
        firstLine = nodedataInLine[0]
        # print(firstLine)
        firstLineList = firstLine.split()
        # print(firstLineList)
        firstWord = str(firstLineList[0])
    except (UnicodeDecodeError, IndexError):
        firstWord = None
    print(f"firstword:{firstWord}")
    return firstWord

pcapname = sys.argv[1]
f1 = open(pcapname,'rb')
pcapfile = dpkt.pcap.Reader(f1)
packets = pcapfile.readpkts()

pktcount = 0 # 包计数
sessNum = 0 # 同socket的tcp会话计数
tcpSessions = []
appSessions = []

loadstart = time.time()
# 将packets生成TCPnode/APPmessage/TCPsession,读取APPmessage的数据
for ts,buf in packets:
    pktcount += 1
    print(f"--- packet num: {pktcount:02d} packet length: {len(buf)} ---")

    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        print("this is not IPv4 packet!:",eth.type)
        continue
    ip = eth.data
    print("ip length: %d"%(ip.len))
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        print("this is not TCP packet!:",ip.p)
        continue
    tcp = ip.data
    pktsocket = (ip.src,ip.dst,tcp.sport,tcp.dport)
    pktnode = TCPNODE(tcp,count=pktcount)

    
    rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
    if rst_flag:
        continue
    # 解析出首行首单词 非ASCII数据类型的为data
    firstWord = getFirstWord(pktnode)

    print(f"syn: {pktnode.syn} ack: {pktnode.ack} ")
    # 根据syn 和ack判断是否是新的tcp连接,无syn时根据socket判断属于哪个tcpsession
    if pktnode.syn and not pktnode.ack :
        sessNum += 1
        print(f"session num: {sessNum}")
        clientAppMessage = APPMESSAGE(head=pktnode,firstWord=firstWord)
        clientAppMessage.nextSeq += 1
        appSessions.append(clientAppMessage)

        clientTcpSession = TCPSESSION(ip,pktnode.tcpbytes,headApp=clientAppMessage)
        tcpSessions.append(clientTcpSession)
        print(f"seq:{pktnode.seq-clientTcpSession.initSeq}({pktnode.seq}) nextseq: {clientAppMessage.nextSeq-clientTcpSession.initSeq}({clientAppMessage.nextSeq})")
        # 打印payload
        tcpoptions = dpkt.tcp.parse_opts(pktnode.tcpbytes.opts)
        # print("Message segment size client side is: " + str(getMss(tcpoptions)))
        print("client start content: ",pktnode.tcpbytes)
        pass
        
    elif pktnode.syn and pktnode.ack :
        sessNum += 1
        print(f"session num: {sessNum}")
        serverAppMessage = APPMESSAGE(head=pktnode,firstWord=firstWord)
        serverAppMessage.nextSeq += 1
        appSessions.append(serverAppMessage)

        serverTcpSession = TCPSESSION(ip,pktnode.tcpbytes,headApp=serverAppMessage)
        tcpSessions.append(serverTcpSession)
        print(f"________seq:{pktnode.seq-serverTcpSession.initSeq}({pktnode.seq}) nextseq: {serverAppMessage.nextSeq-serverTcpSession.initSeq}({serverAppMessage.nextSeq})")
        # 打印payload
        tcpoptions = dpkt.tcp.parse_opts(tcp.opts)
        # print("________Message segment size server side is: " + str(getMss(tcpoptions)))
        print("________server start content: ",pktnode.tcpbytes)
        pass

    elif not pktnode.syn :
        match = 0 # 是否已经存在session(由syn开始的)
        for i in range(len(tcpSessions)):
            session = tcpSessions[i]
            if pktsocket != session.socket :
                continue
            else:
                match = 1
                break
            
        if match: # 存在时接在匹配的session后
            print(f"session num: {i+1}")
            # 到最后一个message
            message = session.headApp
            while message.nextApp != None:
                message = message.nextApp
            print(f"needseq: {message.nextSeq-session.initSeq}({message.nextSeq})")
            print(f"seq:{pktnode.seq-session.initSeq}({pktnode.seq}) nextseq: {message.nextSeq-session.initSeq+pktnode.len}({message.nextSeq+pktnode.len})")
            # 剔除错误的tcp
            if pktnode.seq-session.initSeq != message.nextSeq-session.initSeq :
                print(f"~not include {message.nextSeq-session.initSeq}")
            if pktnode.seq-session.initSeq == message.nextSeq-session.initSeq :
                print("~include")
                lastnode = message.head
                while lastnode.next != None:
                    lastnode = lastnode.next
                if lastnode.ack == pktnode.ack and lastnode.len == pktnode.len and lastnode.seq == pktnode.seq:
                    print("!!! Duplicated ack !!!")
                    continue
                
                if not pktnode.len  :
                    print("empty tcp")
                    message.hasNode(pktnode)
                    continue
                
                # 根据firstWord判断是否是新的message,不是新的则接在该message后面,否则新建message
                # 不可decode 或者 能够decode为ascii，但是既不在请求头元组中，头三位又不是响应码，这就是数据部分
                if firstWord == None:
                    print(f"first word is not ascii :{pktnode.tcpbytes.data[:20]}")
                    message.hasNode(pktnode)
                    continue
                else:
                    pattern = re.compile(r'^[1-6]\d{2}')
                    result = pattern.findall(firstWord)
                    isResponse = bool(result)
                    print(f"first word is ascii: find code?{result}")
                    if firstWord not in sessionParser.Messagefirstline and not isResponse:
                        print(f"first word not a header :{firstWord}")
                        message.hasNode(pktnode)
                        continue
                
                newMessage = APPMESSAGE(head=pktnode,firstWord=firstWord)
                appSessions.append(newMessage)
                session.hasApp(newMessage)
                print(f"+++ add head:seq:{pktnode.seq-session.initSeq} nextseq: {newMessage.nextSeq-session.initSeq }+++")
        else: # 没有匹配的session,新建session
            sessNum += 1
            print(f"session num: {sessNum}")
            newAppMessage = APPMESSAGE(head=pktnode,firstWord=firstWord)
            appSessions.append(newAppMessage)

            newTcpSession = TCPSESSION(ip,pktnode.tcpbytes,headApp=newAppMessage)
            tcpSessions.append(newTcpSession)
            print(f"seq:{pktnode.seq-newTcpSession.initSeq}({pktnode.seq}) nextseq: {newAppMessage.nextSeq-newTcpSession.initSeq}({newAppMessage.nextSeq})")
    # if pktcount>10:
    #     break
loadend = time.time()
# 每个pcap包创建一个文件夹
cwd = os.getcwd()
pcappattern = re.compile(r'(\.pcap|\.\\)')
rst = re.sub(pcappattern,"",pcapname)
print(f"pcapname: {pcapname} 文件名: {rst}")
foldername = os.path.join(cwd,rst)
if not os.path.exists(rst):
    os.mkdir(rst)
parsestart = time.time()
# 对会话依次解析
linkStatus = sessionParser.LinkStatus()
for i in range(len(tcpSessions)):
    session = tcpSessions[i]
    print(f"=== tcp session number: {i:2d} ===")
    sessionString = f"{socket.inet_ntoa(session.socket[0])};"+\
            f"{session.socket[2]}-"+\
            f"{socket.inet_ntoa(session.socket[1])};"+\
            f"{session.socket[3]}"
    print(sessionString)

    if session.socket[2] == 80 or session.socket[3] == 80:
        sessionParser.httpToFile(session,foldername)
    elif session.socket[2] == 25 or session.socket[3] == 25:
        sessionParser.smtpToFile(session,foldername)
    else:
        sessionParser.ftpToFile(session,foldername,linkStatus)

parseend = time.time()

print(f"sort time: {loadend-loadstart}")
print(f"parse time: {parseend-parsestart}")
