import dpkt
import os
import mimetypes
import zlib
import socket
import io 
import email.parser
import email.policy
import re

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
Messagefirstline = SMTPfirstline + FTPfirstline + HTTPfirstline

# mime类型猜测函数，添加自定义的类型和后缀名
MIMEguesser = mimetypes.MimeTypes()
MIMEguesser.add_type("application/x-javascript",".js") 
# 整个pcap包维护一个连接状态类，用来指示当前读取的数据连接
class LinkStatus:
    def __init__(self,dataLinks=[],dataLinkCount=0,dataLinkSrcPorts=set(),dataLinkDstPorts=set()):
        self.dataLinkCount = dataLinkCount # 当前正在读取数据连接的下标
        self.dataLinks = dataLinks # 数据连接数组（在控制连接中建立） 

# 每次port/pasv时新建一个数据连接
class DATALINK:
    def __init__(self,dataflag=0,datafromServer=0,datafromClient=0,filename=None,data=b'',sport='',cport=''):
        self.datafromServer = datafromServer
        self.datafromClient = datafromClient
        self.dataflag = dataflag
        self.filename = filename
        self.data = data
        self.serverport = sport
        self.clientport = cport
    def export(self,filepath):
        with open(os.path.join(filepath, self.filename), 'wb') as f:
            f.write(self.data)

def getPort(ftpMsg=None):
    sport,cport = 0,0
    node = ftpMsg.head
    nodedataInLine = node.tcpbytes.data.decode().splitlines(keepends=True)
    firstLine = nodedataInLine[0]
    firstLineList = firstLine.split()
    if ftpMsg.firstWord == 'PORT':
        addresslist = firstLineList[1].split(",")
        cport = int(addresslist[-2]) * 256 + int(addresslist[-1])
        sport = 20
    elif ftpMsg.firstWord == '227':
        pattern = re.compile(r'\((.*)\)')
        match = pattern.match(firstLineList[-1])
        addressWithoutParenthese = match.group(1)
        addresslist = addressWithoutParenthese.split(",")
        sport = int(addresslist[-2]) * 256 + int(addresslist[-1])
    return sport,cport

def getFilename(ftpMsg=None):
    node = ftpMsg.head
    nodedataInLine = node.tcpbytes.data.decode().splitlines(keepends=True)
    firstLine = nodedataInLine[0]
    firstLineList = firstLine.split()
    filename = firstLineList[1]
    return filename

def isCommandPORT(ftpMsg=None):
    node = ftpMsg.head
    nodedataInLine = node.tcpbytes.data.decode().splitlines(keepends=True)
    firstLine = nodedataInLine[0]
    firstLineList = firstLine.split()
    command = firstLineList[1]
    if command == 'PORT':
        return True
    else:
        return False

def getIsZip(r=None):
    if 'content-encoding'in r.headers and r.headers['content-encoding']=='gzip':
        return True
    else:
        return False
        
# 一TCP连接建一个文件夹，文件夹中包含多个httpmsg还原的文件
def session2folder(tcpsession=[],foldername=None):
    sessionString = f"{socket.inet_ntoa(tcpsession.socket[0])};"+\
            f"{tcpsession.socket[2]}-"+\
            f"{socket.inet_ntoa(tcpsession.socket[1])};"+\
            f"{tcpsession.socket[3]}"
    folderPath = os.path.join(foldername,sessionString)
    if not os.path.exists(folderPath):
        os.mkdir(folderPath)
    print(f'folder created')
    return folderPath

def httpToFile(tcpsession=[],foldername=None):
    
    folderPath = session2folder(tcpsession,foldername)
    print(f"{tcpsession.sizeApp}")
    appmsg = tcpsession.headApp
    msgNum = 0
    while appmsg != None:
        isZip = False
        data = b'' # 用于解压后写入文件的数据（报文的主体部分）
        ext = '' # 文件后缀 
        isData = False # 标志是有无主体的报文
        msgData = appmsg.getdata() # 完整报文数据
        print(f"--- {msgNum:02d} HTTPmsg data length {len(msgData)} ---")
        if not msgData:
            print("报文为空")
            msgNum += 1
            appmsg = appmsg.nextApp
            continue

        # 保存报文
        messageTxtName = f'{msgNum:02d}.txt'
        with open(os.path.join(folderPath,messageTxtName), 'wb') as txt:
            txt.write(msgData)
        
        # 将主体写到文件
        if appmsg.firstWord in HTTPfirstline[:2]:
            print("<<<Response")
            try:
                r = dpkt.http.Response(msgData)
                data = r.body
            except dpkt.dpkt.NeedData:
                print("主体数据不完整")
            
            if not data:
                isData = False
            else:
                ext = MIMEguesser.guess_extension(r.headers['content-type'])
                print(f"ext:{ext}")

                isZip = getIsZip(r)
                isData = True
        elif appmsg.firstWord in HTTPfirstline[2:7]:
            print(">>>Request With Entity")
            try:
                r = dpkt.http.Request(msgData)
                data = r.body
            except dpkt.dpkt.NeedData:
                print("主体数据不完整")
            
            if not data:
                isData = False
            else:
                ext = MIMEguesser.guess_extension(r.headers['content-type'])
                print(f"ext:{ext}")

                isZip= getIsZip(r)
                isData = True
        elif appmsg.firstWord in HTTPfirstline[7:]:
            print(">>>Request Without Entity")
            isData = False 
        else:
            print(f"{appmsg.firstWord}")
            isData = True 
        # print(f"<<<data:{data}")

        if not isData:
            print("body is empty!")
            msgNum += 1
            appmsg = appmsg.nextApp
            continue
        
        print(f"zip?:{isZip}")
        if isZip:
            print(f"'content-encoding':{r.headers['content-encoding']}")
            content = zlib.decompress(data,wbits = zlib.MAX_WBITS | 16)
            print("decompressed data：",content[:20])
            data = content
        else:
            print("not compressed")

        if not ext:
            ext = '.bin'

        filename = f'{msgNum:02d}{ext}'
        with open(os.path.join(folderPath,filename), 'wb') as f:
            f.write(data)

        msgNum += 1
        appmsg = appmsg.nextApp

def smtpToFile(tcpsession=[],foldername=None):
    folderPath = session2folder(tcpsession,foldername)
    appmsg = tcpsession.headApp
    msgNum = 0
    while appmsg != None:
        msgData = appmsg.getdata()
        msgNum += 1
        # 保存报文
        msgTxtName = f'{msgNum:02d}.txt'
        with open(os.path.join(folderPath,msgTxtName), 'wb') as txt:
            txt.write(msgData)

        # 是data是才解析报文
        if appmsg.firstWord == 'DATA':
            msgData = msgData[6:]
            print(f"message body: {msgData[:10]}")
            parsedMsg = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(msgData,headersonly=False)
            print(f'Keys: {parsedMsg.items()}')
            print(f"To: {parsedMsg['to']}")
            count = 0
            for part in parsedMsg.walk():
                count += 1
                ext = MIMEguesser.guess_extension(part.get_content_type())
                filename = part.get_filename(failobj=None) # 'content-disposition'的'filename'不存在且'content-type'的'name'不存在时返回
                if not filename:
                    if ext:
                        filename = f'part-{count:03d}{ext}'
                    else :
                        continue
                with open(os.path.join(folderPath, filename), 'wb') as f:
                    f.write(part.get_payload(decode=True))
                
        appmsg = appmsg.nextApp

def ftpToFile(tcpsession=[],foldername=None,linkstatus=None):
    folderPath = session2folder(tcpsession,foldername)
    if linkstatus.dataLinkCount >= len(linkstatus.dataLinks) and linkstatus.dataLinkCount != 0:
        print("All data has been read")
        return
    # 为ftp一个session维持一个count 计数ftp创造和接受的数据连接 只在存取命令时改变
    count = 0 
    # 控制连接：从客户端发到服务端
    if tcpsession.socket[3] == 21:
        ftpMsg = tcpsession.headApp
        print(f"apps:{tcpsession.sizeApp}")
        while ftpMsg!= None:# msg loop
            # port 主动模式
            if ftpMsg.firstWord in FTPfirstline[0]:
                print(ftpMsg.firstWord)
                print(f"this is {count} ACTIVE datalink created")
                sport,cport = getPort(ftpMsg)
                datalink = DATALINK(sport=sport,cport=cport)
                linkstatus.dataLinks.append(datalink)
            # pasv 被动模式
            elif ftpMsg.firstWord in FTPfirstline[1]:
                print(ftpMsg.firstWord)
                print(f"this is {count} PASSIVE datalink created")
                datalink = DATALINK()
                linkstatus.dataLinks.append(datalink)
            # RETR 
            elif ftpMsg.firstWord in FTPfirstline[3]:
                print(ftpMsg.firstWord)
                linkstatus.dataLinks[count].filename = getFilename(ftpMsg)
                linkstatus.dataLinks[count].dataflag = 1
                linkstatus.dataLinks[count].datafromServer = 1
                count += 1
            # STOR APPE
            elif ftpMsg.firstWord in FTPfirstline[4:6]:
                print(ftpMsg.firstWord)
                linkstatus.dataLinks[count].filename = getFilename(ftpMsg)
                linkstatus.dataLinks[count].dataflag = 1
                linkstatus.dataLinks[count].datafromClient = 1
                count += 1
            # 从 server 发出但无文件'LIST','NLST','REST'
            elif ftpMsg.firstWord in FTPfirstline[6:9]:
                print(ftpMsg.firstWord)
                linkstatus.dataLinks[count].datafromServer = 1
                linkstatus.dataLinks[count].dataflag = 0
                count += 1
            # 直接在控制连接中传输
            elif ftpMsg.firstWord in FTPfirstline[9:]:
                pass
            ftpMsg = ftpMsg.nextApp

    # 控制连接：从服务端发到客户端
    elif tcpsession.socket[2] == 21:
        ftpMsg = tcpsession.headApp 
        while ftpMsg!= None:# msg loop
            # 200 主动模式的确认
            if ftpMsg.firstWord == '200':
                # 而且是对port命令的确认
                if(isCommandPORT(ftpMsg)):
                    print(f"this is {count} ACTIVE datalink returned")
                    # linkstatus.dataLinkPorts.add(linkstatus.dataLinks[count].serverport)
                    count += 1
            # 227 被动模式的确认
            elif ftpMsg.firstWord == '227':
                print(f"this is {count} PASSIVE datalink returned")
                sport,cport = getPort(ftpMsg)
                linkstatus.dataLinks[count].serverport = sport
                # linkstatus.dataLinkPorts.add(sport) 
                count += 1
            ftpMsg = ftpMsg.nextApp
    
    elif linkstatus.dataLinkCount == 0:
        return
    # 从服务端发出，且是用于发送数据（而不是回应客户端的）
    elif tcpsession.socket[2] == linkstatus.dataLinks[linkstatus.dataLinkCount].serverport and linkstatus.dataLinks[linkstatus.dataLinkCount].datafromServer == 1:
        print(f"here from server: {linkstatus.dataLinkCount} dataflag:{linkstatus.dataLinks[linkstatus.dataLinkCount].dataflag}")
        ftpMsg = tcpsession.headApp

        # 有文件
        if linkstatus.dataLinks[linkstatus.dataLinkCount].dataflag==1:
            print("data from server!")
            linkstatus.dataLinks[linkstatus.dataLinkCount].data = ftpMsg.getdata()
            linkstatus.dataLinks[linkstatus.dataLinkCount].export(folderPath)
        else:
            print("list data or other")
        linkstatus.dataLinkCount += 1
        
        
    # 从客户端发出，且是用于发送数据（而不是回应服务端的）
    elif tcpsession.socket[3] == linkstatus.dataLinks[linkstatus.dataLinkCount].serverport and linkstatus.dataLinks[linkstatus.dataLinkCount].datafromClient == 1:
        print(f"here from client: {linkstatus.dataLinkCount} dataflag:{linkstatus.dataLinks[linkstatus.dataLinkCount].dataflag}")
        ftpMsg = tcpsession.headApp
        
        # 有文件
        if linkstatus.dataLinks[linkstatus.dataLinkCount].dataflag == 1:
            print("data from client!")
            linkstatus.dataLinks[linkstatus.dataLinkCount].data = ftpMsg.getdata()
            linkstatus.dataLinks[linkstatus.dataLinkCount].export(folderPath)
        else:
            print("list data or other")
        
        linkstatus.dataLinkCount += 1

