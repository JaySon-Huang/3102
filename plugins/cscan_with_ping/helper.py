#!/usr/bin/env python
# coding=utf-8

import sys
import time
import array
import struct
import socket
import select

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    timer = time.time

# ICMP parameters
ICMP_ECHOREPLY = 0      # Echo reply (per RFC792)
ICMP_ECHO = 8           # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128        # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)
ICMP_MAX_RECV = 2048        # Max size of incoming buffer

NumDataBytes = 56
Timeout = 3000

def resolve_hostname(hostname):
    hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(hostname)
    return ipaddrlist

def get_c_class_ips(iplist):
    pre_set = set()
    for ip in iplist:
        pre_set.add(ip[:ip.rfind('.')+1])
    iplist = [pre + str(_) for _ in range(1,255) for pre in pre_set]
    return iplist


# 发送ICMP Echo包的helper

def __cal_checksum(data):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if (len(data) % 2):
        data += "\x00"
    converted = array.array("H", data)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)

    val &= 0xffffffff # Truncate val to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)

    val = (val >> 16) + (val & 0xffff)    # Add high 16 bits to low 16 bits
    val += (val >> 16)                    # Add carry from above (if any)
    answer = ~val & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)
    
    return answer

def __get_packet(identifier, seq_num):
    checksum = 0
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, checksum, identifier, seq_num
    )

    # Because of the string/byte changes in python 2/3 we have
    # to build the data differnely for different version
    # or it will make packets with unexpected size.
    numBytesTime = struct.calcsize("d")
    numBytesStuff = (NumDataBytes - 8) - numBytesTime
    if sys.version[:1] == '2':
        data = 'Q' * numBytesStuff
    else:
        data = [ord('Q') & 0xff] * numBytesStuff
        data = bytearray(data)
    data = struct.pack("d", timer()) + data

    # 计算校验和
    checksum = __cal_checksum(header + data)

    # 根据校验和重新构造ICMP头
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, checksum, identifier, seq_num
    )
    return header + data

def send_one(destIP, identifier, seq_num=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    pkt = __get_packet(identifier, seq_num)
    
    try:
        sent_time = timer()
        s.sendto(pkt, (destIP, 80)) #ICMP包与端口号无关,随便写的80
    except socket.error:
        s.close()
        raise

    return s, sent_time

def receive_one(s, identifier, seq):
    startedSelect = timer()
    timeLeft = Timeout/1000
    while True:
        whatReady = select.select([s], [], [], Timeout/1000)
        timeReceived = timer()
        howLongInSelect = timeReceived - startedSelect
        if whatReady[0] == []: # Timeout
            return None

        recPacket, addr = s.recvfrom(ICMP_MAX_RECV)

        # # IP头的解析
        # ipHeader = recPacket[:20]
        # iphVersion, iphTypeOfSvc, iphLength, \
        # iphID, iphFlags, iphTTL, iphProtocol, \
        # iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
        #     "!BBHHHBBHII", ipHeader
        # )

        icmpHeader = recPacket[20:28]
        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack(
            "!BBHHH", icmpHeader
        )
        
        # identifier一致，说明这是我们发出的包
        if icmpPacketID == identifier and seq == icmpSeqNumber:
            dataSize = len(recPacket) - 28
            return timeReceived

        # 判断是否超时
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return None

        # 继续while循环等待下一个回复的包

if __name__ == '__main__':
    iplist = resolve_hostname('www.baidu.com')
    iplist = get_c_class_ips(iplist)
