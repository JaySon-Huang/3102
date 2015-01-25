#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import array
import select
import struct
import socket
import signal
import logging

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

#debug switch
logging.basicConfig(
    # level=logging.DEBUG,
    level=logging.INFO,
    # format='[line:%(lineno)d] %(levelname)s %(message)s',
    format='%(message)s',
    datefmt='%a, %d %b %Y %H:%M:%S',
)

class JSPing(object):
    MAX_SLEEP = 1000

    def __init__(self, count=4, numDataBytes=56, timeout=3000):
        self.useIPv6 = False
        self.count = count
        self.timeout = timeout
        self.numDataBytes = numDataBytes

    def reset(self):
        self.seq_num = 0
        self.pktsRcvd = 0
        self.pktsSent = 0
        self.totTime = 0.0
        self.maxTime = None
        self.minTime = None

    def __exit_handler(self, signum, frame):
        if self.recall:
            self.recall()
        if self.verbose:
            self.dump_stats()
        sys.exit(-1)

    def dump_stats(self):
        logging.info(
            '\n--- %s ping statistics ---\n'
            '%d packets transmitted, %d packets received, %.1f%% packet loss'%
            (self.hostname, self.pktsSent, self.pktsRcvd,
             (self.pktsSent-self.pktsRcvd)*1.0/self.pktsSent*100
            )
        )
        if self.pktsRcvd > 0:
            logging.info(
                'round-trip min/avg/max = %.3f/%.3f/%.3f ms\n'%
                 (self.minTime, self.totTime/self.pktsRcvd, self.maxTime)
            )

    def execute(self, hostname, verbose=True):
        # 重置统计信息
        self.reset()

        self.hostname = hostname
        self.verbose = verbose
        self.recall = recall

        signal.signal(signal.SIGINT, self.__exit_handler)   # Handle Ctrl-C
        if hasattr(signal, "SIGBREAK"):
            # Handle Ctrl-Break e.g. under Windows
            signal.signal(signal.SIGBREAK, self.__exit_handler)

        destIP = self.__resolve_address(hostname)

        identifier = (os.getpid()) & 0xffff
        for i in range(self.count):
            s, sent_time = self.__send_one(destIP, identifier)
            self.pktsSent += 1

            recv_time, dataSize, iphSrcIP, icmpSeqNumber, iphTTL \
                = self.__receive_one(s, identifier)

            s.close()
            # 显示这次ping的结果,计算delay,添加统计信息
            if recv_time:
                delay = (recv_time-sent_time)*1000
                try:
                    host_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!I", iphSrcIP))
                except AttributeError:
                    # Python on windows dosn't have inet_ntop.
                    host_addr = hostname
                if self.verbose:
                    logging.info(
                        "%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % 
                        (dataSize, host_addr, icmpSeqNumber, iphTTL, delay)
                    )
                self.pktsRcvd += 1
                self.totTime += delay
                if not self.maxTime:
                    self.minTime = self.maxTime = delay
                else:
                    self.maxTime = max(self.maxTime, delay)
                    self.minTime = min(self.minTime, delay)

            else:
                if self.verbose:
                    logging.info(
                        'Request timeout for icmp_seq %d' % i
                    )

            if self.MAX_SLEEP > delay:
                time.sleep( (self.MAX_SLEEP - delay)/1000 )

        # 调用回调函数
        if self.recall:
            self.recall()
        if self.verbose:
            self.dump_stats()

        return self.pktsRcvd != 0

    def __resolve_address(self, hostname):
        if self.useIPv6:
            try:
                # 使用`getaddrinfo`可以支持IPv4/IPv6
                family, type_, proto, canonname, sockaddr = socket.getaddrinfo(hostname, None)
                if family == socket.AF_INET6:
                    self.isIPv6 = True
                elif family == socket.AF_INET:
                    self.isIPv6 = False
                raise NotImplementedError
            except socket.gaierror:
                etype, evalue, etb = sys.exc_info()
                logging.error(
                    'JSPING : cannot resolve %s: Unknown host\n'
                    'error: %s'%(hostname, evalue.args[1])
                )
                raise
        else:
            try:
                hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(hostname)
                self.hostname = hostname
                destIP = ipaddrlist[0]
                self.isIPv6 = False
            except socket.herror:
                etype, evalue, etb = sys.exc_info()
                logging.error(
                    'JSPING : cannot resolve %s: Unknown host\n'
                    'error: %s'%(hostname, evalue.args[1])
                )
                raise
        logging.debug(
            '%s -> IPs:%s'%(hostname, ipaddrlist)
        )
        if self.verbose:
            logging.info(
                'JSPING %s (%s): %d data bytes'%
                (hostname, destIP, self.numDataBytes)
            )
        return destIP
        
    def __send_one(self, destIP, identifier):
        try:
            if self.useIPv6:
                s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 
                            socket.getprotobyname("ipv6-icmp"))
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 
                            socket.getprotobyname("icmp"))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except socket.error:
            etype, evalue, etb = sys.exc_info()
            logging.error(
                'error: "%s"\n'
                'Note that python-ping uses RAW sockets and requiers root rights.' %
                evalue.args[1]
            )
            sys.exit(-1)

        seq_num = self.seq_num
        self.seq_num += 1
        pkt = self.__get_packet(identifier, seq_num)
        
        try:
            sent_time = timer()
            s.sendto(pkt, (destIP, 80)) #ICMP包与端口号无关,随便写的80
        except socket.error:
            s.close()
            etype, evalue, etb = sys.exc_info()
            logging.error(
                'Socket failed: (%s)' % evalue.args[1]
            )
            raise

        return s, sent_time

    def __get_packet(self, identifier, seq_num):
        checksum = 0
        if self.useIPv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, checksum, identifier, seq_num
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, checksum, identifier, seq_num
            )

        # Because of the string/byte changes in python 2/3 we have
        # to build the data differnely for different version
        # or it will make packets with unexpected size.
        numBytesTime = struct.calcsize("d")
        numBytesStuff = (self.numDataBytes - 8) - numBytesTime
        if sys.version[:1] == '2':
            data = 'Q' * numBytesStuff
        else:
            data = [ord('Q') & 0xff] * numBytesStuff
            data = bytearray(data)
        data = struct.pack("d", timer()) + data

        # 计算校验和
        checksum = self.__cal_checksum(header + data)

        # 根据校验和重新构造ICMP头
        if self.useIPv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, checksum, identifier, seq_num
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, checksum, identifier, seq_num
            )
        return header + data

    def __cal_checksum(self, data):
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
        
        logging.debug(
            'checksum of data (%s) is %d'%(data, answer)
        )
        return answer

    def __receive_one(self, s, identifier):
        startedSelect = timer()
        whatReady = select.select([s], [], [], self.timeout/1000)
        howLongInSelect = (timer() - startedSelect)
        if whatReady[0] == []: # Timeout
            return None, 0, 0, 0, 0

        timeReceived = timer()

        recPacket, addr = s.recvfrom(ICMP_MAX_RECV)

        ipHeader = recPacket[:20]
        iphVersion, iphTypeOfSvc, iphLength, \
        iphID, iphFlags, iphTTL, iphProtocol, \
        iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
            "!BBHHHBBHII", ipHeader
        )

        if self.useIPv6:
            icmpHeader = recPacket[0:8]
        else:
            icmpHeader = recPacket[20:28]

        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack(
            "!BBHHH", icmpHeader
        )

        if icmpPacketID == identifier: # Our packet
            dataSize = len(recPacket) - 28
            return timeReceived, (dataSize + 8), iphSrcIP, icmpSeqNumber, iphTTL

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return None, 0, 0, 0, 0

if __name__ == '__main__':
    ping = JSPing()
    if len(sys.argv) == 1:
        ping.execute('114.114.114.114')
        ping.execute('www.baidu.com')
    elif len(sys.argv) == 2:
        ping.execute(sys.argv[1])
    else:
        print("usage: ./ping.py hostname")
        sys.exit(-1)
