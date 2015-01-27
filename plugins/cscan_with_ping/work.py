#!/usr/bin/env python
# coding=utf-8

from core.plugin import Plugin
from comm.coroutine import WorkerPool

import os
import socket

from .helper import resolve_hostname, get_c_class_ips
from .helper import send_one, receive_one

class cscan_with_ping(Plugin):
    def __init__(self):
        super(cscan_with_ping, self).__init__('cscan_with_ping')
        self.wp = WorkerPool()

    def start(self, domain, domain_type, level):
        super(cscan_with_ping, self).start(domain, domain_type, level)

        self.result = {
            'root_domain': [],
            'ip': [],
            'domain': [],
        }

        try:
            iplist = resolve_hostname(domain)
        except socket.gaierror:
            # 域名解析错误
            super(cscan_with_ping, self).end()
            return self.result

        iplist = get_c_class_ips(iplist)
        for seq, ip in enumerate(iplist):
            self.wp.add_job(self.__scan_one, ip, seq)

        self.wp.run()

        super(cscan_with_ping, self).end()
        return self.result

    def __scan_one(self, ip, seq):
        identifier = (os.getpid()) & 0xffff
        try:
            sock,sent_time = send_one(ip, identifier, seq)
            recv_time = receive_one(sock, identifier, seq)
            sock.close()
            if recv_time is not None:
                delay = (recv_time-sent_time)*1000
                self.result['ip'].append(ip)
                
        except socket.error:
            # TODO: 发送包文出错
            pass
