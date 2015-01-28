#!/usr/bin/env python
# coding=utf-8

from core.plugin import Plugin
from comm.coroutine import WorkerPool

import os
import socket

from .helper import resolve_hostname, get_c_class_ips
from .helper import send_one, receive_one

class cscan_with_ping(Plugin):
    
    has_root_privilege = None

    def __init__(self):
        super(cscan_with_ping, self).__init__('cscan_with_ping')
        self.wp = WorkerPool()

        # 第一次init才需要测试权限
        if cscan_with_ping.has_root_privilege is not None:
            return

        # 测试是否有权限创建RAW socket
        try:
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except socket.error:
            cscan_with_ping.has_root_privilege = False
            self.logger.exception(
                'Create RAW socket FAILED!\n'
                'Note that plugin cscan_with_ping need root privilege.'
            )
        else:
            cscan_with_ping.has_root_privilege = True
            

    def start(self, domain, domain_type, level):
        super(cscan_with_ping, self).start(domain, domain_type, level)

        self.result = {
            'root_domain': [],
            'ip': [],
            'domain': [],
        }

        if not cscan_with_ping.has_root_privilege:
            super(cscan_with_ping, self).end()
            return self.result

        if domain_type == 'domain':
            try:
                iplist = resolve_hostname(domain)
            except socket.gaierror:
                # 域名解析错误
                super(cscan_with_ping, self).end()
                return self.result
        elif domain_type == 'ip':
            iplist = [domain]

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
        except socket.error:
            # TODO: 发送失败，重发处理?
            return

        # FIXME: 协程导致的现象是否可以改进?
        recv_time = receive_one(sock, identifier, seq)
        sock.close()
        if recv_time is not None:
            delay = (recv_time-sent_time)*1000
            self.result['ip'].append(ip)
