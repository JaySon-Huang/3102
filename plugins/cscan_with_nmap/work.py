#!/usr/bin/env python
# coding=utf-8

from core.plugin import Plugin
from nmap import PortScanner


class cscan_with_nmap(Plugin):
    def __init__(self):
        super(cscan_with_nmap, self).__init__('cscan_with_nmap')

    def start(self, domain, domain_type, level):
        super(cscan_with_nmap, self).start(domain, domain_type, level)
        try:
            # import pdb;pdb.set_trace()
            nm = PortScanner()
        except nmap.PortScannerError:
            # 没有检测到namp
            print "Please Install nmap first."
            raise
        except:
            print "Unknow exception"
            raise
        nm.scan(hosts=domain+'/24', arguments='-sP -sV')

        self.result = {
            'root_domain': [],
            'ip': nm.all_hosts(),
            'domain':[]
        }

        super(cscan_with_nmap, self).end()
        return self.result
