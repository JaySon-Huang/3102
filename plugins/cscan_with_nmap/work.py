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
            nm = PortScanner()
        except PortScannerError, e:
            # 没有检测到namp
            print "Please Install nmap first."
            raise e
        except:
            raise
        print 'running cscan'
        nm.scan(hosts=domain+'/24', arguments='-sP -sV')
        self.result = {
            'root_domain': [],
            'ip': nm.all_hosts(),
            'domain':[]
        }

        super(cscan_with_nmap, self).end()
        return self.result
