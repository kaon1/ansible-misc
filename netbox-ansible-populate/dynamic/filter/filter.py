#!/usr/bin/python
"""
Kaon Thana 7-27-2021
Forked from original author: Nick Russo <njrusmc@gmail.com> (Pluralsight training course)
File contains custom filters for use in Ansible playbooks.
https://www.ansible.com/
"""
import json
import jmespath
from pprint import pprint
#import flatten_3d


def flatten_3d(list_of_lists):
    if len(list_of_lists) == 0:
        return list_of_lists
    if isinstance(list_of_lists[0], list):
        return flatten_3d(list_of_lists[0]) + flatten_3d(list_of_lists[1:])
    return list_of_lists[:1] + flatten_3d(list_of_lists[1:])

class FilterModule:
    """
    Defines a filter module object.
    """

    @staticmethod
    def filters():
        """
        Return a list of hashes where the key is the filter
        name exposed to playbooks and the value is the function.
        """
        return {
            'map_ip_name': FilterModule.map_ip_name,
        }

    @staticmethod
    def map_ip_name(ip_list,json_data):
        ip_map = []
        for ip in ip_list:
            ##skip juniper self mgmt ips that start with 128.0
            if ip.startswith('128.'): continue

            ip_by_name = jmespath.search(
                    '[*].\"interface-information\"[*].\"physical-interface\"[*].\"logical-interface\"[?\"address-family\"[0].\"interface-address\"[0].\"ifa-local\"[?\"data"==`'+ip+'`]].name[*].data',
                    json_data)

            ## check if IP has a mask. if it has no mask add a /32
            check_for_mask = ip.split('/')
            if len(check_for_mask) < 2:
                ip = ip + "/32"

            if flatten_3d(ip_by_name):
                ip_map = [{'intf_name': flatten_3d(ip_by_name)[0], 'ip': ip}] + ip_map
            else:
                ip_map = [{'intf_name': 'empty', 'ip': ip}] + ip_map
        return ip_map
