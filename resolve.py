#help
"""
    To run this tool independently...
    1. Type pyhton to open python shell
    2. import resolve
    3. resolve.resolve_domain([domain-name])

    for example for lums network scan type resolve.resolve_domain("lums.edu.pk")
    this will create a file in the tmp folder with name lums.edu.pk_whitelist.txt and that file will
    have the information of all subnets allocated to lums.edu.pk
"""

#dependencies 
"""
To use install argparse and whois libraries
    sudo pip install ipwhois
        dependencies ->sudo pip install dnspython
                     ->sudo pip install ipaddr
"""

#imports
import socket
from ipwhois import IPWhois
import os

# function to parse addr_info list returns a list of entry points
def parse_addr_info_list(addr_info):
    ip_set = []
    for family, sock_t, proto, cannon, sock_name in addr_info:
        ip, port =sock_name
        ip_set.append(ip)
    return list(set(ip_set))

# get address range of an ip
def get_allocated_range(ip):
    print "Fetching whois report of {}".format(ip)
    obj = IPWhois(ip)
    results = obj.lookup_rdap(depth=1)
    #TODO Confirm that cidr is the relevant field
    ip_cidr = results["network"]["cidr"].split(",")
    return ip_cidr

def write_to_file(ip_ranges, domain_name):
    if not os.path.exists("tmp"):
        os.makedirs("tmp")
    os.chdir("tmp")
    filename ="{}_whitelist.txt".format(domain_name) 
    with open(filename,"wb") as f:
        for ip_range in ip_ranges:
            for ip_sub in ip_range:
                ip_sub = ip_sub.replace(" ", "")
                f.write("{}\n".format(str(ip_sub)))  
    os.chdir("..")
    return filename

def resolve_domain(domain_name):
    print "Finding the ip of the domain name"
    try:
        addr_info = socket.getaddrinfo(domain_name, 80, 0, 0, socket.IPPROTO_TCP)
    except e:
        return "failed"
    entry_points = parse_addr_info_list(addr_info)
    ranges = []
    for ip in entry_points:
        ranges.append(get_allocated_range(ip))
    return write_to_file(ranges,domain_name)