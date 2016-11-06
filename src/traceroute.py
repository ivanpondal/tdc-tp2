#! /usr/bin/env python2
import argparse
import time
import pprint
from scapy.all import IP, ICMP, sr1

def send_with_retries(destination, ttl, timeout, number_retries):
    res = None
    retries = 0
    rtt = 0.0
    while res == None and retries <= number_retries:
        rtt = time.clock()
        res = sr1(IP(dst=destination, ttl=ttl)/ICMP(), timeout=timeout,
                verbose=0)
        rtt = time.clock() - rtt
        retries = retries + 1
    return (res, rtt)

def most_frequent_hop(d):
    values_list = list(d.values())
    return list(d.keys())[values_list.index(max(values_list, key=lambda x:len(x)))]

MAX_HOPS = 30

parser = argparse.ArgumentParser(description='Yet another trace route utility.')

parser.add_argument('destination_address', default=None, help='destination address')
parser.add_argument('--samples', '-s', dest='hop_samples', default=30, type=int,
                    help='number of samples per hop, 30 by default')
parser.add_argument('--timeout', '-t', dest='hop_timeout', default=0.5, type=float,
                    help='timeout in seconds for each hop, 4 seconds by default')
parser.add_argument('--retry', '-l', dest='hop_retry', default=2, type=int,
                    help='number of retries for each hop, 2 by default')

args = parser.parse_args()

res = sr1(IP(dst=args.destination_address)/ICMP(), timeout=args.hop_timeout,
        retry=args.hop_retry, verbose=0)

if res == None:
    print 'Couldn\'t solve destination address'
    exit()

ttl = 1
last_hop = None
final_hop = res[IP].src

print 'Destination IP address ' + final_hop

rtt = 0.0
hops = []
while ttl <= MAX_HOPS and last_hop != final_hop:
    hops.append({})
    [res, rtt] = send_with_retries(final_hop, ttl, args.hop_timeout, args.hop_retry)
    if res == None:
        print str(ttl) + ": N/A"
        ttl = ttl + 1
        continue
    for sample in range(args.hop_samples): 
        [res, rtt] = send_with_retries(final_hop, ttl, args.hop_timeout, args.hop_retry)
        if res != None:
            if res[IP].src not in hops[ttl - 1]:
                hops[ttl - 1][res[IP].src] = [] 
            hops[ttl - 1][res[IP].src].append(rtt)
    last_hop = most_frequent_hop(hops[ttl - 1])
    print str(ttl) + ": " + last_hop
    ttl = ttl + 1

pprint.pprint(hops)
