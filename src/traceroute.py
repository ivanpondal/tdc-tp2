#! /usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import time
import pprint
import geoip2.database
from jinja2 import Environment, FileSystemLoader
from scapy.all import IP, ICMP, sr1

MAX_HOPS = 30

def send_with_retries(destination, ttl, timeout, number_retries):
    res = None
    retries = 0
    rtt = 0.0
    while res == None and retries <= number_retries:
        rtt = time.time()
        res = sr1(IP(dst=destination, ttl=ttl)/ICMP(), timeout=timeout,
                verbose=0)
        rtt = time.time() - rtt
        retries = retries + 1
    return (res, rtt)

def most_frequent_hop(d):
    try:
        values_list = list(d.values())
        return list(d.keys())[values_list.index(max(values_list, key=lambda x:len(x)))]
    except ValueError:
        return None

def traceroute(
        destination_address,
        hop_samples = 30,
        hop_timeout = 0.5,
        hop_retry = 2
    ):

    res = sr1(IP(dst=destination_address)/ICMP(), timeout=hop_timeout,
            retry=hop_retry, verbose=0)

    if res == None:
        raise ValueError('Couldn\'t solve destination address')
        return

    ttl = 1
    last_hop = None
    final_hop = res[IP].src

    print 'Destination IP address ' + final_hop

    rtt = 0.0
    hops = []
    while ttl <= MAX_HOPS and last_hop != final_hop:
        hops.append({})
        [res, rtt] = send_with_retries(final_hop, ttl, hop_timeout, hop_retry)
        if res == None:
            print str(ttl) + ": N/A"
            ttl = ttl + 1
            continue
        for sample in range(hop_samples):
            [res, rtt] = send_with_retries(final_hop, ttl, hop_timeout, hop_retry)
            if res != None:
                if res[IP].src not in hops[ttl - 1]:
                    hops[ttl - 1][res[IP].src] = []
                hops[ttl - 1][res[IP].src].append(rtt)
        last_hop = most_frequent_hop(hops[ttl - 1])
        print str(ttl) + ": " + last_hop
        ttl = ttl + 1

    return hops

def main():

    parser = argparse.ArgumentParser(description='Yet another trace route utility.')

    parser.add_argument('destination_address', default=None, help='destination address')
    parser.add_argument('--samples', '-s', dest='hop_samples', default=30, type=int,
                        help='number of samples per hop, 30 by default')
    parser.add_argument('--timeout', '-t', dest='hop_timeout', default=0.5, type=float,
                        help='timeout in seconds for each hop, 4 seconds by default')
    parser.add_argument('--retry', '-l', dest='hop_retry', default=2, type=int,
                        help='number of retries for each hop, 2 by default')

    args = parser.parse_args()

    hops = traceroute(args.destination_address, args.hop_samples, args.hop_timeout, args.hop_retry)

    pprint.pprint(hops)

    # reader = geoip2.database.Reader('../GeoLite2-City.mmdb')

    # ip_mas_frecuente_para_cada_hop = map(most_frequent_hop, hops)
    # labels = [i+1 for i in range(len(ip_mas_frecuente_para_cada_hop)) if ip_mas_frecuente_para_cada_hop[i] != None]

    # ubicaciones = []
    # for hop in ip_mas_frecuente_para_cada_hop:
    #     if hop is not None:
    #         try:
    #             print("geolocalizando {}".format(hop))
    #             ubicaciones.append(reader.city(hop))
    #         except geoip2.errors.AddressNotFoundError:
    #             print("No encontramos geolocalización para la IP {}".format(hop))


    # # http://jinja.pocoo.org/docs/dev/api/
    # jinjaenv = Environment(loader = FileSystemLoader('./templates'))
    # template = jinjaenv.get_template('mapa.html')
    # print(template.render(ips=ip_mas_frecuente_para_cada_hop, labels=labels, ubicaciones=ubicaciones))

if __name__ == "__main__":
    main()
