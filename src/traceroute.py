#! /usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import division
import argparse
import time
import pprint
import datetime
from scapy.all import IP, ICMP, sr1
import socket


# Traceroute

MAX_HOPS = 30

def send_with_retries(destination, ttl, timeout, number_retries):
    res = None
    retries = 0
    rtt = 0.0
    while res == None and retries <= number_retries:
        try:
            rtt = time.time()
            res = sr1(IP(dst=destination, ttl=ttl)/ICMP(), timeout=timeout, verbose=0)
            rtt = time.time() - rtt
        except:
            print "* Scapy spurious error"
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


    ttl = 1
    last_hop = None
    final_hop = socket.gethostbyname(destination_address)

    print("Start: {}".format(datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y %z')))
    print 'Destination IP address ' + final_hop

    rtt = 0.0
    hops = []
    while ttl <= MAX_HOPS and last_hop != final_hop:
        hops.append({})
        [res, rtt] = send_with_retries(final_hop, ttl, hop_timeout, hop_retry)
        if res == None:
            print "{0:>2}: N/A".format(ttl)
            ttl = ttl + 1
            continue
        for sample in range(hop_samples):
            [res, rtt] = send_with_retries(final_hop, ttl, hop_timeout, hop_retry)
            if res != None:
                if res[IP].src not in hops[ttl - 1]:
                    hops[ttl - 1][res[IP].src] = []
                hops[ttl - 1][res[IP].src].append(rtt)
        last_hop = most_frequent_hop(hops[ttl - 1])
        print "{0:>2}: {1:<15}".format(ttl, last_hop)
        ttl = ttl + 1

    return hops


# Jump detector

import numpy
from scipy import stats

def thompson_tau(n):
    t = stats.t.ppf(1-(0.05/2), n-2)
    return (t * (n-1)) / (numpy.sqrt(n) * numpy.sqrt(n - 2 + t ** 2))

def jump_detector(inp_hops, hop_samples, modified_thompson=False, verbose=False):

    if verbose:
        print "Performing intercontinental jump detection"

    hops = []
    deltas = []

    for hop in inp_hops:
        if len(hop) > 0:
            hops.append({
                'ip':      hop.keys()[0],
                'mean':    numpy.mean(hop.values()[0]),
                'std':     numpy.std(hop.values()[0]),
                'outlier': False,
            })
        else:
            hops.append(False)

    i = 0
    prev_valid_hop = False
    for hop in hops:
        if hop and prev_valid_hop:
            hop_delta = hop['mean'] - prev_valid_hop['mean']
            if hop_delta < 0:
                hop_delta = 0
            deltas.append({
                'hop_no': i,
                'delta':  hop_delta,
            })
            hop['delta'] = hop_delta
            prev_valid_hop = hop
        elif hop:
            prev_valid_hop = hop
        i += 1


    # Modified Thompson method
    if modified_thompson:

        while len(deltas) > 2:
            print "{} remaining".format(len(deltas))
            mean_delta = numpy.mean([x['delta'] for x in deltas])
            std_delta = numpy.std([x['delta'] for x in deltas])
            for delta in deltas:
                delta['deviation'] = abs(delta['delta'] - mean_delta)
            deltas = sorted(deltas, key=lambda x: x['deviation'])
            cur_hop = deltas[-1]
            tau = thompson_tau(len(deltas)) * std_delta
            if cur_hop['deviation'] > tau:
                hops[cur_hop['hop_no']]['outlier'] = True
                deltas.pop()
            else:
                break

    # Traditional Thompson method
    else:
        mean_delta = numpy.mean([x['delta'] for x in deltas])
        std_delta = numpy.std([x['delta'] for x in deltas])
        tau = thompson_tau(len(deltas)) * std_delta

        if verbose:
            print "Thompson tau value (n = {}): {}".format(len(deltas), thompson_tau(len(deltas)))

        for cur_hop in deltas:
            deviation = abs(cur_hop['delta'] - mean_delta)
            if deviation > tau:
                hops[cur_hop['hop_no']]['outlier'] = True

    if verbose:
        i = 1
        print("Hop Most frequent IP  Avg          Delta         Std     Loss%")
        for hop in hops:
            if hop:
                outlier_msg = "<<< outlier" if hop['outlier'] else ""
                mean_ms = hop['mean'] * 1000
                loss = (hop_samples - len(inp_hops[i-1][hop['ip']])) / hop_samples
                if 'delta' in hop:
                    delta_ms = hop['delta'] * 1000 if hop['delta'] else 0
                    print "{0:>2}: {1:<15}  {2:>7.3f} ms  (d {3:>7.3f} ms) {4:6.3f} {5:5.2f}% {6}" \
                        .format(i, hop['ip'], mean_ms, delta_ms, hop['std']*1000, loss*100, outlier_msg)
                else:
                    print "{0:>2}: {1:<15}  {2:>7.3f} ms                 {3:6.3f} {4:5.2f}% {5}" \
                        .format(i, hop['ip'], mean_ms, hop['std']*1000, loss*100, outlier_msg)
            else:
                print "{0:>2}: {1:<15}".format(str(i), "N/A")
            i += 1

    return hops

# Print per-hop data for plot generation
def print_hops(hops):
    deltas = [hop['delta'] for hop in hops if hop and 'delta' in hop]
    tau = thompson_tau(len(deltas))
    mean_delta = numpy.mean(deltas)
    std_delta = numpy.std(deltas)

    res = 'hop mean std delta norm_delta\n'
    i = 1
    for hop in hops:
        if hop and 'delta' in hop:
            mean = hop['mean']
            std = hop['std']
            delta = hop['delta']
            norm_delta = abs(delta - mean_delta) / std_delta
            res += "{} {} {} {} {}\n".format(i, mean * 1000,
                std * 1000, delta*1000, norm_delta)
        i += 1
    return res


# Map generator
import geoip2.database
from jinja2 import Environment, FileSystemLoader

def map_generator(hops):
    reader = geoip2.database.Reader('../GeoLite2-City.mmdb')

    ip_mas_frecuente_para_cada_hop = map(most_frequent_hop, hops)
    labels = [i+1 for i in range(len(ip_mas_frecuente_para_cada_hop)) if ip_mas_frecuente_para_cada_hop[i] != None]

    ubicaciones = []
    for hop in ip_mas_frecuente_para_cada_hop:
        if hop is not None:
            try:
                print("Geolocalizing {}".format(hop))
                ubicaciones.append(reader.city(hop))
            except geoip2.errors.AddressNotFoundError:
                print("IP {} couldn't be geolocalized".format(hop))


    # http://jinja.pocoo.org/docs/dev/api/
    jinjaenv = Environment(loader = FileSystemLoader('./templates'))
    template = jinjaenv.get_template('mapa.html')
    return template.render(ips=ip_mas_frecuente_para_cada_hop, labels=labels, ubicaciones=ubicaciones)


# Main script

def main():

    parser = argparse.ArgumentParser(description='Yet another trace route utility.')

    parser.add_argument('destination_address', default=None, help='destination address')
    parser.add_argument('--samples', '-s', dest='hop_samples', default=30, type=int,
                        help='number of samples per hop, 30 by default')
    parser.add_argument('--timeout', '-t', dest='hop_timeout', default=0.5, type=float,
                        help='timeout in seconds for each hop, 4 seconds by default')
    parser.add_argument('--retry', '-l', dest='hop_retry', default=2, type=int,
                        help='number of retries for each hop, 2 by default')
    parser.add_argument('--modified-thompson', dest='modified_thompson', action='store_true',
                    help='use modified Thompson method for outlier detection')
    parser.add_argument('--map-file', '-m', dest='map_file', default=False, type=str,
                    help='output HTML file for map of geolocalized hops')
    parser.add_argument('--out-file', '-o', dest='out_file', default=False, type=str,
                    help='output file for processed measurements')
    parser.add_argument('--raw-out-file', '-r', dest='raw_out_file', default=False, type=str,
                    help='output file for per-hop RTT raw measurements')
    parser.add_argument('--mock-input', '-k', dest='mock_input', default=False, type=str,
                    help='input file with measurements to be processed')
    args = parser.parse_args()

    if args.mock_input:
        hops = None
        import ast
        with open(args.mock_input, 'r') as inp:
            read_inp = inp.read()
            hops = ast.literal_eval(read_inp)
    else:
        hops = traceroute(args.destination_address, args.hop_samples, args.hop_timeout, args.hop_retry)

    if args.raw_out_file:
        with open(args.raw_out_file, 'w') as raw_out_file:
            pprint.pprint(hops, raw_out_file)

    processed_hops = jump_detector(hops, args.hop_samples, verbose=True,
        modified_thompson=args.modified_thompson)

    if args.out_file:
        with open(args.out_file, 'w') as out_file:
            printed_hops = print_hops(processed_hops)
            out_file.write(printed_hops)

    if args.map_file:
        with open(args.map_file, 'w') as map_file:
            map_file.write(map_generator(hops))

if __name__ == "__main__":
    main()
