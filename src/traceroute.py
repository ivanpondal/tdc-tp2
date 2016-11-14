#! /usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import division
import argparse
import time
import pprint
import datetime
import socket
from scapy.all import IP, ICMP, sr1, sr


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
    hops = [{} for i in range(MAX_HOPS)]

    ultimoid = 0
    ttl_final = MAX_HOPS

    for t in range(hop_samples):
        primer_id = ultimoid
        probes_a_enviar = []
        for ttl in range(1, MAX_HOPS+1):
            icmpid = primer_id + ttl
            probes_a_enviar.append(IP(dst=final_hop, ttl=ttl) / ICMP(id=icmpid))
        ultimoid = icmpid

        try:
            res, unanswered = sr(probes_a_enviar, verbose=0, timeout=hop_timeout)
        except socket.error as err:
            sys.exit(err)

        for sent, received in res:
            if received.type == 0:
                # ECHO reply
                id_recibido = received[1].id
            elif received.type == 11:
                # TTL exceeded
                id_recibido = received[3].id
            else:
                # Otro tipo de paquete que no me interesa
                continue
            if id_recibido < primer_id + 1 or id_recibido > ultimoid:
                # recibi una respuesta de algo que no mande en esta tanda. Lo salteo
                continue


            ttl = id_recibido - primer_id
            iphop = received.src
            if received.type == 0:
                if iphop == final_hop:
                    if ttl < ttl_final:
                        ttl_final = ttl
            rtt = (received.time - sent.sent_time)
            if iphop not in hops[ttl-1]:
                hops[ttl-1][iphop] = []
            hops[ttl-1][iphop].append(rtt)

    return hops[:ttl_final+1]


# Jump detector

import numpy
from scipy import stats

def thompson_tau(n):
    t = stats.t.ppf(1-(0.05/2), n-2)
    return (t * (n-1)) / (numpy.sqrt(n) * numpy.sqrt(n - 2 + t ** 2))

def jump_detector(inp_hops, hop_samples, modified_cimbala=False, verbose=False):

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


    # Modified Cimbala method
    if modified_cimbala:

        while len(deltas) > 2:
            print "{} remaining".format(len(deltas))
            mean_delta = numpy.mean([x['delta'] for x in deltas])
            std_delta = numpy.std([x['delta'] for x in deltas])
            for delta in deltas:
                delta['deviation'] = abs(delta['delta'] - mean_delta)
            deltas = sorted(deltas, key=lambda x: x['deviation'])
            cur_hop = deltas[-1]
            tau = thompson_tau(len(deltas)) * std_delta
            print "    mean: {0:7.3f}, std: {1:7.3f}".format(mean_delta * 1000, std_delta * 1000)
            print "    hop {0:<2} (d {1:7.3f})".format(cur_hop['hop_no'], cur_hop['delta'] * 1000)
            print "    tau: {0:7.3f}, deviation: {1:7.3f}".format(tau * 1000, cur_hop['deviation'] * 1000)
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
                    print "{0:>2}: {1:<15}  {2:>7.3f} ms  (d {3:>7.3f} ms) {4:6.3f} {5:5.2f}% {6}".format(i, hop['ip'], mean_ms, delta_ms, hop['std']*1000, loss*100, outlier_msg)
                else:
                    print "{0:>2}: {1:<15}  {2:>7.3f} ms                 {3:6.3f} {4:5.2f}% {5}".format(i, hop['ip'], mean_ms, hop['std']*1000, loss*100, outlier_msg)
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

    res = 'hop hop_delta hop_norm_delta\n'
    i = 1
    prev_mean = 0
    for hop in hops:
        if hop:
            hop_delta = (hop['mean'] - prev_mean)
            hop_norm_delta = (hop_delta - mean_delta) / std_delta
            res += "{} {} {}\n".format(i, hop_delta*1000, hop_norm_delta)
            prev_mean = hop['mean']
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
    parser.add_argument('--mock-input', '-k', dest='mock_input', default=False, type=str,
                    help='input file with measurements to be processed')
    parser.add_argument('--map-file', '-m', dest='map_file', default=False, type=str,
                    help='output HTML file for map of geolocalized hops')
    parser.add_argument('--raw-out-file', '-r', dest='raw_out_file', default=False, type=str,
                    help='output file for per-hop RTT raw measurements')
    parser.add_argument('--out-file', '-o', dest='out_file', default=False, type=str,
                    help='output file for processed measurements')
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

    processed_hops = jump_detector(hops, args.hop_samples, verbose=True, modified_cimbala=False)

    if args.out_file:
        with open(args.out_file, 'w') as out_file:
            printed_hops = print_hops(processed_hops)
            out_file.write(printed_hops)

    if args.map_file:
        with open(args.map_file, 'w') as map_file:
            map_file.write(map_generator(hops))

if __name__ == "__main__":
    main()
