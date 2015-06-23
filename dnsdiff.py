import argparse
import json
from tcolors import bcolors
# Using http://www.dnspython.org/ because awesome and using BSD-style license for distribution!
from dns.resolver import Resolver, NoNameservers, NoAnswer, NXDOMAIN

parser = argparse.ArgumentParser(description='Process nameserver entries')
parser.add_argument('-H', '-host', '--hostname', help='domain to query, format <hostname>')
parser.add_argument('-ns1', '--nameserver1', nargs='*', help='first nameserver group address or IP, format: '
                                                             '<nameserver1> <nameserve2>')
parser.add_argument('-ns2', '--nameserver2', nargs='*', help='second nameserver group address or IP, format: '
                                                             '<nameserver1> <nameserve2>')
parser.add_argument('-q', '--query', nargs='*', help='queries to diff, format: \'<host>:<type>\'')
parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='txt file containing hosts and addresses '
                                                                      'separed by space and new queries by newline')
parser.add_argument('-v', '--verbose', nargs='*', default=0)
parser.add_argument('-z', '--zone', type=argparse.FileType('r'), help='zone file provided by nameserver softwares,'
                                                                      'RFC1035')
parser.add_argument('-j', '--json', help='return as JSON')

args = parser.parse_args()
sys_r = Resolver()
dns1 = args.nameserver1
dns2 = args.nameserver2
domain = args.hostname
verbosity = args.verbose
query = args.query
qfile=args.file
qzone=args.zone
sjson = args.json
queries = {}
rjson = {'WARNING': {}, 'FAIL': {}, 'OK': {}}
record_types = ['a', 'aaaa', 'afsdb', 'apl', 'caa', 'cdnskey', 'cds', 'cert', 'cname', 'dhcid', 'dlv', 'dname',
                'dnskey', 'ds', 'hip', 'ipseckey', 'key', 'kx', 'loc', 'mx', 'naptr', 'ns', 'nsec', 'nsec3',
                'nsec3param', 'ptr', 'rrsig', 'rp', 'sig', 'soa', 'srv', 'sshfp', 'ta', 'tkey', 'tlsa', 'tsig', 'txt']

if qfile is None and query is None and qzone is None:
    exit('Need at least one query to be made')
elif query:
    if ' ' in query[0]:
        query = query[0].split(' ')

    for q in query:
        record = q.split(':')[0]
        rtype = q.split(':')[1]
        if record == '@':
            try:
                if queries['@'] and rtype not in queries['@']:
                    queries['@'].append(rtype)
            except KeyError:
                queries['@'] = []
                queries['@'].append(rtype)
        else:
            queries[record] = rtype
else:
    if qfile is not None:
        for q in qfile.readlines():
            q = q.rstrip('\n')
            record = q.split(':')[0]
            rtype = q.split(':')[1]
            if record == '@':
                try:
                    if queries['@'] and rtype not in queries['@']:
                        queries['@'].append(rtype)
                except KeyError:
                    queries['@'] = []
                    queries['@'].append(rtype)
            else:
                queries[record] = rtype
    elif qzone is not None:
        for q in qzone.readlines():
            q = q.rstrip('\n').replace('\t', ' ').replace('  ', ' ').replace('  ', ' ')
            q = q.split(' ')
            if ';' in q[0]:
                continue

            if q[0].split('.')[0] != domain.split('.')[0]:
                record = q[0].split('.')[0]
                if q[2].lower() in record_types:
                    rtype = q[2].lower()
                else:
                    rtype = q[3].lower()
                queries[record] = rtype
            elif q[0].split('.')[0] == domain.split('.')[0]:
                rtype = q[3].lower()
                try:
                    if queries['@'] and rtype not in queries['@']:
                        queries['@'].append(rtype)
                except KeyError:
                    queries['@'] = []
                    queries['@'].append(rtype)

dns_server1 = []
dns_server2 = []

for server in dns1:
    try:
        for item in sys_r.query(server):
            dns_server1.append(item.address)
    except NXDOMAIN:
        dns_server1.append(server)

for server in dns2:
    try:
        for item in sys_r.query(server):
            dns_server2.append(item.address)
    except NXDOMAIN:
        dns_server2.append(server)

for query, rtype in queries.iteritems():
    if query != '' and query != '@':
        tmp_result1 = []
        tmp_result2 = []
        try:
            sys_r.nameservers = dns_server1
            for record in sys_r.query('.'.join([query, domain]), rtype).rrset.items:
                tmp_result1.append(record)
        except NoAnswer:
            tmp_result1.append(None)
        except NoNameservers:
            tmp_result1.append(None)

        try:
            sys_r.nameservers = dns_server2
            for record in sys_r.query('.'.join([query, domain]), rtype).rrset.items:
                tmp_result2.append(record)
        except NoAnswer:
            tmp_result2.append(None)
        except NoNameservers:
            tmp_result2.append(None)

        if not tmp_result1 and not tmp_result2:
            print bcolors.WARNING + query, "NOT FOUND", rtype.upper() + bcolors.ENDC
            try:
                if rjson['WARNING'][rtype] and query not in rjson['WARNING'][rtype]:
                    rjson['WARNING'][rtype].append(query)
            except KeyError:
                rjson['WARNING'][rtype] = []
                rjson['WARNING'][rtype].append(query)

        elif tmp_result1.sort() == tmp_result2.sort():
            if verbosity > 0:
                print bcolors.OKGREEN + '.'.join([query, domain]), "OK", rtype.upper(), "Address => Nameserver(s): '"\
                    + str(tmp_result1) + "' && Nameserver(s): '" + str(tmp_result2) + "'" + bcolors.ENDC
            else:
                print bcolors.OKGREEN + '.'.join([query, domain]), "OK", rtype.upper() + bcolors.ENDC

            try:
                if rjson['OK'][rtype] and query not in rjson['OK'][rtype]:
                    rjson['OK'][rtype].append(query)
            except KeyError:
                rjson['OK'][rtype] = []
                rjson['OK'][rtype].append(query)

        else:
            print bcolors.FAIL + '.'.join([query, domain]), "FAIL", rtype.upper(), "Nameserver(s): '" \
                + str(dns_server1) + "' : result: '" + str(tmp_result1) + "' || Nameserver(s): '" \
                + str(dns_server2) + "', : result: '" + str(tmp_result2) + "'" + bcolors.ENDC

            try:
                if rjson['FAIL'][rtype] and query not in rjson['FAIL'][rtype]:
                    rjson['FAIL'][rtype].append(query)
            except KeyError:
                rjson['FAIL'][rtype] = []
                rjson['FAIL'][rtype].append(query)
    else:
        for r in rtype:
            tmp_result1 = []
            tmp_result2 = []
            try:
                sys_r.nameservers = dns_server1
                for record in sys_r.query(domain, r).rrset.items:
                    tmp_result1.append(record)
            except NoAnswer:
                tmp_result1.append(None)
            except NoNameservers:
                tmp_result1.append(None)

            try:
                sys_r.nameservers = dns_server2
                for record in sys_r.query(domain, r).rrset.items:
                    tmp_result2.append(record)
            except NoAnswer:
                tmp_result2.append(None)
            except NoNameservers:
                tmp_result2.append(None)

            tmp_result1.sort()
            tmp_result2.sort()
            if not tmp_result1 and not tmp_result2:
                print bcolors.WARNING + domain, "NOT FOUND", r.upper() + bcolors.ENDC
                try:
                    if rjson['WARNING'][r] and query not in rjson['WARNING'][r]:
                        rjson['WARNING'][r].append(query)
                except KeyError:
                    rjson['WARNING'][r] = []
                    rjson['WARNING'][r].append(query)
            elif tmp_result1 == tmp_result2:
                if verbosity > 0:
                    print bcolors.OKGREEN + domain, "OK", r.upper(), "Address => Nameserver(s): '" \
                        + str(tmp_result1) + "' && Nameserver(s): '" + str(tmp_result2) + "'" + bcolors.ENDC
                else:
                    print bcolors.OKGREEN + domain, "OK", r.upper() + bcolors.ENDC

                try:
                    if rjson['OK'][r] and query not in rjson['OK'][r]:
                        rjson['OK'][r].append(query)
                except KeyError:
                    rjson['OK'][r] = []
                    rjson['OK'][r].append(query)

            else:
                print bcolors.FAIL + domain, "FAIL", r.upper(), "Nameserver(s): '" + str(dns_server1)\
                    + "' : result: '" + str(tmp_result1) + "' || Nameserver(s): '" + str(dns_server2)\
                    + "', : result: '" + str(tmp_result2) + "'" + bcolors.ENDC

            try:
                if rjson['FAIL'][r] and query not in rjson['FAIL'][r]:
                    rjson['FAIL'][r].append(query)
            except KeyError:
                rjson['FAIL'][r] = []
                rjson['FAIL'][r].append(query)