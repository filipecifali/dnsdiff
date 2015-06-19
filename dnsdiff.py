import argparse
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
args = parser.parse_args()
sys_r = Resolver()
dns1 = args.nameserver1
dns2 = args.nameserver2
domain = args.hostname
verbosity = args.verbose
query = args.query
qfile=args.file
qzone=args.zone

queries = {}

if qfile is None and query is None and qzone is None:
    exit('Need at least one query to be made')
elif query:
    for q in query:
        record = q.split(':')[0]
        rtype = q.split(':')[1]
        queries[record] = rtype
else:
    if qfile is not None:
        for q in qfile.readlines():
            q = q.rstrip('\n')
            record = q.split(':')[0]
            rtype = q.split(':')[1]
            queries[record] = rtype
    elif qzone is not None:
        for q in qzone.readlines():
            q = q.rstrip('\n').replace('\t', ' ').replace('  ', ' ').replace('  ', ' ')
            q = q.split(' ')
            if ';' in q[0]:
                continue

            if q[0].split('.')[0] != domain.split('.')[0]:
                record = q[0].split('.')[0]
            elif q[0].split('.')[0] == domain.split('.')[0]:
                record = ''

            rtype = q[2].lower()
            queries[record] = rtype

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
    tmp_result1 = []
    tmp_result2 = []
    if query != '':
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

        if len(tmp_result1) == 0 and len(tmp_result2) == 0:
            print bcolors.WARNING + query, "NOT FOUND!!" + bcolors.ENDC
        elif tmp_result1.sort() == tmp_result2.sort():
            if verbosity > 0:
                print bcolors.OKGREEN + query, "OK!! Address => nameserver(s): '" + str(tmp_result1) + "' && " \
                                                        "nameserver(s): '" + str(tmp_result2) + "'" + bcolors.ENDC
            else:
                print bcolors.OKGREEN + query, "OK!!" + bcolors.ENDC
        else:
            print bcolors.FAIL + query, "FAIL!!", "nameserver(s): '" + str(dns_server1) + "' : result: '" + \
                str(tmp_result1) + "' || nameserver(s): '" + str(dns_server2) + "', : result: '" + str(tmp_result2) + \
                "'" + bcolors.ENDC
    else:
        try:
            sys_r.nameservers = dns_server1
            for record in sys_r.query(domain, rtype).rrset.items:
                tmp_result1.append(record)
        except NoAnswer:
            tmp_result1.append(None)
        except NoNameservers:
            tmp_result1.append(None)

        try:
            sys_r.nameservers = dns_server2
            for record in sys_r.query(domain, rtype).rrset.items:
                tmp_result2.append(record)
        except NoAnswer:
            tmp_result2.append(None)
        except NoNameservers:
            tmp_result2.append(None)

        if len(tmp_result1) == 0 and len(tmp_result2) == 0:
            print bcolors.WARNING + domain, "NOT FOUND!!" + bcolors.ENDC
        elif tmp_result1.sort() == tmp_result2.sort():
            if verbosity > 0:
                print bcolors.OKGREEN + domain, "OK!! Address => nameserver(s): '" + str(tmp_result1) + "' && " \
                                                        "nameserver(s): '" + str(tmp_result2) + "'" + bcolors.ENDC
            else:
                print bcolors.OKGREEN + domain, "OK!!" + bcolors.ENDC
        else:
            print bcolors.FAIL + domain, "FAIL!!", "nameserver(s): '" + str(dns_server1) + "' : result: '" + \
                str(tmp_result1) + "' || nameserver(s): '" + str(dns_server2) + "', : result: '" + str(tmp_result2) + \
                "'" + bcolors.ENDC
