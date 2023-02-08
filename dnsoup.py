import socket
import os
import sys
import dns.resolver
import time
import argparse
import json
from datetime import datetime, timezone
import warnings
warnings.filterwarnings('ignore')

'''
RESOURCES LIST:
[1]  https://stackoverflow.com/questions/6076690/verbose-level-with-argparse-and-multiple-v-options
[2]  https://stackoverflow.com/questions/5603364/how-to-code-argparse-combinational-options-in-python
[3]  https://stackoverflow.com/questions/43786174/how-to-pass-and-parse-a-list-of-strings-from-command-line-with-argparse-argument
[4]  https://stackoverflow.com/questions/11540854/file-as-command-line-argument-for-argparse-error-message-if-argument-is-not-va
[5]  https://stackoverflow.com/questions/27957373/python-import-and-initialize-argparse-after-if-name-main
[6]  https://gist.github.com/linuxluigi/0613c2c699d16cb5e171b063c266c3ad
[7]  https://stackoverflow.com/questions/8989457/dnspython-setting-query-timeout-lifetime
[8]  https://mkaz.blog/code/python-argparse-cookbook/
[9]  https://stackoverflow.com/questions/55324449/how-to-specify-a-minimum-or-maximum-float-value-with-argparse
[10] https://stackoverflow.com/questions/14463277/how-to-disable-python-warnings
'''

verbosity = 0

def print_answer_details(answer):
    print("-"*32)
    try:
        print(f"{answer.address}")
    except Exception as e:
        pass
    try:    
        print(f"answer.choose_relativity(): {answer.choose_relativity()}")
    except Exception as e:
        pass
    print(f"\nanswer.covers(): {answer.covers()}"
    f"\nanswer.extended_rdatatype(): {answer.extended_rdatatype()}"
    f"\nanswer.rdclass: {answer.rdclass}"
    f"\nanswer.rdtype: {answer.rdtype}"
    f"\nanswer.to_digestable(): {answer.to_digestable()}"
    f"\nanswer.to_text(): {answer.to_text()}")
    try:
        print(f"\nanswer.validate(): {answer.validate()}")
    except Exception as e:
        pass
    print("-"*32)


def init_resolver(resolver_addrs=None):
    '''
    Note: Using dnspython's Stub Resolver component here.

    Dnspython’s resolver module implements a “stub resolver”, which does DNS recursion with the aid of a remote “full resolver” 
    provided by an ISP or other service provider. By default, dnspython will use the full resolver specified by its host system, 
    but another resolver can easily be used simply by setting the nameservers attribute.

    Link: https://dnspython.readthedocs.io/en/latest/resolver.html#resolver
    '''
    resolver = dns.resolver.Resolver()
    # If no resolver_addrs are passed than the resolvers in 
    # /etc/resolv.conf are defaulted to.
    if resolver_addrs != None:
        resolver.nameservers = resolver_addrs
    if verbosity > 1:
        print("Initializing with following DNS Resolvers:")
        for ns in resolver.nameservers:
            print(f"\t{ns}:{resolver.port}")
        print()
    return resolver


def update_resolver_nameserver(resolver, nameserver):
    # Simple way to make the nameserver to be just one nameserver
    # this way we can query different nameservers if we put this in 
    # a loop to update the nameserver per iteration.
    # If we leave it to the original implementation where a 
    # list of nameservers is passed in, then we will only
    # see the results of the namserver that returns the first
    # successful query, where as the other nameserver would have
    # returned something completely different.
    # Will properly set the port if nameserver is in ip:port syntax,
    # otherwise it is defaulted to port 53. 
    port = 53 # Default DNS port
    if ':' in nameserver:
        temp = nameserver.split(':')
        if len(temp) == 2:
            # must be length of 2 exactly 
            # because we are expecting input like: 1.2.3.4:53
            try:
                port = int(temp[1])
            except Exception as e:
                print(f"[ERROR] {nameserver} port is not a number")
                return False
            else:
                if((1 <= port <= 65535) == False):
                    # Port is not in valid range
                    print(f"[ERROR] {nameserver} port is between 1 and 65535")
                    return False
            nameserver = temp[0] # nameserver = first part of ip:port string
        else:
            return False

    if is_ip_address(nameserver) == False:
        # namerserver was not a valid IP address
        return False
    resolver.nameservers = [nameserver]
    resolver.port = port
    return resolver


def update_resolver_timeout(resolver, timeout):
    '''
    See this link:  https://dnspython.readthedocs.io/en/latest/resolver-class.html
    We could use resolver.timeout if we are only concerned with time for server to responsd.
    Or we can use resolver.lifetime if we want to set total round trip time.
    Lifetime seems to work better than timeout in for our purposes.
    '''
    #resolver.timeout = float(timeout)
    resolver.lifetime = float(timeout)
    return resolver


def hostname_single_dns_lookup(target, resolver, nameserver, record_type, recursion_depth):
    successful_queries = []
    try:
        answers = resolver.query(target, record_type)            
        for answer in answers:
            query_result = {}
            if verbosity > 0:
                print(f'[ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ]  [ Answer:{answer} ]')
            if verbosity > 2:
                print_answer_details(answer)
            query_result['target'] = target
            query_result['resolver'] = nameserver
            query_result['resource_record'] = record_type
            query_result['answer'] = answer.to_text()
            query_result['recursion_depth'] = recursion_depth
            query_result['timestamp'] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            if verbosity > 1:
                print(query_result)
            successful_queries.append(query_result)
    except dns.resolver.NoAnswer as e:
        if verbosity > 1:
            print(f'\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> No answer')
        if verbosity > 2:
            print(e)
    except dns.resolver.NXDOMAIN as e:
        if verbosity > 1:
            print(f'\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> NXDOMAIN')
        if verbosity > 2:
            print(e)
    except dns.rdatatype.UnknownRdatatype as e:
        if verbosity > 1:
            print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Unknown by Resolver")
        if verbosity > 2:
            print(e)
    except dns.resolver.NoMetaqueries as e:
        if verbosity > 1:
            print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Metaqueries not allowed by Resolver")
        if verbosity > 2:
            print(e)
    except dns.resolver.NoNameservers as e:
        if verbosity > 1:
            print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> caused NoNameservers error")
        if verbosity > 2:
            print(e)
    except dns.exception.Timeout as e:
        if verbosity > 1:
            print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Query timed out")
        if verbosity > 2:
            print(e)
    finally:
        time.sleep(0.05) # sleep to prevent rate limiting
    return successful_queries


def dns_lookup(target_type, target, resolver, nameserver, record_types, recursive_flag, recursion_depth):
    successful_queries = []
    if target_type == 'hostname':
        for record_type in record_types:
            try:
                answers = resolver.query(target, record_type)            
                for answer in answers:
                    query_result = {}
                    if verbosity > 0:
                        print(f'[ Target: {target} ]  [ Resolver: {nameserver} ]  [ Record: {record_type} ]  [ Answer: {answer} ]')
                    if verbosity > 2:
                        print_answer_details(answer)
                    query_result["target"] = target
                    query_result["resolver"] = nameserver
                    query_result["resource_record"] = record_type
                    query_result["answer"] = answer.to_text()
                    if recursive_flag:
                        query_result["recursion_depth"] = recursion_depth
                    query_result["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    if verbosity > 1:
                        print(query_result)
                    successful_queries.append(query_result)
            except dns.resolver.NoAnswer as e:
                if verbosity > 1:
                    print(f'\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> No answer')
                if verbosity > 2:
                    print(e)
            except dns.resolver.NXDOMAIN as e:
                if verbosity > 1:
                    print(f'\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> NXDOMAIN')
                if verbosity > 2:
                    print(e)
            except dns.rdatatype.UnknownRdatatype as e:
                if verbosity > 1:
                    print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Unknown by Resolver")
                if verbosity > 2:
                    print(e)
            except dns.resolver.NoMetaqueries as e:
                if verbosity > 1:
                    print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Metaqueries not allowed by Resolver")
                if verbosity > 2:
                    print(e)
            except dns.resolver.NoNameservers as e:
                if verbosity > 1:
                    print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> caused NoNameservers error")
                if verbosity > 2:
                    print(e)
            except dns.exception.Timeout as e:
                if verbosity > 1:
                    print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Query timed out")
                if verbosity > 2:
                    print(e)
            finally:
                time.sleep(0.05) # sleep to prevent rate limiting
            
    elif target_type == 'ip':
        record_type = 'PTR'
        # Perform the reverse DNS lookup on IP address
        try:
            answers = resolver.query(dns.reversename.from_address(target), 'PTR')
            for answer in answers:
                query_result = {}
                if verbosity > 0:
                    print(f'[ Target: {target} ]  [ Resolver: {nameserver} ]  [ Record: {record_type} ]  [ Answer: {answer} ]')
                query_result["target"] = target
                query_result["resolver"] = nameserver
                query_result["resource_record"] = "PTR"
                query_result["answer"] = answer.to_text()
                if recursive_flag:
                    query_result["recursion_depth"] = recursion_depth
                query_result["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                successful_queries.append(query_result)
        except dns.resolver.NoAnswer as e:
            if verbosity > 1:
                print(f'\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> No answer')
            if verbosity > 2:
                print(e)
        except dns.resolver.NXDOMAIN as e:
            if verbosity > 1:
                print(f'\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> NXDOMAIN')
            if verbosity > 2:
                print(e)
        except dns.resolver.NoNameservers as e:
                if verbosity > 1:
                    print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> caused NoNameservers error")
                if verbosity > 2:
                    print(e)
        except dns.exception.Timeout as e:
            if verbosity > 1:
                print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Query timed out")
            if verbosity > 2:
                print(e)
        except dns.exception.SyntaxError as e:
            if verbosity > 1:
                print(f"\t[EXCEPTION] [ Target:{target} ]  [ Resolver:{nameserver} ]  [ Record:{record_type} ] ---> Input malformed")
            if verbosity > 2:
                print(e)
        finally:
                time.sleep(0.05) # sleep to prevent rate limiting
    else:
        # shouldn't get to this point as long as previous code is right
        print("[ERROR] target_type parameter not specified as 'hostname' or 'ip'")
        sys.exit(1)
    return successful_queries


def is_ip_address(target):
    if( " " in target ):
        # return false if theres a blank space in the ip address
        return False
    try:
        net_addr = socket.inet_aton(target)
        if verbosity > 1:
            print(f"{target} converts to {net_addr}")
    except socket.error:
        return False
    except UnicodeError:
        return False
    return True


def is_hostname(target):
    try:
        hostname_ip = socket.gethostbyname(target)
        if verbosity > 1:
            print(f"{target} maps to {hostname_ip}")
    except socket.gaierror:
        return False
    except UnicodeError:
        return False
    return True


def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return True


def file_to_list(filename):
    f = open(filename, 'r')
    output_list = []
    for line in f.readlines():
        output_list.append(line.strip())
    return output_list


def range_limited_float_type(arg):
    """ Type function for argparse - a float within some predefined bounds """
    MIN_VAL = 0.001
    MAX_VAL = 100
    try:
        f = float(arg)
    except ValueError:    
        raise argparse.ArgumentTypeError("Must be a floating point number")
    if f < MIN_VAL or f > MAX_VAL:
        raise argparse.ArgumentTypeError("Argument must be < " + str(MAX_VAL) + "and > " + str(MIN_VAL))
    return f


def get_parser():
    """
    Creates a new argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Determines if targets in a file are IPs or Hostnames, and then does DNS lookups for every record type known by the python DNS module."
    )
    parser.add_argument('--output','-o', dest='output_file', default=None)
    parser.add_argument('--recursive','-r', dest='recursive_flag', action='store_true', default=False)
    parser.add_argument('--max-recursion-depth','-mrd', dest='max_recursion_depth', type=int, default=3)
    parser.add_argument('--timeout','-t', dest='timeout', type=range_limited_float_type, default=None)
    parser.add_argument('-v', '--verbose', dest='verbose', action='count', default=0)
    # Every DNS Record the python module knows about
    # As seen here: 
    # https://dnspython.readthedocs.io/en/latest/_modules/dns/rdatatype.htm
    parser.add_argument('--record-types', '-rt', 
        dest='record_types', 
        choices=['A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT','RP','AFSDB','X25','ISDN','RT','NSAP','NSAP_PTR','SIG','KEY','PX','GPOS','AAAA','LOC','NXT','SRV','NAPTR','KX','CERT','A6','DNAME','OPT','APL','DS','SSHFP','IPSECKEY','RRSIG','NSEC','DNSKEY','DHCID','NSEC3','NSEC3PARAM','TLSA','SMIMEA','HIP','NINFO','CDS','CDNSKEY','OPENPGPKEY','CSYNC','ZONEMD','SVCB','HTTPS','SPF','UNSPEC','NID','L32','L64','LP','EUI48','EUI64','TKEY','TSIG','IXFR','AXFR','MAILB','MAILA','ANY','URI','CAA','AVC','AMTRELAY','TA','DLV', 'a', 'ns', 'md', 'mf', 'cname', 'soa', 'mb', 'mg', 'mr', 'null', 'wks', 'ptr', 'hinfo', 'minfo', 'mx', 'txt', 'rp', 'afsdb', 'x25', 'isdn', 'rt', 'nsap', 'nsap_ptr', 'sig', 'key', 'px', 'gpos', 'aaaa', 'loc', 'nxt', 'srv', 'naptr', 'kx', 'cert', 'a6', 'dname', 'opt', 'apl', 'ds', 'sshfp', 'ipseckey', 'rrsig', 'nsec', 'dnskey', 'dhcid', 'nsec3', 'nsec3param', 'tlsa', 'smimea', 'hip', 'ninfo', 'cds', 'cdnskey', 'openpgpkey', 'csync', 'zonemd', 'svcb', 'https', 'spf', 'unspec', 'nid', 'l32', 'l64', 'lp', 'eui48', 'eui64', 'tkey', 'tsig', 'ixfr', 'axfr', 'mailb', 'maila', 'any', 'uri', 'caa', 'avc', 'amtrelay', 'ta', 'dlv'], 
        nargs='+', 
        default=['A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT','RP','AFSDB','X25','ISDN','RT','NSAP','NSAP_PTR','SIG','KEY','PX','GPOS','AAAA','LOC','NXT','SRV','NAPTR','KX','CERT','A6','DNAME','OPT','APL','DS','SSHFP','IPSECKEY','RRSIG','NSEC','DNSKEY','DHCID','NSEC3','NSEC3PARAM','TLSA','SMIMEA','HIP','NINFO','CDS','CDNSKEY','OPENPGPKEY','CSYNC','ZONEMD','SVCB','HTTPS','SPF','UNSPEC','NID','L32','L64','LP','EUI48','EUI64','TKEY','TSIG','IXFR','AXFR','MAILB','MAILA','ANY','URI','CAA','AVC','AMTRELAY','TA','DLV']
    )
    tgroup = parser.add_argument_group(title='REQUIRED: targets string or targets filename')
    targets_group = tgroup.add_mutually_exclusive_group(required=True)
    targets_group.add_argument('--targets-string','-ts', dest='targets_string', default=[], nargs='+')
    targets_group.add_argument('--targets-file', '-tf', dest='targets_file', default=None)
    rgroup = parser.add_argument_group(title='OPTIONAL: resolvers string or resolvers filename')
    resolvers_group = rgroup.add_mutually_exclusive_group(required=False)
    resolvers_group.add_argument('--resolvers-string','-rs', dest='resolvers_string', default=[], nargs='+')
    resolvers_group.add_argument('--resolvers-file', '-rf', dest='resolvers_file', default=None)
    return parser


def main(timeout, targets, resolver_addrs, record_types, recursive, max_recursion_depth, verbose, output_file):
    global verbosity
    verbosity = verbose 
    all_queries = {}
    resolver = init_resolver()
    if resolver_addrs is not [] and resolver_addrs is not None:
        nameserver_list = resolver_addrs
    else:
        nameserver_list = resolver.nameservers
    if timeout:
        resolver = update_resolver_timeout(resolver, timeout)
    witnessed_targets = []
    
    while targets:
        target_obj = targets.pop()
        target = target_obj[0] # target address
        recursion_depth = target_obj[1] # recursion level
        if target in witnessed_targets:
            continue
        else:
            witnessed_targets.append(target)
        if is_ip_address(target):
            if verbosity > 1:
                print(f"{target} is an IP address")
            target_type = 'ip'
        elif is_hostname(target):
            if verbosity > 1:
                print(f"{target} is a hostname")
            target_type = 'hostname'
        else:
            if verbosity > 1:
                print(f"{target} is neither an IP address nor a hostname")
            continue

        for nameserver in nameserver_list:
            og_resolver = resolver
            resolver = update_resolver_nameserver(resolver, nameserver)
            if resolver == False:
                resolver = og_resolver # restore resolver value otherwise we get attribute accessing issues later.
                # The namerserver passed in was not an IP so skip over it. 
                continue            
            successful_queries = dns_lookup(target_type, target, resolver, nameserver, record_types, recursive, recursion_depth)
            
            if successful_queries:
                if verbosity > 1:
                    print("\nSucessful Queries")
                    print(successful_queries)
                    print()

                target_to_nameserver_mapping = all_queries.get(target, {})
                nameserver_to_queries_list = target_to_nameserver_mapping.get(nameserver,[])

                if recursive:
                    for successful_query in successful_queries:
                        recursive_witnessed_targets = []
                        recursive_targets = []
                        recursive_targets.append(successful_query)
                        
                        while recursive_targets:
                            # recursive_target_item == 'rti'
                            recursive_target = recursive_targets.pop()
                            rti_answer = recursive_target.get('answer')
                            rti_recursion_depth = recursive_target.get('recursion_depth')
                            if rti_answer in witnessed_targets:
                                # this points back to a base (root level) target we examined.
                                # may be some issues here if we find a recurisve target thats also in our list
                                # of targets to process but has not yet been processed... shouldnt be an issue, 
                                # but may end up with some duplicate data in that case. 
                                continue
                            if rti_answer in recursive_witnessed_targets:
                                # we have duplicate answers in our recursion, 
                                # no need to recursive twice. 
                                continue
                            recursive_witnessed_targets.append(rti_answer)
                                                        
                            if rti_recursion_depth + 1 > max_recursion_depth:
                                continue
                            new_recursion_depth = rti_recursion_depth + 1
                            
                            if is_ip_address(rti_answer):
                                successful_recursive_queries = dns_lookup('ip', rti_answer, resolver, nameserver, record_types, recursive, new_recursion_depth)
                            elif is_hostname(rti_answer):
                                successful_recursive_queries = dns_lookup('hostname', rti_answer, resolver, nameserver, record_types, recursive, new_recursion_depth)
                            else:
                                if verbosity > 1:
                                    print(f"{target} is neither an IP address nor a hostname")
                                continue
                            if successful_recursive_queries:
                                recursive_target['children'] = []
                                for successful_recursive_query in successful_recursive_queries:
                                    recursive_target['children'].append(successful_recursive_query)
                                    recursive_targets.append(successful_recursive_query)

                nameserver_to_queries_list.extend(successful_queries)
                target_to_nameserver_mapping.update({nameserver:nameserver_to_queries_list})
                all_queries.update({target:target_to_nameserver_mapping})

    if all_queries:
        print(json.dumps(all_queries))

    if output_file is not None:
        if output_file[-5:] != '.json':
            # Adds '.json' extension if it does not exist.
            output_file += '.json'
        with open(output_file, 'w') as output_json_file:
            json.dump(all_queries, output_json_file)


if __name__ == "__main__":
    parser = get_parser()
    args = parser.parse_args()

    if args.targets_file:
        if(is_valid_file(parser, args.targets_file)):
            targets = file_to_list(args.targets_file)
    else:
        targets = args.targets_string
    if args.verbose > 1:
        print(f"Targets: {targets}")
    # Turn targets into a list of tuple with:
    # target name being the first value in the tuple,
    # and the recursion depth being the second value (aka zero since these are root nodes). 
    targets = [(i, 0) for i in targets]
    if args.resolvers_file:
        if(is_valid_file(parser, args.resolvers_file)):
            resolver_addrs = file_to_list(args.resolvers_file)
    elif args.resolvers_string:
        resolver_addrs = args.resolvers_string
    else:
        resolver_addrs = None
    if args.verbose > 1:
        if resolver_addrs is not None:
            print(f"Resolvers: {resolver_addrs}")
        else:
            print("Using default resolvers in /etc/resolv.conf")

    record_types = list(set([i.upper() for i in args.record_types]))
    if args.verbose > 1:
        print(f"Using the following record types: {record_types}")

    main(args.timeout, targets, resolver_addrs, record_types, args.recursive_flag, args.max_recursion_depth, args.verbose, args.output_file)
