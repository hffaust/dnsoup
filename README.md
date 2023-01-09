# dnsoup
- A thorough dns enumeration tool.
- Performs DNS querires with the option to recursively explore returned answers.
- Outputs results in a JSON object that can be saved to a file.

# Usage:
- `$ python3 dnsoup.py <parameters>`
## Examples:
- `$ python3 dnsoup.py -tf targets_file.txt`
- `$ python3 dnsoup.py -tf targets_file.txt -rf resolvers_file.txt -o dnsoup_output.json`
- `$ python3 dnsoup.py -ts google.com -t 1`
- `$ python3 dnsoup.py -ts google.com -rs 8.8.8.8 75.75.76.76 -r -v -o dnsoup-google.json`
- `$ python3 dnsoup.py -ts google.com -rs 8.8.8.8 75.75.76.76 1.1.1.1 -t 0.5 -r -mrd 5 -vvv -o dnsoup-google.json`
- `$ python3 dnsoup.py -ts google.com -rs 8.8.8.8 -t 3 -r -mrd 5 -vvv -o dnsoup-google.json -rt a aaaa sig openpgpkey cname`
- `$ python3 dnsoup.py --target-string google.com --resolver-string 8.8.8.8 --timeout 3 --recursive --max-recursion-depth 5 -vvv --output dnsoup-google.json --record-types a aaaa sig openpgpkey cname`
## Parameters:
- `--output`, `-o`:
  - Saves JSON output to a file.
- `--recursive`, `-r`
  - Turns on recursive mode, which is off by default.
- `--max-recursion-depth`, `-mrd`
  - Set the maximum recursion depth, which is set to 3 by default.
  - Only has effect when using the `--recursive` option
- `--timeout`, `-t`
  - Sets the timeout value for how long to wait for a DNS response. This option is off by default, but you basically have to use it when operating on targets/resolvers that you have little information about, otherwise the program will take a while.
  - Recommended values are between `0.3` - `2` depending on your internet connection speed.
- `--verbose`, `-v`
  - Sets the verbosity level. Set to 0 by default, but can go up to level 3.
  - Use by doing `-v` for level 1, `-vv` for level 2, or `-vvv` for level 3. 
- `--record-types`, `-rt`
  - The records you want to use. Can input as a space separate list in upper or lowercase.
  - By default, all records will be tried that includes the following: `['A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT','RP','AFSDB','X25','ISDN','RT','NSAP','NSAP_PTR','SIG','KEY','PX','GPOS','AAAA','LOC','NXT','SRV','NAPTR','KX','CERT','A6','DNAME','OPT','APL','DS','SSHFP','IPSECKEY','RRSIG','NSEC','DNSKEY','DHCID','NSEC3','NSEC3PARAM','TLSA','SMIMEA','HIP','NINFO','CDS','CDNSKEY','OPENPGPKEY','CSYNC','ZONEMD','SVCB','HTTPS','SPF','UNSPEC','NID','L32','L64','LP','EUI48','EUI64','TKEY','TSIG','IXFR','AXFR','MAILB','MAILA','ANY','URI','CAA','AVC','AMTRELAY','TA','DLV']`
  - The list of supported records has to do with what the `dnspython` module supports. More inforamtion can be found here: https://dnspython.readthedocs.io/en/latest/_modules/dns/rdatatype.htm
- `--targets-string`, `-ts`
  - Required parameter. Mutually exclusive with `--targets-file`.
  - One of more targets to do dns queries against.
  - Input as a space separated list.
- `--targets-file`, `-tf`
  - Required parameter. Mutually exclusive with `--targets-string`.
  - One of more targets to do dns queries against.
  - File format should have one target per line.
- `--resolvers-string`, `-rs`
  - Optional parameter. Mutually exclusive with `--resolvers-file`.
  - If no resolvers are specified, will use whatever is configured in `/etc/resolv.conf`.
  - One of more resolvers to to use for dns queries.
  - Input as a space separated list.
- `--resolvers-file`, `-rf`
  - Optional parameter. Mutually exclusive with `--resolvers-string`.
  - If no resolvers are specified, will use whatever is configured in `/etc/resolv.conf`.
  - One of more resolvers to to use for dns queries.
  - File format should have one resolver per line.

# Ouput Format
- This is subject to change in the future, but as of now, this is the format:
```
{
  <target_1>:{
    <resolver_1>:[
      {
        target: <target_1>,
        resolver: <resolver_1>,
        resource_record: <record_type>,
        answer: <answer>,
        recursion_depth: <int>,
        timestamp: <timestamp>,
        children: [
        ... repeat structure above with recursion_depth + 1 ...
        ]
      },
      ...
    ],
    <resolver_2>:[...],
  },
  <target_2>:{
    <resolver_1>:[...],
    <resolver_2>:[...],
    ...
  },
  ...
}
```
## Output Format Real Example
- To illustrate this format, here is a snippet of the ouput returned when running this command `$ python3 dns_enumeration_v1.py -ts example.com -rs 8.8.8.8 -r`:
```
{
  "example.com":{
    "8.8.8.8":[
      ... omitted for brevity ...
      {
        "target":"example.com",
        "resolver":"8.8.8.8",
        "resource_record":"NS",
        "answer":"a.iana-servers.net.",
        "recursion_depth":0,
        "timestamp":"2023-01-09T19:17:09.145710Z",
        "children":[
          {
            "target":"a.iana-servers.net.",
            "resolver":"8.8.8.8",
            "resource_record":"NSEC",
            "answer":"b.iana-servers.net. A AAAA RRSIG NSEC",
            "recursion_depth":1,
            "timestamp":"2023-01-09T19:17:11.578780Z"
          },
          {
            "target":"a.iana-servers.net.",
            "resolver":"8.8.8.8",
            "resource_record":"A",
            "answer":"199.43.135.53",
            "recursion_depth":1,
            "timestamp":"2023-01-09T19:17:13.098502Z",
            "children":[
              {
                "target":"199.43.135.53",
                "resolver":"8.8.8.8",
                "resource_record":"PTR",
                "answer":"a.iana-servers.net.",
                "recursion_depth":2,
                "timestamp":"2023-01-09T19:17:16.899579Z"
              }
            ]
          },
          {
            "target":"a.iana-servers.net.",
            "resolver":"8.8.8.8",
            "resource_record":"AAAA",
            "answer":"2001:500:8f::53",
            "recursion_depth":1,
            "timestamp":"2023-01-09T19:17:16.240071Z"
          }
        ]
      },
      ... omitted for brevity ...
    ]
  }
}
```
