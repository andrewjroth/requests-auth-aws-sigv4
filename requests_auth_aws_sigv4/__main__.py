#!/bin/env python3
from __future__ import print_function
import logging
import sys
import os.path
import argparse
import re
from collections import OrderedDict
import requests
from requests.compat import urlparse

from . import AWSSigV4


def parse_response_headers(resp):
    ''' Parse response to yield formatted header lines '''
    yield "HTTP/{} {} {}".format((resp.raw.version / 10.0), resp.status_code, resp.reason)
    for name, value in OrderedDict(sorted(resp.headers.items(), key=lambda t: t[0])).items():
        yield "{}: {}".format(name, value)


if __name__ == '__main__':
    if sys.argv[0].endswith('__main__.py'):
        prog_name = os.path.basename(os.path.dirname(os.path.abspath(__file__)))
    else:
        prog_name = os.path.basename(sys.argv[0])
    
    logging.basicConfig()
    log = logging.getLogger(prog_name)
    
    cli = argparse.ArgumentParser(prog=prog_name,
        description='Send a request with AWS Signature V4 added for authentication')
    
    # Match cURL options, if possible
    cli.add_argument('url', help='Request URL')
    cli.add_argument('-i', '--include', action='store_true',
        help="Include protocol response headers in the output")
    cli.add_argument('-H', '--header', action='append',
        help="Pass custom header(s) to server")
    cli.add_argument('-v', '--verbose', action='store_true',
        help="Make the operation more talkative")
    cli.add_argument('-X', '--request', default="GET", metavar="<command>",
        choices=["DELETE", "GET", "HEAD",  "OPTIONS", "PATCH", "POST", "PUT"],
        help="Specify request command to use")
    cli.add_argument('-d', '--data', action='append',
        help="HTTP POST data; changes request command to 'POST'")
    
    # Additional, non-cURL options
    cli.add_argument('--debug', action='store_true', help="Enable debug output")
    cli.add_argument('--service', help="Name of service for AWS Signature")
    cli.add_argument('--region', help="AWS Region Name")
    
    # Parse args and make request
    args = cli.parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)
    m = re.search('([a-z0-9-]+)\.([a-z]{2}-[a-z]+-\d{1})\.', args.url)
    if args.service is None:
        if m:
            log.debug("Guessing service from url: %s", m.group(1))
            args.service = m.group(1)
        else:
            print("Couldn't determine service, option --service is needed")
            sys.exit(2)
    if args.region is None and m is not None:
        log.debug("Guessing region from url: %s", m.group(2))
        args.region = m.group(2)
    if args.data:
        args.request = 'POST'
        post_data = dict(map(lambda d: d.split('='), args.data))
    else:
        post_data = None
    if args.header:
        headers = dict(map(lambda h: map(lambda i:  i.strip(), h.split(':')), args.header))
    else:
        headers = None
    log.debug("Request: %s %s (service=%s, region=%s)", 
        args.request, args.url, args.service, args.region)
    r = requests.request(args.request, args.url, headers=headers, data=post_data,
        auth=AWSSigV4(args.service, region=args.region))
    
    # Output response
    log.debug("Response: %s %s", r.status_code, r.reason)
    if args.verbose: # Print to sys.stderr for Verbose output
        request_url = urlparse(r.request.url)
        print("> {} {} HTTP/{}".format(r.request.method, request_url.path, (r.raw.version / 10.0)),
            file=sys.stderr)
        req_headers = r.request.headers.copy()
        if 'Host' in req_headers: # Make sure Host header is first, if it exists
            print("> Host:", req_headers.pop('Host'), file=sys.stderr)
        for key, value in req_headers.items():
            print("> {}: {}".format(key, value), file=sys.stderr)
        print(">", file=sys.stderr) # Blank line at end of request headers
        for resp_line in parse_response_headers(r):
            print("<", resp_line, file=sys.stderr) # Each response header
    if args.include:
        for resp_line in parse_response_headers(r):
            print(resp_line)
        print() # Blank line to seperate headers from data
    try:
        json_data = r.json()
        if len(json_data) <= 1: # If only one item, print it's value
            print("".join(json_data.values()))
        else:
            print(json_data)
    except:
        print(r.text)
