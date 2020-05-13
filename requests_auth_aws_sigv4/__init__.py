#!/bin/env python3
from __future__ import print_function
import os
import datetime
import hashlib
import hmac
import logging
from collections import OrderedDict
import requests
from requests.auth import AuthBase
from requests.compat import urlencode, quote, urlparse


USE_BOTO3 = False
try:
    import boto3
    USE_BOTO3 = True
except ImportError:
    pass


log = logging.getLogger('aws-sigv4')


def sign_msg(key, msg):
    ''' Sign message using key '''
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


class AWSSigV4(AuthBase):
    
    def __init__(self, service, **kwargs):
        ''' Create authentication mechanism
        
        :param service: AWS Service identifier, for example `ec2`.  This is required.
        :param region:  AWS Region, for example `us-east-1`.  If not provided, it will be set using
            the environment variables `AWS_DEFAULT_REGION` or using boto3, if available.
        :param session: If boto3 is available, will attempt to get credentials using boto3, 
            unless passed explicitly.  If using boto3, the provided session will be used or a new 
            session will be created.
        
        '''
        # Set Service
        self.service = service
        if USE_BOTO3:
            # Setup Session
            if 'session' in kwargs:
                if type(kwargs['session']) == boto3.Session:
                    session = kwargs['session']
                else:
                    raise ValueError("Session must be boto3.Session, {} invalid, ".format(type(kwargs['session'])))
            else:
                session = boto3.Session()
            log.debug("Using boto3 session: %s", session)
        
        # First, get credentials passed explicitly
        self.aws_access_key_id = kwargs.get('aws_access_key_id')
        self.aws_secret_access_key = kwargs.get('aws_secret_access_key')
        self.aws_session_token = kwargs.get('aws_session_token')
        # Next, try environment variables or use boto3
        if self.aws_access_key_id is None or self.aws_secret_access_key is None:
            if USE_BOTO3:
                cred = session.get_credentials()
                log.debug("Got credential from boto3 session")
                self.aws_access_key_id = cred.access_key
                self.aws_secret_access_key = cred.secret_key
                self.aws_session_token = cred.token
            else:
                log.debug("Checking environment for credentials")
                self.aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
                self.aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
                self.aws_session_token = os.environ.get('AWS_SESSION_TOKEN') or os.environ.get('AWS_SECURITY_TOKEN')
        # Last, fail if still not found
        if self.aws_access_key_id is None or self.aws_secret_access_key is None:
            raise KeyError("AWS Access Key ID and Secret Access Key are required")
        
        # Get Region passed explicitly
        self.region = kwargs.get('region')
        # Next, try environment variables or use boto3
        if self.region is None:
            if USE_BOTO3:
                self.region = session.region_name
                log.debug("Got region from boto3 session")
            else:
                log.debug("Checking environment for region")
                self.region = os.environ.get('AWS_DEFAULT_REGION')
        # Last, fail if not found
        if self.region is None:
            raise KeyError("Region is required")
    
    
    def __call__(self, r):
        ''' Called to add authentication information to request
        
        :param r: `requests.models.PreparedRequest` object to modify
        
        :returns: `requests.models.PreparedRequest`, modified to add authentication
        
        '''
        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        self.amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = t.strftime('%Y%m%d')
        log.debug("Starting authentication with amzdate=%s", self.amzdate)

        # Parse request to get URL parts
        p = urlparse(r.url)
        log.debug("Request URL: %s", p)
        host = p.hostname
        uri = p.path
        if len(p.query) > 0:
            qs = dict(map(lambda i: i.split('='), p.query.split('&')))
        else:
            qs = dict()
        
        ## Task 1: Create Cononical Request
        ## Ref: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        # Query string values must be URL-encoded (space=%20) and be sorted by name.
        canonical_querystring = "&".join(map(lambda p: "=".join(p), sorted(qs.items())))
        
        # Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.
        headers_to_sign = {'host': host, 'x-amz-date': self.amzdate}
        if self.aws_session_token is not None:
            headers_to_sign['x-amz-security-token'] = self.aws_session_token
        ordered_headers = OrderedDict(sorted(headers_to_sign.items(), key=lambda t: t[0]))
        canonical_headers = ''.join(map(lambda h: ":".join(h) + '\n', ordered_headers.items()))
        signed_headers = ';'.join(ordered_headers.keys())
        
        # Create payload hash (hash of the request body content).
        if r.method == 'GET':
            payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
        else:
            payload_hash = hashlib.sha256((r.body).encode('utf-8')).hexdigest()
        
        # Combine elements to create canonical request
        canonical_request = '\n'.join([r.method, uri, canonical_querystring, 
            canonical_headers, signed_headers, payload_hash])
        log.debug("Canonical Request: '%s'", canonical_request)
        
        ## Task 2: Create string to sign
        credential_scope = '/'.join([self.datestamp, self.region, self.service, 'aws4_request'])
        string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', self.amzdate, 
            credential_scope, hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])
        log.debug("String-to-Sign: '%s'", string_to_sign)
        
        ## Task 3: Calculate Signature
        kDate = sign_msg(('AWS4' + self.aws_secret_access_key).encode('utf-8'), self.datestamp)
        kRegion = sign_msg(kDate, self.region)
        kService = sign_msg(kRegion, self.service)
        kSigning = sign_msg(kService, 'aws4_request')
        signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        ## Task 4: Add signing information to request
        authorization_header = "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
            self.aws_access_key_id, credential_scope, signed_headers, signature)
        r.headers.update({
            'Host': host, 
            'X-AMZ-Date': self.amzdate,
            'Authorization': authorization_header, 
        })
        return r


def parse_response_headers(resp):
    ''' Parse response to yield formatted header lines '''
    yield "HTTP/{} {} {}".format((resp.raw.version / 10.0), resp.status_code, resp.reason)
    for name, value in OrderedDict(sorted(resp.headers.items(), key=lambda t: t[0])).items():
        yield "{}: {}".format(name, value)


if __name__ == '__main__':
    import sys
    import argparse
    import re
    
    logging.basicConfig()
    
    cli = argparse.ArgumentParser(
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
        help="HTTP POST data")
    
    # Additional, non-cURL options
    cli.add_argument('--debug', action='store_true', help="Enable debug output")
    cli.add_argument('--service', help="Name of service for AWS Signature")
    cli.add_argument('--region', help="AWS Region Name")
    
    # Parse args and make request
    args = cli.parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)
    if args.service is None:
        m = re.search('([a-z0-9-]+)\.[a-z]{2}-[a-z]+-\d{1}', args.url)
        if m:
            args.service = m.group(1)
        else:
            print("Couldn't determine service, option --service is needed")
            sys.exit(2)
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
