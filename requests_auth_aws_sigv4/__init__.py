#!/bin/env python3
from __future__ import print_function
import os
import datetime
import hashlib
import hmac
import logging
from collections import OrderedDict
from requests import __version__ as requests_version
from requests.auth import AuthBase
from requests.compat import urlencode, quote, urlparse


USE_BOTO3 = False
try:
    import boto3
    USE_BOTO3 = True
except ImportError:
    pass

__version__ = '0.7'


log = logging.getLogger(__name__)


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
        
        # Setup Headers
        # r.headers is type `requests.structures.CaseInsensitiveDict`
        if 'Host' not in r.headers:
            r.headers['Host'] = host
        if 'Content-Type' not in r.headers:
            r.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
        if 'User-Agent' not in r.headers:
            r.headers['User-Agent'] = 'python-requests/{} auth-aws-sigv4/{}'.format(
                            requests_version, __version__)
        r.headers['X-AMZ-Date'] = self.amzdate
        if self.aws_session_token is not None:
            r.headers['x-amz-security-token'] = self.aws_session_token

        ## Task 1: Create Cononical Request
        ## Ref: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        # Query string values must be URL-encoded (space=%20) and be sorted by name.
        canonical_querystring = "&".join(map(lambda p: "=".join(p), sorted(qs.items())))
        
        # Create payload hash (hash of the request body content).
        if r.method == 'GET':
            payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
        else:
            if r.body:
                if isinstance(r.body, bytes):
                    log.debug("Request Body: <bytes> %s", r.body)
                    payload_hash = hashlib.sha256(r.body).hexdigest()
                else:
                    log.debug("Request Body: <str> %s", r.body)
                    payload_hash = hashlib.sha256(r.body.encode('utf-8')).hexdigest()
            else:
                log.debug("Request Body is empty")
                payload_hash = hashlib.sha256(b'').hexdigest()
        r.headers['x-amz-content-sha256'] = payload_hash
        
        # Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.
        headers_to_sign = sorted(filter(lambda h: h.startswith('x-amz-') or h == 'host',
            map(lambda H: H.lower(), r.headers.keys())))
        canonical_headers = ''.join(map(lambda h: ":".join((h, r.headers[h])) + '\n', headers_to_sign))
        signed_headers = ';'.join(headers_to_sign)
        
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
        log.debug("Signature: %s", signature)
        
        ## Task 4: Add signing information to request
        r.headers['Authorization'] = "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
            self.aws_access_key_id, credential_scope, signed_headers, signature)
        log.debug("Returning Request: <PreparedRequest method=%s, url=%s, headers=%s, SignedHeaders=%s, Signature=%s", 
            r.method, r.url, r.headers, signed_headers, signature)
        return r

