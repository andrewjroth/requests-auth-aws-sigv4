import urllib.parse

import pytest
from requests.models import Request
from mockito import when, spy2, unstub

import requests_auth_aws_sigv4


def test_sign_msg():
    result = b'-\x93\xcb\xc1\xbe\x16{\xcb\x167\xa4\xa2<\xbf\xf0\x1axx\xf0\xc5\x0e\xe83\x95N\xa5"\x1b\xb1\xb8\xc6('
    assert requests_auth_aws_sigv4.sign_msg(b'key', 'msg') == result


def test_init_provided():
    """ Test for provided credentials and region """
    aws_auth = requests_auth_aws_sigv4.AWSSigV4('test', region='test-region-1',
                                                aws_access_key_id="key_id",
                                                aws_secret_access_key="secret_key")
    assert aws_auth.aws_access_key_id == "key_id"
    assert aws_auth.aws_secret_access_key == "secret_key"
    assert aws_auth.aws_session_token is None
    assert aws_auth.region == "test-region-1"


def test_init_environment():
    """ Test for credentials and region from environment """
    spy2(requests_auth_aws_sigv4.os.environ.get)
    when(requests_auth_aws_sigv4.os.environ).get('AWS_ACCESS_KEY_ID').thenReturn("key_id")
    when(requests_auth_aws_sigv4.os.environ).get('AWS_SECRET_ACCESS_KEY').thenReturn("secret_key")
    when(requests_auth_aws_sigv4.os.environ).get('AWS_DEFAULT_REGION').thenReturn("test-region-1")
    aws_auth = requests_auth_aws_sigv4.AWSSigV4('test')
    assert aws_auth.aws_access_key_id == "key_id"
    assert aws_auth.aws_secret_access_key == "secret_key"
    assert aws_auth.aws_session_token is None
    assert aws_auth.region == "test-region-1"
    unstub()


def test_init_provided_with_session():
    """ Test for provided credentials and region """
    aws_auth = requests_auth_aws_sigv4.AWSSigV4('test', region='test-region-1',
                                                aws_access_key_id="key_id",
                                                aws_secret_access_key="secret_key",
                                                aws_session_token="token")
    assert aws_auth.aws_access_key_id == "key_id"
    assert aws_auth.aws_secret_access_key == "secret_key"
    assert aws_auth.aws_session_token == "token"
    assert aws_auth.region == "test-region-1"


def test_init_environment_with_session():
    """ Test for credentials and region from environment """
    spy2(requests_auth_aws_sigv4.os.environ.get)
    when(requests_auth_aws_sigv4.os.environ).get('AWS_ACCESS_KEY_ID').thenReturn("key_id")
    when(requests_auth_aws_sigv4.os.environ).get('AWS_SECRET_ACCESS_KEY').thenReturn("secret_key")
    when(requests_auth_aws_sigv4.os.environ).get('AWS_SESSION_TOKEN').thenReturn("token")
    when(requests_auth_aws_sigv4.os.environ).get('AWS_DEFAULT_REGION').thenReturn("test-region-1")
    aws_auth = requests_auth_aws_sigv4.AWSSigV4('test')
    assert aws_auth.aws_access_key_id == "key_id"
    assert aws_auth.aws_secret_access_key == "secret_key"
    assert aws_auth.aws_session_token == "token"
    assert aws_auth.region == "test-region-1"
    unstub()


def test_init_no_keys():
    """ Test for provided credentials and region """
    with pytest.raises(KeyError):
        aws_auth = requests_auth_aws_sigv4.AWSSigV4('test', region='test-region-1')


def test_init_no_region():
    """ Test for provided credentials and region """
    with pytest.raises(KeyError):
        aws_auth = requests_auth_aws_sigv4.AWSSigV4('test', aws_access_key_id="key_id",
                                                    aws_secret_access_key="secret_key")


def test_call_simple(frozentime):
    aws_auth = requests_auth_aws_sigv4.AWSSigV4('test', region='test-region-1',
                                                aws_access_key_id="key_id",
                                                aws_secret_access_key="secret_key",
                                                aws_session_token="token")
    req = Request('GET', "https://testhost/action?param=value")
    result = aws_auth(req.prepare())
    assert 'Authorization' in result.headers
    assert result.headers['Authorization'] == ", ".join([
        f"AWS4-HMAC-SHA256 Credential=key_id/{frozentime:%Y%m%d}/test-region-1/test/aws4_request",
        f"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
        f"Signature=817adf89563cdf0728f4e684c9ac9ead2cca25c4610e9bb3ddfebe8665ea72f2"
    ])
    assert result.headers['Host'] == "testhost"
    assert result.headers['Content-Type'] == "application/x-www-form-urlencoded; charset=utf-8; application/json"
    assert result.headers['User-Agent'] == 'python-requests/{} auth-aws-sigv4/{}'.format(
        requests_auth_aws_sigv4.requests_version, requests_auth_aws_sigv4.__version__)
    assert result.headers['X-AMZ-Date'] == frozentime.strftime('%Y%m%dT%H%M%SZ')
    assert result.headers['x-amz-security-token'] == "token"
    assert result.headers['x-amz-content-sha256'] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_call_no_payload_signing(frozentime):
    aws_auth = requests_auth_aws_sigv4.AWSSigV4('test', region='test-region-1',
                                                aws_access_key_id="key_id",
                                                aws_secret_access_key="secret_key",
                                                aws_session_token="token",
                                                payload_signing_enabled=False,
                                                )
    req = Request('GET', "https://testhost/action?param=value")
    result = aws_auth(req.prepare())
    assert 'Authorization' in result.headers
    assert result.headers['Authorization'] == ", ".join([
        f"AWS4-HMAC-SHA256 Credential=key_id/{frozentime:%Y%m%d}/test-region-1/test/aws4_request",
        f"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
        f"Signature=a5e20a7d27d57597b3776e04f087343407397fe2418e40cf85ffab051dd2cf1d"
    ])
    assert result.headers['x-amz-content-sha256'] == "UNSIGNED-PAYLOAD"


def test_uri_double_encoded_segment(frozentime):
    aws_auth = requests_auth_aws_sigv4.AWSSigV4('test', region='test-region-1',
                                                aws_access_key_id="key_id",
                                                aws_secret_access_key="secret_key",
                                                aws_session_token="token")
    segment = urllib.parse.quote('123 / abc', safe='')
    req = Request('GET', f'https://testhost/action/{segment}?param=value')
    result = aws_auth(req.prepare())
    assert 'Authorization' in result.headers
    assert result.headers['Authorization'] == ", ".join([
        f"AWS4-HMAC-SHA256 Credential=key_id/{frozentime:%Y%m%d}/test-region-1/test/aws4_request",
        f"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
        f"Signature=89a91408e96df9231d23bc51aa31916f1f72db68d6e96ba633c6652ba86fe2cd"
    ])
    assert result.headers['Host'] == "testhost"
    assert result.headers['Content-Type'] == "application/x-www-form-urlencoded; charset=utf-8; application/json"
    assert result.headers['User-Agent'] == 'python-requests/{} auth-aws-sigv4/{}'.format(
        requests_auth_aws_sigv4.requests_version, requests_auth_aws_sigv4.__version__)
    assert result.headers['X-AMZ-Date'] == frozentime.strftime('%Y%m%dT%H%M%SZ')
    assert result.headers['x-amz-security-token'] == "token"
    assert result.headers['x-amz-content-sha256'] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
