import pytest
import requests
from mockito import mock, when, verify, unstub

from requests_auth_aws_sigv4 import __main__ as main


def test_parse_response_headers():
    response = mock({
        'raw': mock({'version': 11}),  # HTTP/1.1
        'status_code': 200,
        'reason': "OK",
        'headers': {
            'Alpha': "One",
            'Charlie': "Three",
            'Beta': "Two",
        }
    }, spec=requests.Response)
    result = list(main.parse_response_headers(response))
    assert result[0] == 'HTTP/1.1 200 OK'
    assert result[1] == 'Alpha: One'
    assert result[2] == 'Beta: Two'
    assert result[3] == 'Charlie: Three'


@pytest.fixture
def mock_auth():
    def _make(method, url, json_data=None, text_data=None):
        mock_request = mock({
            'url': url,
            'method': method,
            'headers': {}
        }, spec=requests.PreparedRequest)

        def _json():
            if json_data is not None:
                return json_data
            raise ValueError
        mock_response = mock({
            'request': mock_request,
            'raw': mock({'version': 11}),  # HTTP/1.1
            'status_code': 200,
            'reason': "OK",
            'headers': {},
            'json': _json,
            'text': text_data
        }, spec=requests.Response)
        mock_AWSSigV4 = mock(main.AWSSigV4)
        when(mock_AWSSigV4).__call__(mock_request).thenReturn(mock_request)
        when(main).AWSSigV4("service", region="tt-region-1", payload_signing_enabled=True).thenReturn(mock_AWSSigV4)
        when(requests).request(...).thenReturn(mock_response)
        return mock_response
    yield _make
    unstub()


def test_run(capfd, mock_auth):
    url = "https://service.tt-region-1.example.com/path?query=string"
    mock_resp = mock_auth("GET", url, {"result": "data"})
    main.run([url])
    verify(mock_resp).json()
    captured = capfd.readouterr()
    assert captured.out == "data\n"


def test_run_include_headers(capfd, mock_auth):
    url = "https://service.tt-region-1.example.com/path?query=string"
    mock_resp = mock_auth("GET", url, {"result": "data"})
    main.run(["-i", url])
    verify(mock_resp).json()
    captured = capfd.readouterr()
    assert captured.out.splitlines() == ["HTTP/1.1 200 OK", "", "data"]


def test_run_verbose(capfd, mock_auth):
    url = "https://service.tt-region-1.example.com/path?query=string"
    mock_resp = mock_auth("GET", url, {"result": "data"})
    main.run(["-v", url])
    verify(mock_resp).json()
    captured = capfd.readouterr()
    assert captured.err.splitlines() == ["> GET /path HTTP/1.1", ">", "< HTTP/1.1 200 OK"]
    assert captured.out == "data\n"
