# requests-auth-aws-sigv4
Use AWS signature version 4 Authentication with the python requests module

This package provides an authentication class that can be used with the popular 
[requests](https://requests.readthedocs.io/en/master/) package to add the 
[AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
authentication information.

The signing code is inspired by the python example provided by AWS.

This package should support any/all AWS API's, including API Gateway API's (execute-api), 
Elasticsearch clusters, and others.  AWS Credentials may be pulled from the environment
in an easy and familiar way.
The signature is added as a header to the request.

## Installation

```
pip install requests-auth-aws-sigv4
```

## Usage

```python
import requests
from requests_auth_aws_sigv4 import AWSSigV4

r = requests.request('POST', 'https://sts.us-east-1.amazonaws.com', 
    data=dict(Version='2011-06-15', Action='GetCallerIdentity'), 
    auth=AWSSigV4('sts'))
print(r.text)
```

If **boto3** is available, it will attempt to use credentials that have been configured for the AWS CLI or SDK's,
as documented in [Boto3 User Guide: Credentials](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#credentials).
Otherwise, if **boto3** is not available, credentials must be provided using either environment variables or parameters.

#### Example using environment variables

Environment variable names are the same as documented for AWS CLI and SDK's.

```shell
export AWS_ACCESS_KEY_ID=MYACCESSKEY
export AWS_SECRET_ACCESS_KEY=THISISSECRET
export AWS_SESSION_TOKEN=THISISWHERETHESUPERLONGTOKENGOES
```

```python
import requests
from requests_auth_aws_sigv4 import AWSSigV4

aws_auth = AWSSigV4('ec2') # If not provided, check for AWS Credentials from Environment Variables

r = requests.request('GET', 'https://ec2.us-east-1.amazonaws.com?Version=2016-11-15&Action=DescribeRegions',
    auth=aws_auth)
print(r.text)
```

#### Example using parameters

Passing credentials as parameters overrides all other possible sources. 

```python
import requests
from requests_auth_aws_sigv4 import AWSSigV4

aws_auth = AWSSigV4('ec2',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
)

r = requests.request('GET', 'https://ec2.us-east-1.amazonaws.com?Version=2016-11-15&Action=DescribeRegions',
    auth=aws_auth)
print(r.text)
```

### Usage with Elasticsearch Client (elasticsearch-py)

```python
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_auth_aws_sigv4 import AWSSigV4

es_host = 'search-service-foobar.us-east-1.es.amazonaws.com'
aws_auth = AWSSigV4('es')

# use the requests connection_class and pass in our custom auth class
es_client = Elasticsearch(host=es_host,
                          port=80,
                          connection_class=RequestsHttpConnection,
                          http_auth=aws_auth)
es_client.info()
```

### Debug Logging

All log messages are at the module level.

```python
import logging
logging.basicConfig() # Setup basic logging to stdout
log = logging.getLogger('requests_auth_aws_sigv4')
log.setLevel(logging.DEBUG)
```

## Command Line Usage

The module can be run from the command line in a way that is similar to how cURL works.

```shell
$ python3 -m requests_auth_aws_sigv4 https://sampleapi.execute-api.us-east-1.amazonaws.com/test/ -v
> GET /test/ HTTP/1.1
> Host: sampleapi.execute-api.us-east-1.amazonaws.com
> User-Agent: python-requests/2.23.0 auth-aws-sigv4/0.2
> Accept-Encoding: gzip, deflate
> Accept: */*
> Connection: keep-alive
> X-AMZ-Date: 20200513T180549Z
> Authorization: AWS4-HMAC-SHA256 Credential=AKIASAMPLEKEYID/20200513/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=EXAMPLESIGNATUREISHERE
>
< HTTP/1.1 200 OK
< Connection: keep-alive
< Content-Length: 25
< Content-Type: application/json
< Date: Wed, 13 May 2020 18:05:49 GMT
< Server: Server
< x-amz-apigw-id: MeExampleiMFs99=
< x-amzn-RequestId: 7example-7b7b-4343-9a9a-9bbexampleaf
hello
```

## Temporary Security Credentials

Credentials issued from [AWS STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
to grant temporary access can be used normally.  Set the token by passing the `aws_session_token` parameter, 
setting the `AWS_SESSION_TOKEN` environment variable, or configure the credential for boto3 as normal.

## Using boto3 (or botocore) for AWS Credentials

The packages **boto3** and **botocore** are not requirements to use this module.  
As mentioned above, if **boto3** is available, a boto3.Session will be created to attempt to get credentials
and configure the default region.  This will happen automatically if credentials are not provided as parameters.

