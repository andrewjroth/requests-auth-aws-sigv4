import setuptools

from requests_auth_aws_sigv4 import __version__

with open("README.md", "r") as f:
    long_desc = f.read()

setuptools.setup(
    name="requests-auth-aws-sigv4",
    version=__version__,
    author="Andrew Roth",
    author_email="andrew@andrewjroth.com",
    description="AWS SigV4 Authentication with the python requests module",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/andrewjroth/requests-auth-aws-sigv4",
    packages=['requests_auth_aws_sigv4'],
    install_requires=['requests'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=2.7, >=3.6",
)
