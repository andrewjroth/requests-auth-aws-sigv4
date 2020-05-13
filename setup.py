import setuptools

with open("README.md", "r") as f:
    long_desc = f.read()

setuptools.setup(
    name="requests-auth-aws-sigv4",
    version="0.1",
    author="Andrew Roth",
    author_email="andrew@andrewjroth.com",
    description="AWS SigV4 Authentication with the python requests module",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/andrewjroth/requests-auth-aws-sigv4",
    packages=setuptools.find_packages(),
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
