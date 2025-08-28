#!/usr/bin/env python
"""
Setup script for anysecret-io
"""
import os
from setuptools import setup, find_packages

# Get the directory containing setup.py
here = os.path.abspath(os.path.dirname(__file__))

# Read the README file
def read_readme():
    try:
        with open(os.path.join(here, "README.md"), "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "Universal secret manager for Python applications with multi-cloud support"

# Read requirements
def read_requirements():
    try:
        with open(os.path.join(here, "requirements.txt"), "r") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return ["cryptography>=3.4.0", "pydantic>=2.0.0"]

setup(
    name="anysecret-io",
    version="0.1.0",
    author="AnySecret.io Team",
    author_email="hello@anysecret.io",
    description="Universal secret manager for Python applications with multi-cloud support",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://anysecret.io/",
    project_urls={
        "Bug Tracker": "https://github.com/anysecret-io/anysecret-lib/issues",
        "Documentation": "https://github.com/anysecret-io/anysecret-lib/docs/quickstart.md",
        "Source Code": "https://github.com/anysecret-io/anysecret-lib",
    },
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3 :: Only",
        "Framework :: AsyncIO",
        "Framework :: FastAPI",
    ],
    keywords="secrets, secret-management, cloud, aws, gcp, azure, vault, fastapi, async",
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "gcp": [
            "google-cloud-secret-manager>=2.16.0",
            "google-auth>=2.16.0",
        ],
        "aws": [
            "boto3>=1.26.0",
            "botocore>=1.29.0",
        ],
        "azure": [
            "azure-keyvault-secrets>=4.7.0",
            "azure-identity>=1.12.0",
        ],
        "vault": [
            "hvac>=1.0.0",
        ],
        "all": [
            "google-cloud-secret-manager>=2.16.0",
            "google-auth>=2.16.0",
            "boto3>=1.26.0",
            "botocore>=1.29.0",
            "azure-keyvault-secrets>=4.7.0",
            "azure-identity>=1.12.0",
            "hvac>=1.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "pre-commit>=2.20.0",
            "twine>=4.0.0",
            "build>=0.8.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "anysecret=anysecret.cli.main:app",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)