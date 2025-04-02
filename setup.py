from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="securepulse",
    version="0.1.0",
    author="Open Door MSP",
    author_email="info@opendoormsp.com",
    description="Comprehensive security monitoring and compliance framework for Microsoft 365",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tier3tech/SecurePulse",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
)