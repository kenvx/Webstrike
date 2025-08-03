from setuptools import setup, find_packages
import os

# Read README file
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "Advanced Web Vulnerability Scanner"

setup(
    name="webstrike",
    version="1.0.0",
    description="Advanced Web Vulnerability Scanner",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="kenvx",
    author_email="me@kenn.live",
    url="https://github.com/kenvx/webstrike",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.1",
        "beautifulsoup4>=4.12.2",
        "requests>=2.31.0",
        "httpx>=0.25.2",
        "click>=8.1.7",
        "colorama>=0.4.6",
        "pdfkit>=1.0.0",
        "jinja2>=3.1.2",
        "tqdm>=4.66.1",
        "lxml>=4.9.3"
    ],
    entry_points={
        "console_scripts": [
            "webstrike=cli.webstrike_cli:main",
        ],
    },
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
)
