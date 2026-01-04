#!/usr/bin/env python3
"""Setup script for PUPMAS"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="pupmas",
    version="1.0.0",
    author="PUPMAS Team",
    author_email="security@pupmas.io",
    description="Advanced Cybersecurity Operations and Intelligence Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/pupmas",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "pupmas=pupmas:main",
        ],
    },
    include_package_data=True,
    package_data={
        "pupmas": [
            "config/*.yaml",
            "config/*.json",
            "data/templates/*",
            "data/schemas/*",
        ],
    },
    zip_safe=False,
    keywords="cybersecurity pentesting mitre-attack cve siem ctf security-tools",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/pupmas/issues",
        "Source": "https://github.com/yourusername/pupmas",
        "Documentation": "https://pupmas.readthedocs.io",
    },
)
