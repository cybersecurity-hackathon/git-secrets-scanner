"""
GitSentinel — Automated Secrets Detection & Credential Rotation for Git Repositories.

Install:
    pip install -e .

Usage after install:
    gitsentinel scan ./my-repo
    gitsentinel validate ./my-repo
    gitsentinel rotate ./my-repo --auto
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="gitsentinel",
    version="1.0.0",
    description="Automated secrets detection & credential rotation for Git repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Team GitSentinel",
    url="https://github.com/cybersecurity-hackathon/git-secrets-scanner",
    packages=find_packages(exclude=["tests", "test_repo"]),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "gitsentinel=scanner.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords="security secrets git scanner detection rotation aws credentials",
)
