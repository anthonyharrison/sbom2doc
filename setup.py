# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from setuptools import find_packages, setup

from sbom2doc.version import VERSION

with open("README.md", encoding="utf-8") as f:
    readme = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().split("\n")

setup_kwargs = dict(
    name='sbom2doc',
    version=VERSION,
    description='SBOM documentation tool',
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/anthonyharrison/sbom2doc",
    author='Anthony Harrison',
    author_email='anthony.p.harrison@gmail.com',
    maintainer='Anthony Harrison',
    maintainer_email='anthony.p.harrison@gmail.com',
    license='Apache-2.0',
    keywords=["documentation", "tools", "SBOM", "DevSecOps", "SPDX", "CycloneDX"],
    install_requires=requirements,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    python_requires=">=3.7",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sbom2doc = sbom2doc.cli:main",
        ],
    },
)

setup(**setup_kwargs)
