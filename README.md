# SBOM2DOC

SBOM2DOC documents and summarises the components within an SBOM (Software Bill of Materials). SBOMS are supported in a number of formats including
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).

## Installation

To install use the following command:

`pip install sbom2doc`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

## Usage

```
usage: sbom2doc [-h] [-i INPUT_FILE] [--debug] [--include-license] [-f {console,excel,html,json,markdown,pdf}] [-o OUTPUT_FILE] [-V]

SBOM2doc generates documentation for a SBOM.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

Input:
  -i INPUT_FILE, --input-file INPUT_FILE
                        Name of SBOM file

Output:
  --debug               add debug information
  --include-license     add license text
  -f {console,excel,html,json,markdown,pdf}, --format {console,excel,html,json,markdown,pdf}
                        Output format (default: output to console)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output filename (default: output to stdout)
```
					
## Operation

The `--input-file` option is used to specify the SBOM to be processed. The format of the SBOM is determined according to
the following filename conventions.

| SBOM      | Format    | Filename extension |
| --------- | --------- |--------------------|
| SPDX      | TagValue  | .spdx              |
| SPDX      | JSON      | .spdx.json         |
| SPDX      | YAML      | .spdx.yaml         |
| SPDX      | YAML      | .spdx.yml          |
| CycloneDX | JSON      | .json              |

The `--output-file` option is used to control the destination of the output generated by the tool. The
default is to report to the console, but it can also be stored in a file (specified using `--output-file` option).

Selecting the `html` format option will create a HTML body document which uses the [Bootstrap](https://getbootstrap.com/) framework.

The `--include-license` option is used to indicate if the text for the licenses is to be included in the output.

## Example

Given the following SBOM (flask.spdx)

```bash
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: Python-flask
DocumentNamespace: http://spdx.org/spdxdocs/Python-flask-f95bd9a2-1442-4631-9b13-870422204ed4
LicenseListVersion: 3.21
Creator: Tool: sbom4python-0.10.0
Created: 2023-08-17T20:28:31Z
CreatorComment: <text>This document has been automatically generated.</text>
##### 

PackageName: flask
SPDXID: SPDXRef-Package-1-flask
PackageVersion: 2.2.2
PrimaryPackagePurpose: APPLICATION
PackageSupplier: Person: Armin Ronacher (armin.ronacher@active-4.com)
PackageDownloadLocation: https://pypi.org/project/Flask/2.2.2
FilesAnalyzed: false
PackageLicenseDeclared: BSD-3-Clause
PackageLicenseConcluded: BSD-3-Clause
PackageCopyrightText: NOASSERTION
PackageSummary: <text>A simple framework for building complex web applications.</text>
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/flask@2.2.2
ExternalRef: SECURITY cpe23Type cpe:2.3:a:armin_ronacher:flask:2.2.2:*:*:*:*:*:*:*
##### 

PackageName: click
SPDXID: SPDXRef-Package-2-click
PackageVersion: 8.0.3
PrimaryPackagePurpose: LIBRARY
PackageSupplier: Person: Armin Ronacher (armin.ronacher@active-4.com)
PackageDownloadLocation: https://pypi.org/project/click/8.0.3
FilesAnalyzed: false
PackageLicenseDeclared: BSD-3-Clause
PackageLicenseConcluded: BSD-3-Clause
PackageCopyrightText: NOASSERTION
PackageSummary: <text>Composable command line interface toolkit</text>
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/click@8.0.3
ExternalRef: SECURITY cpe23Type cpe:2.3:a:armin_ronacher:click:8.0.3:*:*:*:*:*:*:*
##### 

PackageName: itsdangerous
SPDXID: SPDXRef-Package-3-itsdangerous
PackageVersion: 2.1.2
PrimaryPackagePurpose: LIBRARY
PackageSupplier: Person: Armin Ronacher (armin.ronacher@active-4.com)
PackageDownloadLocation: https://pypi.org/project/itsdangerous/2.1.2
FilesAnalyzed: false
PackageLicenseDeclared: BSD-3-Clause
PackageLicenseConcluded: BSD-3-Clause
PackageCopyrightText: NOASSERTION
PackageSummary: <text>Safely pass data to untrusted environments and back.</text>
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/itsdangerous@2.1.2
ExternalRef: SECURITY cpe23Type cpe:2.3:a:armin_ronacher:itsdangerous:2.1.2:*:*:*:*:*:*:*
##### 

PackageName: jinja2
SPDXID: SPDXRef-Package-4-jinja2
PackageVersion: 3.0.2
PrimaryPackagePurpose: LIBRARY
PackageSupplier: Person: Armin Ronacher (armin.ronacher@active-4.com)
PackageDownloadLocation: https://pypi.org/project/Jinja2/3.0.2
FilesAnalyzed: false
PackageLicenseDeclared: BSD-3-Clause
PackageLicenseConcluded: BSD-3-Clause
PackageCopyrightText: NOASSERTION
PackageSummary: <text>A very fast and expressive template engine.</text>
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/jinja2@3.0.2
ExternalRef: SECURITY cpe23Type cpe:2.3:a:armin_ronacher:jinja2:3.0.2:*:*:*:*:*:*:*
##### 

PackageName: markupsafe
SPDXID: SPDXRef-Package-5-markupsafe
PackageVersion: 2.1.1
PrimaryPackagePurpose: LIBRARY
PackageSupplier: Person: Armin Ronacher (armin.ronacher@active-4.com)
PackageDownloadLocation: https://pypi.org/project/MarkupSafe/2.1.1
FilesAnalyzed: false
PackageLicenseDeclared: BSD-3-Clause
PackageLicenseConcluded: BSD-3-Clause
PackageCopyrightText: NOASSERTION
PackageSummary: <text>Safely add untrusted strings to HTML/XML markup.</text>
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/markupsafe@2.1.1
ExternalRef: SECURITY cpe23Type cpe:2.3:a:armin_ronacher:markupsafe:2.1.1:*:*:*:*:*:*:*
##### 

PackageName: werkzeug
SPDXID: SPDXRef-Package-6-werkzeug
PackageVersion: 2.2.2
PrimaryPackagePurpose: LIBRARY
PackageSupplier: Person: Armin Ronacher (armin.ronacher@active-4.com)
PackageDownloadLocation: https://pypi.org/project/Werkzeug/2.2.2
FilesAnalyzed: false
PackageLicenseDeclared: BSD-3-Clause
PackageLicenseConcluded: BSD-3-Clause
PackageCopyrightText: NOASSERTION
PackageSummary: <text>The comprehensive WSGI web application library.</text>
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/werkzeug@2.2.2
ExternalRef: SECURITY cpe23Type cpe:2.3:a:armin_ronacher:werkzeug:2.2.2:*:*:*:*:*:*:*
##### 

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-1-flask
Relationship: SPDXRef-Package-1-flask DEPENDS_ON SPDXRef-Package-2-click
Relationship: SPDXRef-Package-1-flask DEPENDS_ON SPDXRef-Package-3-itsdangerous
Relationship: SPDXRef-Package-1-flask DEPENDS_ON SPDXRef-Package-4-jinja2
Relationship: SPDXRef-Package-1-flask DEPENDS_ON SPDXRef-Package-6-werkzeug
Relationship: SPDXRef-Package-4-jinja2 DEPENDS_ON SPDXRef-Package-5-markupsafe
Relationship: SPDXRef-Package-6-werkzeug DEPENDS_ON SPDXRef-Package-5-markupsafe
```

The following commands will generate a summary of the contents of the SBOM to the console.

```bash
sbom2doc --input flask.spdx 

╭──────────────╮
│ SBOM Summary │
╰──────────────╯
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Item            ┃ Details                                                           ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ SBOM File       │ flask.spdx                                                        │
│ SBOM Type       │ spdx                                                              │
│ Version         │ SPDX-2.3                                                          │
│ Name            │ Python-flask                                                      │
│ Creator         │ Tool:sbom4python-0.10.0                                           │
│ Created         │ 2023-08-17T20:28:31Z                                              │
│ Files           │ 0                                                                 │
│ Packages        │ 6                                                                 │
│ Relationships   │ 7                                                                 │
│ Services        │ 0                                                                 │
│ Vulnerabilities │ 0                                                                 │
└─────────────────┴───────────────────────────────────────────────────────────────────┘
╭─────────────────╮
│ Package Summary │
╰─────────────────╯
┏━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Name         ┃ Version ┃ Type        ┃ Supplier                                     ┃ License      ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ flask        │ 2.2.2   │ APPLICATION │ Armin Ronacher (armin.ronacher@active-4.com) │ BSD-3-Clause │
│ click        │ 8.0.3   │ LIBRARY     │ Armin Ronacher (armin.ronacher@active-4.com) │ BSD-3-Clause │
│ itsdangerous │ 2.1.2   │ LIBRARY     │ Armin Ronacher (armin.ronacher@active-4.com) │ BSD-3-Clause │
│ jinja2       │ 3.0.2   │ LIBRARY     │ Armin Ronacher (armin.ronacher@active-4.com) │ BSD-3-Clause │
│ markupsafe   │ 2.1.1   │ LIBRARY     │ Armin Ronacher (armin.ronacher@active-4.com) │ BSD-3-Clause │
│ werkzeug     │ 2.2.2   │ LIBRARY     │ Armin Ronacher (armin.ronacher@active-4.com) │ BSD-3-Clause │
└──────────────┴─────────┴─────────────┴──────────────────────────────────────────────┴──────────────┘


┏━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Name         ┃ Version ┃ Ecosystem ┃ Download                                    ┃ Copyright   ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ flask        │ 2.2.2   │ pypi      │ https://pypi.org/project/Flask/2.2.2        │ NOASSERTION │
│ click        │ 8.0.3   │ pypi      │ https://pypi.org/project/click/8.0.3        │ NOASSERTION │
│ itsdangerous │ 2.1.2   │ pypi      │ https://pypi.org/project/itsdangerous/2.1.2 │ NOASSERTION │
│ jinja2       │ 3.0.2   │ pypi      │ https://pypi.org/project/Jinja2/3.0.2       │ NOASSERTION │
│ markupsafe   │ 2.1.1   │ pypi      │ https://pypi.org/project/MarkupSafe/2.1.1   │ NOASSERTION │
│ werkzeug     │ 2.2.2   │ pypi      │ https://pypi.org/project/Werkzeug/2.2.2     │ NOASSERTION │
└──────────────┴─────────┴───────────┴─────────────────────────────────────────────┴─────────────┘


┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Name         ┃ PURL                        ┃ CPE                                                       ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ flask        │ pkg:pypi/flask@2.2.2        │ cpe:2.3:a:armin_ronacher:flask:2.2.2:*:*:*:*:*:*:*        │
│ click        │ pkg:pypi/click@8.0.3        │ cpe:2.3:a:armin_ronacher:click:8.0.3:*:*:*:*:*:*:*        │
│ itsdangerous │ pkg:pypi/itsdangerous@2.1.2 │ cpe:2.3:a:armin_ronacher:itsdangerous:2.1.2:*:*:*:*:*:*:* │
│ jinja2       │ pkg:pypi/jinja2@3.0.2       │ cpe:2.3:a:armin_ronacher:jinja2:3.0.2:*:*:*:*:*:*:*       │
│ markupsafe   │ pkg:pypi/markupsafe@2.1.1   │ cpe:2.3:a:armin_ronacher:markupsafe:2.1.1:*:*:*:*:*:*:*   │
│ werkzeug     │ pkg:pypi/werkzeug@2.2.2     │ cpe:2.3:a:armin_ronacher:werkzeug:2.2.2:*:*:*:*:*:*:*     │
└──────────────┴─────────────────────────────┴───────────────────────────────────────────────────────────┘
╭────────────────────────╮
│ Component Type Summary │
╰────────────────────────╯
┏━━━━━━━━━━━━━┳━━━━━━━┓
┃ Type        ┃ Count ┃
┡━━━━━━━━━━━━━╇━━━━━━━┩
│ APPLICATION │ 1     │
│ LIBRARY     │ 5     │
└─────────────┴───────┘
╭─────────────────╮
│ License Summary │
╰─────────────────╯
┏━━━━━━━━━━━━━━┳━━━━━━━┓
┃ License      ┃ Count ┃
┡━━━━━━━━━━━━━━╇━━━━━━━┩
│ BSD-3-Clause │ 6     │
└──────────────┴───────┘
╭──────────────────╮
│ Supplier Summary │
╰──────────────────╯
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Supplier                                     ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Armin Ronacher (armin.ronacher@active-4.com) │ 6     │
└──────────────────────────────────────────────┴───────┘
╭──────────────╮
│ NTIA Summary │
╰──────────────╯
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Element                            ┃ Status ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ All file information provided?     │ True   │
│ All package information provided?  │ True   │
│ Creator identified?                │ True   │
│ Creation time identified?          │ True   │
│ Dependency relationships provided? │ True   │
└────────────────────────────────────┴────────┘

NTIA conformant True                                                
```

## Licence

Licenced under the Apache 2.0 Licence.

## Limitations

The tool has the following limitations

- SBOMs in RDF (SPDX) and XML (SPDX and CycloneDX) formats are not supported.

- Invalid SBOMs will result in unpredictable results.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.