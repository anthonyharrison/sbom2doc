# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4sbom.data.document import SBOMDocument
from lib4sbom.output import SBOMOutput


def generate_markdown(sbom_parser, filename, outfile):
    # Get constituent components of the SBOM
    packages = sbom_parser.get_packages()
    files = sbom_parser.get_files()
    relationships = sbom_parser.get_relationships()
    document = SBOMDocument()
    document.copy_document(sbom_parser.get_document())

    markdown_data = []

    markdown_data.append("\n# SBOM Summary\n")
    markdown_data.append("| Item | Details |")
    markdown_data.append("| ------------ | ------------ |")
    markdown_data.append("| SBOM File |" + filename + "|")
    markdown_data.append("| SBOM Type |" + document.get_type() + "|")
    markdown_data.append("| Version |" + document.get_version() + "|")
    markdown_data.append("| Name |" + document.get_name() + "|")
    creator_identified = False
    for c in document.get_creator():
        creator_identified = True
        markdown_data.append("| Creator |" + f"{c[0]}:{c[1]}" + "|")
    markdown_data.append("| Created |" + document.get_created() + "|")
    markdown_data.append("| Files |" + str(len(files)) + "|")
    markdown_data.append("| Packages |" + str(len(packages)) + "|")
    markdown_data.append("| Relationships |" + str(len(relationships)) + "|")
    creation_time = document.get_created() is not None

    files_valid = True
    packages_valid = True
    relationships_valid = len(relationships) > 0
    sbom_licenses = []
    if len(files) > 0:

        markdown_data.append("\n# File Summary\n")
        markdown_data.append("| Name | Type | License | Copyright |")
        markdown_data.append(
            "| ------------ | ------------ |------------ |------------ |"
        )
        for file in files:
            # Minimum elements are ID, Name
            id = file.get("id", None)
            name = file.get("name", None)
            file_type = ", ".join(t for t in file.get("filetype", None))
            license = file.get("licenseconcluded", None)
            copyright = file.get("copyrighttext", "-")
            if license is not None:
                sbom_licenses.append(license)
            else:
                license = "NOT KNOWN"
            markdown_data.append(
                "| "
                + name
                + " | "
                + file_type
                + " | "
                + license
                + " | "
                + copyright
                + " |"
            )
            if id is None or name is None:
                files_valid = False

    if len(packages) > 0:

        markdown_data.append("\n# Package Summary\n")
        markdown_data.append("| Name | Version | Supplier | License |")
        markdown_data.append(
            "| ------------ | ------------ |------------ |------------ |"
        )
        for package in packages:
            # Minimum elements are ID, Name, Version, Supplier
            id = package.get("id", None)
            name = package.get("name", None)
            version = package.get("version", None)
            supplier = package.get("supplier", None)
            license = package.get("licenseconcluded", None)
            if license is not None:
                sbom_licenses.append(license)
            else:
                license = "NOT KNOWN"
            markdown_data.append(
                "| "
                + name
                + " | "
                + version
                + " | "
                + supplier
                + " | "
                + license
                + " |"
            )
            if (
                id is None
                or name is None
                or version is None
                or supplier is None
                or supplier == "NOASSERTION"
            ):
                packages_valid = False

    markdown_data.append("\n# License Summary\n")
    markdown_data.append("| License | Count |")
    markdown_data.append("| ------------ | ----------- |")
    # Create an empty dictionary
    freq = {}
    for items in sorted(sbom_licenses):
        freq[items] = sbom_licenses.count(items)
    for key, value in freq.items():
        markdown_data.append("| " + key + " | " + str(value) + " | ")

    markdown_data.append("\n# NTIA Summary\n")
    markdown_data.append("| Element | Status |")
    markdown_data.append("| ------------ | ----------- |")
    markdown_data.append("| All file information provided? |" + str(files_valid) + "|")
    markdown_data.append(
        "| All package information provided? |" + str(packages_valid) + "|"
    )
    markdown_data.append("| Creator identified? |" + str(creator_identified) + "|")
    markdown_data.append("| Creation time identified? |" + str(creation_time) + "|")
    markdown_data.append(
        "| Dependency relationships provided?' |" + str(relationships_valid) + "|"
    )

    valid_sbom = (
        files_valid
        and packages_valid
        and creator_identified
        and creation_time
        and relationships_valid
    )
    markdown_data.append(f"\nNTIA conformant {valid_sbom}")

    markdown_document = SBOMOutput(filename=outfile)
    markdown_document.generate_output(markdown_data)
