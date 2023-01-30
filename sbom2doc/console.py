# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4sbom.data.document import SBOMDocument
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def send_to_console(sbom_parser, filename):
    # Get constituent components of the SBOM
    packages = sbom_parser.get_packages()
    files = sbom_parser.get_files()
    relationships = sbom_parser.get_relationships()
    document = SBOMDocument()
    document.copy_document(sbom_parser.get_document())

    print(Panel("SBOM Summary", style="bold", expand=False))
    table = Table()
    table.add_column("Item")
    table.add_column("Details")
    table.add_row("SBOM File", filename)
    table.add_row("SBOM Type", document.get_type())
    table.add_row("Version", document.get_version())
    table.add_row("Name", document.get_name())
    creator_identified = False
    for c in document.get_creator():
        creator_identified = True
        table.add_row("Creator", f"{c[0]}:{c[1]}")
    table.add_row("Created", document.get_created())
    table.add_row("Files", str(len(files)))
    table.add_row("Packages", str(len(packages)))
    table.add_row("Relationships", str(len(relationships)))
    creation_time = document.get_created() is not None

    console = Console()
    console.print(table)

    files_valid = True
    packages_valid = True
    relationships_valid = len(relationships) > 0
    sbom_licenses = []
    if len(files) > 0:

        print(Panel("File Summary", style="bold", expand=False))
        table = Table()
        table.add_column("Name")
        table.add_column("Type")
        table.add_column("License")
        table.add_column("Copyright")
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
            table.add_row(name, file_type, license, copyright)
            if id is None or name is None:
                files_valid = False
        console = Console()
        console.print(table)

    if len(packages) > 0:

        print(Panel("Package Summary", style="bold", expand=False))
        table = Table()
        table.add_column("Name")
        table.add_column("Version")
        table.add_column("Supplier")
        table.add_column("License")
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
            table.add_row(name, version, supplier, license)
            if (
                id is None
                or name is None
                or version is None
                or supplier is None
                or supplier == "NOASSERTION"
            ):
                packages_valid = False
        console = Console()
        console.print(table)

    print(Panel("License Summary", style="bold", expand=False))
    table = Table()
    table.add_column("License")
    table.add_column("Count")
    # Create an empty dictionary
    freq = {}
    for items in sorted(sbom_licenses):
        freq[items] = sbom_licenses.count(items)
    for key, value in freq.items():
        table.add_row(key, str(value))
    console = Console()
    console.print(table)

    print(Panel("NTIA Summary", style="bold", expand=False))
    table = Table()
    table.add_column("Element")
    table.add_column("Status")
    table.add_row("All file information provided?", str(files_valid))
    table.add_row("All package information provided?", str(packages_valid))
    table.add_row("Creator identified?", str(creator_identified))
    table.add_row("Creation time identified?", str(creation_time))
    table.add_row("Dependency relationships provided?", str(relationships_valid))
    console = Console()
    console.print(table)
    valid_sbom = (
        files_valid
        and packages_valid
        and creator_identified
        and creation_time
        and relationships_valid
    )
    print(f"\nNTIA conformant {valid_sbom}")
