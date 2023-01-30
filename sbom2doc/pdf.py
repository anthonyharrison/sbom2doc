# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from cve_bin_tool.output_engine import pdfbuilder
from lib4sbom.data.document import SBOMDocument


def generate_pdf(sbom_parser, filename, outfile):
    # Get constituent components of the SBOM
    packages = sbom_parser.get_packages()
    files = sbom_parser.get_files()
    relationships = sbom_parser.get_relationships()
    document = SBOMDocument()
    document.copy_document(sbom_parser.get_document())

    # Build document
    pdfdoc = pdfbuilder.PDFBuilder()
    cm = pdfdoc.cm
    # pdfdoc.front_page("SBOM Report")
    pdfdoc.heading(1, "SBOM Summary")
    pdfdoc.createtable(
        "SBOMsummary",
        ["Item", "Details"],
        pdfdoc.tblStyle,
    )
    pdfdoc.addrow("SBOMsummary", ["SBOM File", filename])
    pdfdoc.addrow("SBOMsummary", ["SBOM Type", document.get_type()])
    pdfdoc.addrow("SBOMsummary", ["Version", document.get_version()])
    pdfdoc.addrow("SBOMsummary", ["Name", document.get_name()])
    creator_identified = False
    for c in document.get_creator():
        creator_identified = True
        pdfdoc.addrow("SBOMsummary", ["Creator", f"{c[0]}:{c[1]}"])
    pdfdoc.addrow("SBOMsummary", ["Created", document.get_created()])
    pdfdoc.addrow("SBOMsummary", ["Files", str(len(files))])
    pdfdoc.addrow("SBOMsummary", ["Packages", str(len(packages))])
    pdfdoc.addrow("SBOMsummary", ["Relationships", str(len(relationships))])
    pdfdoc.showtable("SBOMsummary", widths=[5 * cm, 9 * cm])

    creation_time = document.get_created() is not None

    files_valid = True
    packages_valid = True
    relationships_valid = len(relationships) > 0
    sbom_licenses = []
    if len(files) > 0:

        pdfdoc.heading(1, "File Summary")
        pdfdoc.createtable(
            "Filesummary",
            ["Name", "Type", "License", "Copyright"],
            pdfdoc.tblStyle,
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
            pdfdoc.addrow("Filesummary", [name, file_type, license, copyright])
            if id is None or name is None:
                files_valid = False
        pdfdoc.showtable("Filesummary", widths=[3 * cm, 2 * cm, 4 * cm, 5 * cm])

    if len(packages) > 0:

        pdfdoc.heading(1, "Package Summary")
        # Separate table for supplier information
        pdfdoc.createtable(
            "Packagesummary",
            ["Name", "Version", "Supplier", "License"],
            pdfdoc.tblStyle,
        )
        supplier_id = 1
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
            pdfdoc.addrow("Packagesummary", [name, version, str(supplier_id), license])
            supplier_id = supplier_id + 1
            if (
                id is None
                or name is None
                or version is None
                or supplier is None
                or supplier == "NOASSERTION"
            ):
                packages_valid = False
        pdfdoc.showtable("Packagesummary", widths=[5 * cm, 2 * cm, 2 * cm, 5 * cm])
        pdfdoc.heading(2, "Package Suupliers")
        pdfdoc.createtable(
            "Packagesupplier",
            ["Id", "Supplier"],
            pdfdoc.tblStyle,
        )
        supplier_id = 1
        for package in packages:
            supplier = package.get("supplier", None)
            pdfdoc.addrow("Packagesupplier", [str(supplier_id), supplier])
            supplier_id = supplier_id + 1
        pdfdoc.showtable("Packagesupplier", widths=[2 * cm, 12 * cm])

    pdfdoc.heading(1, "License Summary")
    pdfdoc.createtable(
        "Licensesummary",
        ["License", "Count"],
        pdfdoc.tblStyle,
    )
    # Create an empty dictionary
    freq = {}
    for items in sorted(sbom_licenses):
        freq[items] = sbom_licenses.count(items)
    for key, value in freq.items():
        pdfdoc.addrow("Licensesummary", [key, str(value)])
    pdfdoc.showtable("Licensesummary", widths=[10 * cm, 4 * cm])

    pdfdoc.heading(1, "NTIA Summary")
    pdfdoc.createtable(
        "NTIAsummary",
        ["Element", "Status"],
        pdfdoc.tblStyle,
    )
    pdfdoc.addrow("NTIAsummary", ["All file information provided?", str(files_valid)])
    pdfdoc.addrow(
        "NTIAsummary", ["All package information provided?", str(packages_valid)]
    )
    pdfdoc.addrow("NTIAsummary", ["Creator identified?", str(creator_identified)])
    pdfdoc.addrow("NTIAsummary", ["Creation time identified?", str(creation_time)])
    pdfdoc.addrow(
        "NTIAsummary", ["Dependency relationships provided?", str(relationships_valid)]
    )
    pdfdoc.showtable("NTIAsummary", widths=[10 * cm, 4 * cm])

    valid_sbom = (
        files_valid
        and packages_valid
        and creator_identified
        and creation_time
        and relationships_valid
    )
    pdfdoc.paragraph(f"NTIA conformant {valid_sbom}")
    pdfdoc.publish(outfile)
