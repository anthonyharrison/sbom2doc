# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4sbom.output import SBOMOutput

from sbom2doc.docbuilder.docbuilder import DocBuilder


class JSONBuilder(DocBuilder):
    def __init__(self):
        self.json_document = {}
        self.element=["",""]
        self.element_data=[]
        self.attribute_headings = []

    def heading(self, level, title, number=True):
        if self.element[level-1] != "":
            self.json_document[self.element[level-1]] = self.element_data
        self.element[level-1] = title
        self.element_data = []

    def createtable(self, header, validate=None):
        # Layout is [headings, ....]
        self.attribute_headings = header

    def addrow(self, data):
        # Add row to table
        my_data = {}
        index = 0
        for d in data:
            if d is not None:
                my_data[self.attribute_headings[index]] = d
            else:
                my_data[self.attribute_headings[index]] = ""
            index = index + 1
        self.element_data.append(my_data)

    def publish(self, filename):
        # Force last set of data to be added to document
        self.heading(1,"dummy")
        json_doc = SBOMOutput(filename=filename, output_format="json")
        json_doc.generate_output(self.json_document)
