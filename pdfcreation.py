import json
import os

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

source_folder = "mitre_groups"
output_folder = "mitre_groups_pdf"

def create_pdf_from_json(json_file_path, pdf_output_path):
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file_path)

    pdf_file = json_file.replace(".json", ".pdf")
    pdf_path = os.path.join(pdf_output_path, pdf_file)

    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.setFont("Helvetica", 10)

    c.drawString(30, 750, f"Threat Actor: {data['threat_actor']}")
    c.drawString(30, 730, f"Group ID: {data['group_id']}")
    c.drawString(30, 710, f"Associated Groups: {data['associated_groups']}")
    c.drawString(30, 690, f"APT Description: {data['apt_description']}")
    c.drawString(30, 670, f"Version Data: {data['version_data']}")

    c.drawString(30, 630, "Capability:")
    for index, capability in enumerate(data["capability"], start=1):
        c.drawString(30, 610 - (index * 20), capability)

    c.drawString(30, 510, "Resources:")
    for index, resource in enumerate(data["resources"], start=1):
        c.drawString(30, 490 - (index * 20), resource)

    c.drawString(30, 390, "Vulnerabilities:")
    for index, vulnerability in enumerate(data["vulnerabilities"], start=1):
        c.drawString(30, 370 - (index * 20), vulnerability)

    c.save()

    print(f"PDF created: {pdf_path}")