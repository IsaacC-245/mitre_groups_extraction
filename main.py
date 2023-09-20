import json
import os

import requests
from bs4 import BeautifulSoup

from extractions import mitre_urls, techniques, vulnerabilities, software, group_id, associated_groups_or_name,\
    version_data, apt_description

url_list = mitre_urls()

output_folder = "mitre_groups"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

for index, link in enumerate(url_list, start=1):
    response = requests.get(link)
    soup = BeautifulSoup(response.content, "html.parser")

    group_name = soup.select_one("h1").text.strip()

    capability_list = techniques(soup)
    vulnerabilities_list = vulnerabilities(soup)
    resources_list = software(soup)

    group_data = {
        "threat_actor": group_name,
        "group_id": group_id(soup),
        "associated_groups": associated_groups_or_name(soup),
        "apt_description": apt_description(soup),
        "version_data": version_data(soup),
        "capability": capability_list,
        "resources": resources_list,
        "vulnerabilities": vulnerabilities_list
    }

    filename = f"{group_name.replace(' ', '_')}.json"
    filepath = os.path.join(output_folder, filename)

    with open(filepath, "w") as file:
        json.dump(group_data, file, indent=4)

    print(f"APT data saved: {filepath}")
