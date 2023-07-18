import json
import os

import requests
from bs4 import BeautifulSoup

from extractions import mitre_urls, techniques, vulnerabilities, software, apt_summary

url_list = mitre_urls()

output_folder = "mitre_groups"
summary_folder = "mitre_groups_summary"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)
if not os.path.exists(summary_folder):
    os.makedirs(summary_folder)

for index, link in enumerate(url_list, start=1):
    response = requests.get(link)
    soup = BeautifulSoup(response.content, "html.parser")

    group_name = soup.select_one("h1").text.strip()

    capability_list = techniques(soup)
    vulnerabilities_list = vulnerabilities(soup)
    resources_list = software(soup)

    group_data = {
        "threat_actor": group_name,
        "capability": capability_list,
        "resources": resources_list,
        "vulnerabilities": vulnerabilities_list
    }

    filename = f"{group_name.replace(' ', '_')}.json"
    filepath = os.path.join(output_folder, filename)

    with open(filepath, "w") as file:
        json.dump(group_data, file, indent=4)

    print(f"APT data saved: {filepath}")

    group_description = apt_summary(soup)

    summary_filename = f"{group_name.replace(' ', '_')}_summary.json"
    summary_filepath = os.path.join(summary_folder, summary_filename)

    with open(summary_filepath, "w") as summary_file:
        json.dump(group_description, summary_file, indent=4)

    print(f"APT summary saved to: {summary_filepath}")
