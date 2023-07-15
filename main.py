from bs4 import BeautifulSoup
import requests
import os
import json
from extractions import mitre_urls, techniques, vulnerabilities, software

# URL of the MITRE ATT&CK groups page
url_list = mitre_urls()

# Create a folder to store the JSON files
output_folder = "mitre_groups"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# Iterate over each group link and extract information from the group page
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
