import requests
import re
from bs4 import BeautifulSoup


def mitre_urls():
    # URL of the MITRE ATT&CK groups page
    url = "https://attack.mitre.org/groups/"

    # Send a GET request to the webpage
    response = requests.get(url)

    # Create a BeautifulSoup object to parse the HTML content
    soup = BeautifulSoup(response.content, "html.parser")

    # Find the side navigation element
    side_nav = soup.select_one("#v-tab > div.side-nav-desktop-view.h-100 > div > div.sidenav-list")
    
    # Find all links to the group pages in the side navigation
    group_links = side_nav.select("div.sidenav-head > a[href^='/groups/G']")

    # Extract the URLs and return the list
    url_list = []
    for link in group_links:
        group_url = "https://attack.mitre.org" + link["href"]
        url_list.append(group_url)

    return url_list


def techniques(soup):
    capability = []
    tds = soup.select("td")
    current_technique = ""
    for td in tds:
        text = td.get_text().strip()
        if text.startswith("T") and text[1:].isdigit():
            current_technique = text
            capability.append(current_technique)
        elif text.startswith("."):
            sub_technique = current_technique + text
            capability.append(sub_technique)

    if not capability:
        return []

    return capability


def vulnerabilities(soup):
    vulnerabilities = []
    tds = soup.select("td")
    for td in tds:
        paragraph = td.find("p")
        if paragraph:
            text = paragraph.get_text()
            # Finds both CVE-XXXX-XXXX and CVE XXXX-XXXX' formats
            matches = re.findall(r"(CVE\s?-?(\d{4})-(\d{2,6}))", text)
            for match in matches:
                # formats to CVE-XXXX-XXXX standard
                cve_number = "CVE-" + match[1] + "-" + match[2]
                vulnerabilities.append(cve_number)

    if not vulnerabilities:
        return []

    return vulnerabilities


def software(soup):
    resources = []
    tds = soup.select("td")
    current_software = ""
    for td in tds:
        text = td.get_text().strip()
        if text.startswith("S") and text[1:].isdigit():
            current_software = text
            resources.append(current_software)

    if not resources:
        return []

    return resources
