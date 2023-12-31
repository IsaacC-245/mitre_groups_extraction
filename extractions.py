import re

import requests
from bs4 import BeautifulSoup


def mitre_urls():
    url = "https://attack.mitre.org/groups/"

    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")

    side_nav = soup.select_one("#sidebar-collapse > div")
    group_links = side_nav.select("div.sidenav-head > a[href^='/groups/G']")

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
    # current_software = ""
    for td in tds:
        text = td.get_text().strip()
        if text.startswith("S") and text[1:].isdigit():
            current_software = text
            resources.append(current_software)

    if not resources:
        return []

    return resources


def group_id(soup):
    return soup.select_one(".card-title:contains('ID:')").next_sibling.strip()


def associated_groups_or_name(soup):
    group_names = {}
    associated_groups_element = soup.select_one(".card-title:contains('Associated Groups')")
    if associated_groups_element:
        associated_groups = associated_groups_element.next_sibling.strip()
        group_names["associated_groups"] = [group.strip() for group in associated_groups.split(',')]
    else:
        return []

    return group_names


def version_data(soup):
    info = {}
    # version = soup.select_one(".card-title:contains('Version')").next_sibling.strip()
    created_date = soup.select_one(".card-title:contains('Created:')").next_sibling.strip()
    last_modified_date = soup.select_one(".card-title:contains('Last Modified:')").next_sibling.strip()
    # info["version"] = version
    info["created_date"] = created_date
    info["last_modified_date"] = last_modified_date

    return info


def apt_description(soup):
    paragraphs = soup.select(".description-body > p")
    return [p.get_text(strip=True) for p in paragraphs]
