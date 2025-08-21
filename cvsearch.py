#!/usr/bin/env python3

import sys
import requests
import re
from colorama import Fore, Style

def green(t):
    return Fore.GREEN + str(t) + Style.RESET_ALL

def red(t):
    return Fore.RED + str(t) + Style.RESET_ALL

def yellow(t):
    return Fore.YELLOW + str(t) + Style.RESET_ALL

def cyan(t):
    return Fore.CYAN + str(t) + Style.RESET_ALL

def format_req(data_req):
    def check(v):
        return green(v) if v and v != "string" else red("None")

    print("CVE ID:", check(data_req.get("cve_id")))
    print("Summary:", check(data_req.get("summary")))

    print("\nExploitDB" + ": " + cyan(f"https://www.exploit-db.com/search?cve={check(data_req.get('cve_id'))}\n"))

    print("CVSS:", green(data_req["cvss"]) if (data_req.get("cvss") or 0) >= 7 else red(data_req.get("cvss", "None")))
    print("CVSS v2:", green(data_req["cvss_v2"]) if (data_req.get("cvss_v2") or 0) >= 7 else red(data_req.get("cvss_v2", "None")))
    print("CVSS v3:", green(data_req["cvss_v3"]) if (data_req.get("cvss_v3") or 0) >= 7 else red(data_req.get("cvss_v3", "None")))

    print("EPSS:", green(data_req["epss"]) if data_req.get("epss", 0) > 0.5 else red(data_req.get("epss", "None")))
    print("Ranking EPSS:", green(data_req["ranking_epss"]) if data_req.get("ranking_epss", 0) > 0.5 else red(data_req.get("ranking_epss", "None")))

    print("KEV:", green("True") if data_req.get("kev") else red("False"))

    print("Propose Action:", check(data_req.get("propose_action")))
    print("Ransonware Campaign:", check(data_req.get("ransomware_campaign")))

    refs = data_req.get("references", [])
    
    if refs and refs[0] != "string":
        print("References:")
        for i, ref in enumerate(refs, 1):
            print(f"  {i}. {green(ref)}")
    else:
        print("References:", red("None"))

    cpes = data_req.get("cpes", [])
    if cpes and any(cpe != "string" for cpe in cpes):
        print("CPEs:")
        for i, cpe in enumerate(cpes, 1):
            print(green(f" {i}. {cpe}"))
    else:
        print("CPEs:", red("None"))

    
    print("Published:", check(data_req.get("published_time")))

def cveidsearch(cveid):
    req = requests.get(f'https://cvedb.shodan.io/cve/{cveid}').json()

    format_req(req)

    ls = [f'https://nvd.nist.gov/vuln/detail/{cveid}', f'https://www.cve.org/CVERecord?id={cveid}', f'https://cvedb.shodan.io/cve/{cveid}']

    print('\nFor more, access:')
    for l in ls:
        print(red('  - ') + green(l))

def vulnsearch(keyw):    
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyw}'

    req = requests.get(url)

    if req.status_code != 200:
        print("Error. Try again.")
        return

    data = req.json()
    vulns = data.get("vulnerabilities", [])

    print(green("\nTotal vulnerabilities found") + ": " + str(len(vulns)))
    print(yellow("Search for more vulns and exploits here") + ": " + cyan(f"https://www.exploit-db.com/search?q={keyw}\n"))

    for vuln in vulns:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descriptions = cve.get("descriptions", [])
        description = descriptions[0]["value"] if descriptions else "No descriptions."

        print(green(cve_id) + ": " + red(description) + "\n" + yellow("Possible Exploits") + ": " + cyan(f"https://www.exploit-db.com/search?cve={cve_id}") + "\n")

def main(kw):
    format_cve = r"^CVE-\d{4}-\d{4,7}$"
    
    if re.match(format_cve, kw, re.IGNORECASE):
        cveidsearch(cveid=kw)
    else:
        fkw = kw.replace(" ","+")
        vulnsearch(fkw)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Use: ./cvsearch.py <keyword(s)>")
        sys.exit(1)

    keywords = " ".join(sys.argv[1:])
    main(keywords)

