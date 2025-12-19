import requests

def search_cve(cve):
    shodanApi = f"https://cvedb.shodan.io/cve/{cve}"
    mitreApi = f"https://cveawg.mitre.org/api/cve/{cve}"
    nistApi = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    cyberhubCve = f"https://www.cyberhub.blog/api/cves?search=middleware"

    mediumSearch = f"https://medium.com/search?q={cve}+exploit"
    cveblogSearch = f"https://www.offsec.com/blog/{cve}"
    exploitdbSearch = f"https://www.exploit-db.com/search?q={cve}"
    cyberhubSearch = f"https://www.cyberhub.blog/cves/{cve}"
    
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    # try to get title
    try:
        reqTitle = requests.get(mitreApi, headers=headers)
        dataMitre = reqTitle.json()

        title = dataMitre['containers']['cna']['title']
    except Exception:
        title = cve

    reqShodan = requests.get(shodanApi)
    dataShodan = reqShodan.json()

    summary = dataShodan['summary']
    is_kevf = dataShodan['kev']
    if is_kevf == True:
        is_kev = "Yes"
    elif is_kevf == False:
        is_kev = "No"
    else:
        is_kev = "Error on request"

    references = dataShodan['references']

    responseBody = {
        "title": title,
        "cve": cve,
        "summary": summary,
        "is_kev": is_kev,
        "exploits": [mediumSearch, cveblogSearch, exploitdbSearch, cyberhubSearch],
        "references": references
    }

    return responseBody



def search_vuln(searchTerm):
    headers = {'User-Agent': 'Mozilla/5.0'}

    nistApi = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={searchTerm}"
    
    reqNist = requests.get(nistApi, headers=headers)
    dataNist = reqNist.json()
    vulns = dataNist.get('vulnerabilities', [])
    
    results = {}

    i=0
    if vulns:
        for item in vulns:
            
            cveId = item['cve']['id']
            summary = item['cve']['descriptions'][0]['value']

            tempData = {
                "cve": cveId,
                "summary": summary
            }
            results[i] = tempData
            i+=1

    return results