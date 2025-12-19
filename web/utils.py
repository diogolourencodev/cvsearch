import re
import requests

def is_valid_cve(term):
    if not term:
        return False

    clean_term = term.strip().upper()
    
    pattern = r'^CVE-\d{4}-\d{4,}$'
    
    return bool(re.match(pattern, clean_term))
