function showLoading(show) {
    const loadingElement = document.querySelector('.loading');
    const resultsElement = document.getElementById('results-container');
    
    if (show) {
        loadingElement.style.display = 'block';
        resultsElement.style.display = 'none';
    } else {
        loadingElement.style.display = 'none';
        if (resultsElement) {
            resultsElement.style.display = 'block';
        }
    }
}

function isCVEID(searchTerm) {
    const cvePattern = /^CVE-\d{4}-\d{4,7}$/i;
    return cvePattern.test(searchTerm.trim());
}

function dataFormat(dataString) {
    if (!dataString || typeof dataString !== 'string') {
        return 'Invalid date';
    }

    const dataLimpa = dataString.replace(/\]$/, '');

    try {
        const data = new Date(dataLimpa);
        
        if (isNaN(data.getTime())) {
            throw new Error('Invalid date');
        }

        const dia = String(data.getDate()).padStart(2, '0');
        const mes = String(data.getMonth() + 1).padStart(2, '0');
        const ano = data.getFullYear();
        const horas = String(data.getHours()).padStart(2, '0');
        const minutos = String(data.getMinutes()).padStart(2, '0');

        return `${dia}/${mes}/${ano} ${horas}:${minutos}`;
    } catch (error) {
        console.error('Error formatting date:', error);
        return 'Invalid date';
    }
}

async function fetchCVEData(cveId) {
    const proxyUrl = 'https://corsproxy.io/?'
    const targetUrl = `https://cvedb.shodan.io/cve/${cveId}`
    
    try {
      const response = await fetch(proxyUrl + encodeURIComponent(targetUrl), {
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        }
      });
      return await response.json();
    } catch (error) {
      console.error("Request error:", error);
      throw error;
    }
}

function filterCriticalVulnerabilities(cveData) {
    const RISK_THRESHOLDS = {
        CVSS_CRITICAL: 9.0,
        CVSS_HIGH: 7.0,
        EPSS_HIGH: 0.75,
        EPSS_MEDIUM: 0.5
    };
  
    const cvss = cveData.cvss_v3 || cveData.cvss || 0;
    const epss = cveData.epss || 0;
    const isKEV = cveData.kev === true;
  
    const isCriticalCVSS = cvss >= RISK_THRESHOLDS.CVSS_CRITICAL;
    const isHighCVSS = cvss >= RISK_THRESHOLDS.CVSS_HIGH;
    const isHighEPSS = epss >= RISK_THRESHOLDS.EPSS_HIGH;
    const isMediumEPSS = epss >= RISK_THRESHOLDS.EPSS_MEDIUM;
  
    let riskLevel = 'LOW';
    if (isKEV) riskLevel = 'CRITICAL_KEV';
    else if (isCriticalCVSS && isHighEPSS) riskLevel = 'CRITICAL';
    else if (isHighCVSS && isMediumEPSS) riskLevel = 'HIGH';
    else if (isHighCVSS) riskLevel = 'MODERATE';

    return {
      cveId: cveData.cve_id,
      riskLevel: riskLevel,
      metrics: {
        cvss: cvss,
        cvssVersion: cveData.cvss_version || '3.0',
        epss: epss,
        epssPercentile: cveData.ranking_epss ? (cveData.ranking_epss * 100).toFixed(1) + '%' : 'N/A',
        isKEV: isKEV
      },
      details: {
        summary: cveData.summary,
        affectedVersions: extractAffectedVersions(cveData.summary),
        references: cveData.references || []
      },
      flags: {
        requiresImmediateAction: isKEV || isCriticalCVSS,
        highExploitProbability: isHighEPSS,
        highImpact: isHighCVSS
      }
    };
  }
  
function extractAffectedVersions(summary) {
    const versionPattern = /versions? (\d+\.\d+\.\d+)/gi;
    const matches = summary.match(versionPattern);
    return matches ? [...new Set(matches)] : [];
}

function getRiskColor(riskLevel) {
    const colors = {
        CRITICAL_KEV: '#ff0000',
        CRITICAL: '#ff4500',
        HIGH: '#ff8c00',
        MODERATE: '#ffd700',
        LOW: '#32cd32'
    };
    return colors[riskLevel] || '#cccccc';
}

function displayReferences(references) {
    if (!references || references.length === 0) {
        return '<p>No references available</p>';
    }

    let html = '<div class="references-container"><h2 style="color: var(--accent-color);">References:</h2><ul>';    

    references.forEach((ref) => {
        html += `
            <li>
                <a href="${ref}" target="_blank" rel="noopener noreferrer">
                    ${ref}
                </a>
            </li>
        `;
    });
    
    html += '</ul></div>';
    return html;
}

function formatSearchTerm(term) {
    return term.trim().replace(/\s+/g, '+');
}

async function handleSearch(e) {
    e.preventDefault();
    
    const searchTerm = document.getElementById('search-input').value.trim();
    
    if (!searchTerm) {
        document.getElementById('results-container').style.display = 'block';
        document.getElementById('results-container').innerHTML = '<span class="error-message">Please enter a search term or CVE-ID.</span>';
        showLoading(false);
        return;
    }

    try {
        showLoading(true);
        
        if (document.getElementById('results-container')) {
            if (isCVEID(searchTerm)) {
                const cveData = await fetchCVEData(searchTerm);
                const resultsContainer = document.getElementById('results-container');
                const filtered = filterCriticalVulnerabilities(cveData);

                let cveTitle = "Title not found";

                try {
                    const response = await fetch(`https://cveawg.mitre.org/api/cve/${filtered.cveId}`);
                    
                    if (response.ok) {
                        const data = await response.json();
                        cveTitle = data.containers?.cna?.title || "Title not found";
                    }
                } catch (error) {
                    console.error('Error fetching CVE title:', error);
                }

                console.log(cveTitle);

                resultsContainer.innerHTML = `
                    <style>
                        .cve-info {
                            list-style-type: none;
                            padding-left: 0;
                        }
                        
                        .cve-info strong {
                            color: var(--accent-color);
                            font-weight: 600;
                        }
                        
                        .cve-info li {
                            margin-bottom: 8px;
                            padding: 5px 0;
                            border-bottom: 1px solid rgba(255,255,255,0.1);
                        }
                        
                        .risk-badge {
                            display: inline-block;
                            padding: 2px 8px;
                            border-radius: 12px;
                            font-size: 12px;
                            font-weight: bold;
                            color: white;
                        }
                        
                        .critical { background-color: #ff0000; }
                        .high { background-color: #ff8c00; }
                        .moderate { background-color: #ffd700; color: #333; }
                        .low { background-color: #32cd32; }

                        a, a:visited, a:hover, a:active {
                            color: inherit;
                        }
                        
                        a:hover {
                            text-decoration: underline;
                            color: var(--accent-color);
                        }
                    </style>
                    <ul class="cve-info">
                        <h1 style="color: #FFD700, font-size: 35px;">${cveTitle}</h1>

                        <li><strong>CVE ID:</strong> ${filtered.cveId || 'Not available'}</li>
                        <li><strong>Summary:</strong> ${filtered.details.summary || 'Not available'}</li>
                        <li><strong>CVSS Score:</strong> ${filtered.metrics.cvss || 'Not available'} 
                            <span class="risk-badge ${filtered.riskLevel.toLowerCase().includes('critical') ? 'critical' : 
                                                    filtered.riskLevel.toLowerCase().includes('high') ? 'high' :
                                                    filtered.riskLevel.toLowerCase().includes('moderate') ? 'moderate' : 'low'}">
                                ${filtered.riskLevel}
                            </span>
                        </li>
                        <li><strong>Published:</strong> ${dataFormat(cveData.published_time) || 'Not available'}</li>
                        <li><strong>Exploits:<br></strong><a href="https://www.exploit-db.com/search?cve=${filtered.cveId}" target="_blank">ExploitDB</a><br><a href="https://www.offsec.com/blog/${filtered.cveId}" target="_blank">OffSec Blog</a></li>

                        <li><strong>EPSS Score:</strong> ${filtered.metrics.epssPercentile} 
                            (${filtered.flags.highExploitProbability ? 'High probability' : 'Medium/Low probability'})
                        </li>
                        <h3 style="color: var(--accent-color);">Main Links</h3>
                        <a href="https://nvd.nist.gov/vuln/detail/${filtered.cveId}" target="_blank">nvd.nist</a><br>
                        <a href="https://www.cve.org/CVERecord?id=${filtered.cveId}" target="_blank">cve.org</a><br>
                        <a href="https://cvedb.shodan.io/cve/${filtered.cveId}" target="_blank">cvedb.shodan</a><br>
                        ${displayReferences(filtered.details.references)}
                    </ul>
                `;
            } else {
                const resultsContainer = document.getElementById('results-container');
                let searchTerm = document.getElementById('search-input').value;
                searchTerm = formatSearchTerm(searchTerm);
            
                try {
                    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${searchTerm}`);
                    
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
            
                    const data = await response.json();
                    const vulns = data.vulnerabilities || [];
                    
                    let htmlContent = '<div class="vuln-results">';
                    
                    vulns.forEach((vuln, index) => {
                        const cve = vuln.cve || {};
                        const cveId = cve.id || 'N/A';
                    
                        const descriptions = cve.descriptions || [];
                        const englishDesc = descriptions.find(desc => desc.lang === 'en');
                        const description = englishDesc?.value || 'No description available';
                    
                        htmlContent += `
                            <style>
                                .vuln-item h3 {
                                    color: #2980B9;
                                    cursor: pointer;
                                    text-decoration: underline;
                                }
                            </style>
                            <div class="vuln-item" data-index="${index}">
                                <h3 class="cve-click" data-cve-id="${cveId}">${cveId}</h3>
                                <p>${description}</p>
                                <br>
                            </div>
                        `;
                    });                    
            
                    htmlContent += '</div>';
                    resultsContainer.innerHTML = htmlContent;

                    document.querySelectorAll('.cve-click').forEach(el => {
                        el.addEventListener('click', (e) => {
                            const id = e.target.getAttribute('data-cve-id');
                            if (id && isCVEID(id)) {
                                document.getElementById('search-input').value = id;
                                handleSearch(new Event('submit'));
                            }
                        });
                    });                    
                    
                } catch (error) {
                    throw error;
                }
            }
        }
    } catch (error) {
        document.getElementById('results-container').style.display = 'block';
        document.getElementById('results-container').innerHTML = `<span class="error-message">${error.message}.</span>`;
    } finally {
        showLoading(false);
    }
}

document.getElementById('search-box').addEventListener('submit', handleSearch);
