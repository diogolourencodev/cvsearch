document.getElementById('searchInput').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        performSearch();
    }
});

async function performSearch() {
    const input = document.getElementById('searchInput');
    const term = input.value.trim();
    const resultsArea = document.getElementById('resultsArea');
    const loading = document.getElementById('loading');

    if (!term) return;

    // Reset UI
    resultsArea.innerHTML = '';
    loading.classList.remove('hidden');
    input.disabled = true;

    try {
        const response = await fetch(`/api/search/${encodeURIComponent(term)}`);
        
        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }

        const data = await response.json();
        renderResults(data);

    } catch (error) {
        resultsArea.innerHTML = `
            <div class="card" style="border-color: var(--danger)">
                <h3 style="color: var(--danger)">Error</h3>
                <p>${error.message}</p>
            </div>
        `;
    } finally {
        loading.classList.add('hidden');
        input.disabled = false;
        input.focus();
    }
}

function renderResults(data) {
    const resultsArea = document.getElementById('resultsArea');
    
    // Check if it's a single CVE result (has 'title' and 'cve')
    if (data.cve && data.title) {
        renderSingleCVE(data);
        return;
    }

    // Check if it's a list of results (from search_vuln)
    // The backend returns an object with numeric keys: {0: {...}, 1: {...}}
    // We convert it to an array using Object.values()
    const list = Object.values(data);

    if (list.length === 0) {
        resultsArea.innerHTML = '<div class="card"><p>No results found.</p></div>';
        return;
    }

    list.forEach(item => {
        // Handle potential empty items if backend index logic had gaps (unlikely now)
        if (!item || !item.cve) return;
        renderListItem(item);
    });
}

function renderSingleCVE(item) {
    const resultsArea = document.getElementById('resultsArea');

    const getSeverityColor = (severity) => {
        if (!severity) return 'var(--text-primary)';
        const s = severity.toLowerCase();
        if (s === 'critical') return 'var(--danger)';
        if (s === 'high') return '#ff9800';
        if (s === 'medium') return '#ffc107';
        return 'var(--success)';
    };
    
    // Define exploit sources with their names and icons
    const exploitSources = [
        { name: 'Medium', icon: 'fab fa-medium' },
        { name: 'OffSec Blog', icon: 'fas fa-shield-alt' },
        { name: 'Exploit-DB', icon: 'fas fa-database' },
        { name: 'Cyberhub', icon: 'fas fa-bug' }
    ];

    const exploitsHtml = item.exploits ? item.exploits.map((link, index) => {
        const source = exploitSources[index] || { name: 'Unknown Source', icon: 'fas fa-link' };
        return `<a href="${link}" target="_blank" class="link-tag"><i class="${source.icon}"></i> ${source.name}</a>`;
    }).join('') : '';

    const referencesHtml = item.references ? item.references.map(ref => 
        `<a href="${ref}" target="_blank" class="link-tag" style="font-size: 0.8rem; margin-top: 0.5rem; display: inline-block;"><i class="fas fa-external-link-alt"></i> ${new URL(ref).hostname}</a>`
    ).join('') : '';

    const html = `
        <div class="card">
            <div class="card-header">
                <span class="cve-id">${item.cve}</span>
                ${item.is_kev === 'Yes' ? '<span class="kev-badge">KEV DETECTED</span>' : ''}
            </div>
            <h3>${item.title || 'No Title Available'}</h3>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 0.5rem;">
                <div>
                    <strong style="color: var(--text-secondary); font-size: 0.9rem;">KEV Status:</strong>
                    <div style="font-weight: bold; color: ${item.is_kev === 'Yes' ? 'var(--danger)' : 'var(--success)'}">${item.is_kev}</div>
                </div>
                <div>
                    <strong style="color: var(--text-secondary); font-size: 0.9rem;">Severity:</strong>
                    <div style="font-weight: bold; color: ${getSeverityColor(item.severity)}">${item.severity || 'N/A'}</div>
                </div>
                <div>
                    <strong style="color: var(--text-secondary); font-size: 0.9rem;">Attack Vector:</strong>
                    <div style="font-weight: bold; color: var(--text-primary)">${item.attackVetor || 'N/A'}</div>
                </div>
                <div>
                    <strong style="color: var(--text-secondary); font-size: 0.9rem;">Complexity:</strong>
                    <div style="font-weight: bold; color: var(--text-primary)">${item.attackComplexity || 'N/A'}</div>
                </div>
                <div>
                    <strong style="color: var(--text-secondary); font-size: 0.9rem;">Privileges:</strong>
                    <div style="font-weight: bold; color: var(--text-primary)">${item.privilegesRequired || 'N/A'}</div>
                </div>
            </div>

            <p class="summary"><strong>Summary:</strong><br>${item.summary || 'No summary provided.'}</p>
            
            <div style="margin-top: 1.5rem; border-top: 1px solid var(--border); padding-top: 1rem;">
                <h4><i class="fas fa-search"></i> Exploit Dorks & Searches</h4>
                <div class="links" style="margin-top: 0.5rem; margin-bottom: 1.5rem;">
                    ${exploitsHtml}
                </div>

                <h4><i class="fas fa-book"></i> References</h4>
                <div class="links" style="margin-top: 0.5rem;">
                    ${referencesHtml || '<span style="color: var(--text-secondary)">No references found.</span>'}
                </div>
            </div>
        </div>
    `;
    resultsArea.innerHTML = html;
}

function renderListItem(item) {
    const resultsArea = document.getElementById('resultsArea');
    
    // Create element to append instead of overwriting innerHTML
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
        <div class="card-header">
            <span class="cve-id">${item.cve}</span>
        </div>
        <p class="summary">${item.summary || 'No summary available'}</p>
        <div class="links">
            <button onclick="document.getElementById('searchInput').value='${item.cve}'; performSearch();" class="link-tag" style="cursor:pointer; background:transparent;">
                <i class="fas fa-search"></i> Analyze this CVE
            </button>
        </div>
    `;
    resultsArea.appendChild(card);
}