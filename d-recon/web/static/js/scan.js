// Страница деталей сканирования
class ScanDetail {
    constructor(target) {
        this.target = target;
        this.scanData = null;
        this.init();
    }

    async init() {
        await this.loadScanData();
        this.renderOverview();
        this.renderModules();
    }

    async loadScanData() {
        try {
            const response = await fetch(`/api/scan/${this.target}`);
            this.scanData = await response.json();
        } catch (error) {
            console.error('Failed to load scan data:', error);
            document.body.innerHTML = '<div class="container"><h1>Scan not found</h1></div>';
        }
    }

    renderOverview() {
        const overview = document.getElementById('overview-info');
        overview.innerHTML = `
            <p><strong>Target:</strong> ${this.scanData.target}</p>
            <p><strong>Scan Date:</strong> ${new Date(this.scanData.timestamp).toLocaleString()}</p>
            <p><strong>Duration:</strong> ${this.scanData.duration}</p>
            <p><strong>Modules Executed:</strong> ${Object.keys(this.scanData.modules).length}</p>
        `;
    }

    renderModules() {
        this.renderSubdomains();
        this.renderPorts();
        this.renderWebServices();
        this.renderOSINT();
    }

    renderSubdomains() {
        const module = this.scanData.modules.subdomains;
        if (!module) return;

        const container = document.querySelector('#subdomains-card .module-content');
        const subdomains = module.subdomains || [];
        
        container.innerHTML = `
            <p><strong>Found:</strong> ${subdomains.length} subdomains</p>
            <div class="subdomains-list">
                ${subdomains.slice(0, 10).map((sub, i) => `
                    <div class="subdomain-item">${i + 1}. ${sub}</div>
                `).join('')}
                ${subdomains.length > 10 ? `<p>... and ${subdomains.length - 10} more</p>` : ''}
            </div>
        `;
    }

    renderPorts() {
        const module = this.scanData.modules.ports;
        if (!module) return;

        const container = document.querySelector('#ports-card .module-content');
        const ports = module.openPorts || [];
        
        container.innerHTML = `
            <p><strong>Scan Type:</strong> ${module.scanType || 'unknown'}</p>
            <p><strong>Open Ports:</strong> ${ports.length}</p>
            <div class="ports-list">
                ${ports.map(port => `
                    <div class="port-item">
                        ${port.number}/${port.protocol} - ${port.service} (${port.state})
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderWebServices() {
        const module = this.scanData.modules.web;
        if (!module) return;

        const container = document.querySelector('#web-card .module-content');
        const services = module.webResults || [];
        
        container.innerHTML = `
            <p><strong>Services Found:</strong> ${services.length}</p>
            <div class="services-list">
                ${services.map(service => `
                    <div class="service-item">
                        <strong>${service.url}</strong> [${service.statusCode}]
                        ${service.tech && service.tech.length > 0 ? 
                            `<br><small>Tech: ${service.tech.join(', ')}</small>` : ''}
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderOSINT() {
        const module = this.scanData.modules.osint;
        if (!module) return;

        const container = document.querySelector('#osint-card .module-content');
        
        let content = '';
        
        if (module.whois) {
            content += `
                <div class="osint-section">
                    <h4>WHOIS</h4>
                    <p>Registrar: ${module.whois.registrar}</p>
                    <p>Created: ${module.whois.createdDate}</p>
                    <p>Expires: ${module.whois.expiryDate}</p>
                </div>
            `;
        }

        if (module.leaks) {
            const leaksFound = module.leaks.filter(leak => leak.found).length;
            content += `
                <div class="osint-section">
                    <h4>Data Leaks</h4>
                    <p><strong>Potential Leaks:</strong> ${leaksFound}</p>
                    ${module.leaks.map(leak => `
                        <div class="leak-item ${leak.found ? 'status-warning' : 'status-success'}">
                            ${leak.source}: ${leak.details}
                        </div>
                    `).join('')}
                </div>
            `;
        }

        container.innerHTML = content;
    }
}

// Функции экспорта
async function exportReport(format) {
    const target = window.location.pathname.split('/').pop();
    
    try {
        const response = await fetch(`/api/scan/${target}`);
        const data = await response.json();
        
        if (format === 'json') {
            downloadJSON(data, `${target}_report.json`);
        } else if (format === 'html') {
            generateHTMLReport(data, target);
        }
    } catch (error) {
        console.error('Export failed:', error);
        alert('Export failed: ' + error.message);
    }
}

function downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
}

function generateHTMLReport(data, target) {
    const html = `
<!DOCTYPE html>
<html>
<head>
    <title>d-recon Report - ${target}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .module { background: #f9f9f9; padding: 15px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>d-recon Report</h1>
    <div class="section">
        <h2>Scan Overview</h2>
        <p><strong>Target:</strong> ${data.target}</p>
        <p><strong>Date:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
        <p><strong>Duration:</strong> ${data.duration}</p>
    </div>
    
    ${Object.entries(data.modules).map(([name, module]) => `
        <div class="section">
            <h2>${name.toUpperCase()} Module</h2>
            <div class="module">
                <pre>${JSON.stringify(module, null, 2)}</pre>
            </div>
        </div>
    `).join('')}
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${target}_report.html`;
    link.click();
    URL.revokeObjectURL(url);
}

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    const target = window.location.pathname.split('/').pop();
    new ScanDetail(target);
});