// Основное приложение
class DReconApp {
    constructor() {
        this.scans = [];
        this.init();
    }

    async init() {
        await this.loadScans();
        this.renderScans();
        this.updateStats();
    }

    async loadScans() {
        try {
            const response = await fetch('/api/scans');
            this.scans = await response.json();
        } catch (error) {
            console.error('Failed to load scans:', error);
        }
    }

    renderScans() {
        const container = document.getElementById('scans-container');
        container.innerHTML = '';

        this.scans.forEach(scan => {
            const scanElement = document.createElement('div');
            scanElement.className = 'scan-item';
            scanElement.innerHTML = `
                <h4>${scan}</h4>
                <small>Click to view details</small>
            `;
            scanElement.addEventListener('click', () => {
                window.location.href = `/scan/${scan}`;
            });
            container.appendChild(scanElement);
        });
    }

    updateStats() {
        document.getElementById('total-scans').textContent = this.scans.length;
        document.getElementById('last-scan').textContent = this.scans[0] || '-';
    }
}

// Инициализация приложения
document.addEventListener('DOMContentLoaded', () => {
    new DReconApp();
});