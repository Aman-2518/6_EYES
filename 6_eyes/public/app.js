document.addEventListener('DOMContentLoaded', () => {
    // Initialize icons
    lucide.createIcons();

    // Elements
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const pageTitle = document.getElementById('page-title');
    const timeDisplay = document.getElementById('time-display');

    const scanForm = document.getElementById('scan-form');
    const scanTypeSelect = document.getElementById('scan_type');
    const singlePortGroup = document.getElementById('single-port-group');
    const rangePortGroup = document.getElementById('range-port-group');
    const btnStartScan = document.getElementById('btn-start-scan');

    const statusIdlePlaceholder = document.getElementById('status-idle-placeholder');
    const statusRunningLoader = document.getElementById('status-running-loader');
    const statusSummaryDashboard = document.getElementById('status-summary-dashboard');

    const targetsFeedbackPanel = document.getElementById('targets-feedback-panel');
    const targetChips = document.getElementById('target-chips');

    const resultsPanel = document.getElementById('results-panel');
    const resultsTbody = document.getElementById('results-tbody');
    const btnDownloadReport = document.getElementById('btn-download-report');

    const risksPanel = document.getElementById('risks-panel');
    const risksContainer = document.getElementById('risks-container');

    const reportsList = document.getElementById('reports-list');

    // System Time Updater
    setInterval(() => {
        const now = new Date();
        timeDisplay.textContent = now.toTimeString().split(' ')[0];
    }, 1000);

    // Tab Navigation
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            
            navButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(tc => tc.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`tab-${targetTab}`).classList.add('active');
            
            if (targetTab === 'scanner') {
                pageTitle.textContent = 'Scanner Dashboard';
            } else if (targetTab === 'reports') {
                pageTitle.textContent = 'Scan Reports';
                loadReportsList();
            }
        });
    });

    // Scan Type Conditional Inputs
    scanTypeSelect.addEventListener('change', (e) => {
        const value = e.target.value;
        if (value === '1') {
            singlePortGroup.classList.remove('show');
            rangePortGroup.classList.remove('show');
        } else if (value === '2') {
            singlePortGroup.classList.add('show');
            rangePortGroup.classList.remove('show');
        } else if (value === '3') {
            singlePortGroup.classList.remove('show');
            rangePortGroup.classList.add('show');
        }
    });

    // Form Submit (Trigger Scan)
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const target = document.getElementById('target').value.trim();
        const scan_type = parseInt(scanTypeSelect.value);
        const port = parseInt(document.getElementById('port').value);
        const start_port = parseInt(document.getElementById('start_port').value);
        const end_port = parseInt(document.getElementById('end_port').value);

        // Reset display
        statusIdlePlaceholder.classList.add('hidden');
        statusSummaryDashboard.classList.add('hidden');
        targetsFeedbackPanel.classList.add('hidden');
        resultsPanel.classList.add('hidden');
        risksPanel.classList.add('hidden');
        statusRunningLoader.classList.remove('hidden');
        btnStartScan.disabled = true;

        const bodyData = {
            target,
            scan_type
        };

        if (scan_type === 2) {
            bodyData.port = port;
        } else if (scan_type === 3) {
            bodyData.start_port = start_port;
            bodyData.end_port = end_port;
        }

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(bodyData)
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Failed to complete scan');
            }

            const data = await response.json();
            renderScanDashboard(data);

        } catch (error) {
            alert(`Scan Error: ${error.message}`);
            statusIdlePlaceholder.classList.remove('hidden');
        } finally {
            statusRunningLoader.classList.add('hidden');
            btnStartScan.disabled = false;
        }
    });

    // Render Dashboard Results
    function renderScanDashboard(data) {
        // Render target chips
        targetChips.innerHTML = '';
        data.targets.forEach(t => {
            const chip = document.createElement('div');
            chip.className = 'target-chip';
            chip.innerHTML = `
                <i data-lucide="server"></i>
                <span class="font-mono">${t.ip}</span>
                <span class="v-badge">IPv${t.version}</span>
                ${t.hostname ? `<span class="text-muted">(${t.hostname})</span>` : ''}
            `;
            targetChips.appendChild(chip);
        });
        targetsFeedbackPanel.classList.remove('hidden');

        // Score logic
        const score = data.security_score;
        document.getElementById('score-value').textContent = score;
        
        const ratingBadge = document.getElementById('security-rating');
        ratingBadge.className = 'score-badge';
        if (score >= 80) {
            ratingBadge.textContent = 'SECURE';
            ratingBadge.classList.add('secure');
        } else if (score >= 50) {
            ratingBadge.textContent = 'WARNING';
            ratingBadge.classList.add('warning');
        } else {
            ratingBadge.textContent = 'VULNERABLE';
            ratingBadge.classList.add('danger');
        }

        // SVG gauge offset: r=40 -> circumference = 2 * PI * 40 ≈ 251.2
        const circle = document.getElementById('score-gauge');
        const offset = 251.2 - (251.2 * score / 100);
        circle.style.strokeDashoffset = offset;

        if (score >= 80) {
            circle.style.stroke = 'var(--success)';
        } else if (score >= 50) {
            circle.style.stroke = 'var(--warning)';
        } else {
            circle.style.stroke = 'var(--danger)';
        }

        // Stats calculation
        const totalPorts = data.scan_results.length;
        const openPorts = data.scan_results.filter(r => r.state === 'OPEN').length;
        const closedPorts = totalPorts - openPorts;
        const highRisks = data.scan_results.filter(r => r.state === 'OPEN' && r.risk.risk === 'HIGH').length;

        document.getElementById('stat-open').textContent = openPorts;
        document.getElementById('stat-closed').textContent = closedPorts;
        document.getElementById('stat-high').textContent = highRisks;

        statusSummaryDashboard.classList.remove('hidden');

        // Table results
        resultsTbody.innerHTML = '';
        data.scan_results.forEach(r => {
            const tr = document.createElement('tr');
            
            const service = r.service || '-';
            const riskText = r.risk.risk || '-';
            const riskClass = riskText.toLowerCase();
            const banner = r.banner || 'Not Available';

            tr.innerHTML = `
                <td><span class="state-badge ${r.state.toLowerCase()}">${r.state}</span></td>
                <td class="font-mono">${r.port}</td>
                <td>${service}</td>
                <td><span class="risk-pill ${riskClass}">${riskText}</span></td>
                <td class="font-mono">${r.ip}</td>
                <td class="font-mono text-muted" style="font-size: 12px; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${banner}">${banner}</td>
            `;
            resultsTbody.appendChild(tr);
        });
        
        btnDownloadReport.href = `/api/reports/${data.report_file}`;
        resultsPanel.classList.remove('hidden');

        // Risks explanations
        const risksOpen = data.scan_results.filter(r => r.state === 'OPEN');
        risksContainer.innerHTML = '';
        
        if (risksOpen.length > 0) {
            risksOpen.forEach(r => {
                const rDiv = document.createElement('div');
                const riskLvl = r.risk.risk.toLowerCase();
                rDiv.className = `risk-item ${riskLvl}`;
                rDiv.innerHTML = `
                    <div class="risk-item-header">
                        <span class="risk-item-title">${r.service} on Port ${r.port}</span>
                        <span class="risk-pill ${riskLvl}">${r.risk.risk} Risk</span>
                    </div>
                    <p class="risk-item-desc">${r.risk.reason}</p>
                    <div class="recommendation-box">
                        <strong>Recommendation:</strong> ${r.risk.recommendation}
                    </div>
                `;
                risksContainer.appendChild(rDiv);
            });
            risksPanel.classList.remove('hidden');
        }

        lucide.createIcons();
    }

    // Load Reports List
    async function loadReportsList() {
        try {
            const response = await fetch('/api/reports');
            const list = await response.json();
            
            reportsList.innerHTML = '';
            if (list.length === 0) {
                reportsList.innerHTML = `
                    <div class="no-reports-msg">
                        <i data-lucide="folder-open"></i>
                        <span>No reports generated yet.</span>
                    </div>
                `;
                lucide.createIcons();
                return;
            }

            list.forEach(item => {
                const date = new Date(item.created * 1000);
                const dateStr = date.toLocaleString();
                const sizeKB = (item.size / 1024).toFixed(2) + ' KB';
                
                const row = document.createElement('div');
                row.className = 'report-item-row';
                row.innerHTML = `
                    <span class="report-filename">${item.filename}</span>
                    <span class="text-muted">${sizeKB}</span>
                    <span class="text-muted">${dateStr}</span>
                    <div style="text-align: right;">
                        <a href="/api/reports/${item.filename}" target="_blank" class="btn-secondary" style="display: inline-flex; padding: 6px 12px;">
                            <i data-lucide="download" style="width: 14px; height: 14px;"></i>
                            <span>View</span>
                        </a>
                    </div>
                `;
                reportsList.appendChild(row);
            });

            lucide.createIcons();
        } catch (error) {
            console.error('Failed to load reports list', error);
        }
    }
});
