// Anti-inspect protection
(function() {
    // Disable right-click context menu
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        return false;
    });

    // Disable keyboard shortcuts for developer tools
    document.addEventListener('keydown', function(e) {
        // F12
        if (e.key === 'F12') {
            e.preventDefault();
            return false;
        }
        // Ctrl+Shift+I (Developer Tools)
        if (e.ctrlKey && e.shiftKey && e.key === 'I') {
            e.preventDefault();
            return false;
        }
        // Ctrl+Shift+J (Console)
        if (e.ctrlKey && e.shiftKey && e.key === 'J') {
            e.preventDefault();
            return false;
        }
        // Ctrl+U (View Source)
        if (e.ctrlKey && e.key === 'u') {
            e.preventDefault();
            return false;
        }
        // Ctrl+Shift+C (Inspector)
        if (e.ctrlKey && e.shiftKey && e.key === 'C') {
            e.preventDefault();
            return false;
        }
        // Ctrl+S (Save)
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            return false;
        }
        // Ctrl+P (Print)
        if (e.ctrlKey && e.key === 'p') {
            e.preventDefault();
            return false;
        }
        // Ctrl+Shift+E (Network)
        if (e.ctrlKey && e.shiftKey && e.key === 'E') {
            e.preventDefault();
            return false;
        }
    });

    // Detect developer tools and redirect/close
    function devToolsDetector() {
        const threshold = 160;
        const check = function() {
            const widthThreshold = window.outerWidth - window.innerWidth > threshold;
            const heightThreshold = window.outerHeight - window.innerHeight > threshold;
            
            if (widthThreshold || heightThreshold) {
                // Developer tools is open
                document.body.innerHTML = '<div style="background:#000;color:#ff0000;padding:50px;text-align:center;font-family:monospace;"><h1>Access Denied</h1><p>Developer tools detected. This application is protected.</p></div>';
                document.body.style.background = '#000';
            }
        };
        
        setInterval(check, 1000);
    }

    // Start detection
    devToolsDetector();
})();

window.onload = () => {
    // Check if user is logged in
    let isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    let currentUser = JSON.parse(localStorage.getItem('currentUser') || 'null');
    
    // DOM Elements
    const navbar = document.getElementById('navbar');
    const footer = document.getElementById('footer');
    const loginSection = document.getElementById('login');
    const registerSection = document.getElementById('register');
    const homeSection = document.getElementById('home');
    const showRegister = document.getElementById('showRegister');
    const showLogin = document.getElementById('showLogin');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const logoutBtn = document.getElementById('logoutBtn');
    
    // Show login page first if not logged in
    if (!isLoggedIn) {
        navbar.style.display = 'none';
        footer.style.display = 'none';
        loginSection.classList.add('active');
        homeSection.classList.remove('active');
    } else {
        navbar.style.display = 'flex';
        footer.style.display = 'block';
        loginSection.classList.remove('active');
        homeSection.classList.add('active');
    }
    
    // Toggle between Login and Register
    showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        loginSection.classList.remove('active');
        registerSection.classList.add('active');
    });
    
    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        registerSection.classList.remove('active');
        loginSection.classList.add('active');
    });
    
    // Login Form Handler
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        
        // Check stored users
        const users = JSON.parse(localStorage.getItem('users') || '[]');
        const user = users.find(u => (u.email === email || u.username === email) && u.password === password);
        
        if (user) {
            localStorage.setItem('isLoggedIn', 'true');
            localStorage.setItem('currentUser', JSON.stringify(user));
            navbar.style.display = 'flex';
            footer.style.display = 'block';
            loginSection.classList.remove('active');
            homeSection.classList.add('active');
            loginForm.reset();
        } else {
            alert('Invalid email/username or password!');
        }
    });
    
    // Register Form Handler
    registerForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const username = document.getElementById('regUsername').value;
        const email = document.getElementById('regEmail').value;
        const organisation = document.getElementById('regOrganisation').value;
        const city = document.getElementById('regCity').value;
        const password = document.getElementById('regPassword').value;
        const confirmPassword = document.getElementById('regConfirmPassword').value;
        
        // Validation
        if (password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }
        
        if (password.length < 6) {
            alert('Password must be at least 6 characters!');
            return;
        }
        
        // Check if user exists
        const users = JSON.parse(localStorage.getItem('users') || '[]');
        if (users.find(u => u.email === email || u.username === username)) {
            alert('User already exists!');
            return;
        }
        
        // Save new user
        const newUser = { username, email, organisation, city, password };
        users.push(newUser);
        localStorage.setItem('users', JSON.stringify(users));
        
        alert('Registration successful! Please login.');
        registerForm.reset();
        registerSection.classList.remove('active');
        loginSection.classList.add('active');
    });
    
    // Logout Handler
    logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        localStorage.setItem('isLoggedIn', 'false');
        localStorage.setItem('currentUser', 'null');
        navbar.style.display = 'none';
        footer.style.display = 'none';
        
        // Hide all scanner sections
        document.querySelectorAll('.scanner-section').forEach(section => {
            section.classList.remove('active');
        });
        
        loginSection.classList.add('active');
    });

    // ========== ORIGINAL APP CODE ==========
    
    const scanBtn = document.getElementById('scanBtn');
    const urlInput = document.getElementById('urlInput');
    const riskText = document.getElementById('riskText');
    const aiPopup = document.getElementById('aiSuggestion');
    const dropArea = document.getElementById('dropArea');
    const exportPdfBtn = document.getElementById('exportPdfBtn');
    const exportFilePdfBtn = document.getElementById('exportFilePdfBtn');

    // Stats variables
    let totalScans = 0;
    let highRiskCount = 0;
    let safeCount = 0;
    let suspiciousCount = 0;
    let scanHistory = [];
    let fileScanHistory = [];

    // Advanced threat databases
    const suspiciousTLDs = ['.xyz', '.top', '.click', '.loan', '.work', '.date', '.racing', '.science', '.cricket', '.win', '.download', '.bid', '.stream', '.trade', '.accountant'];
    const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'password', 'banking', 'signin', 'credential', 'authenticate', 'suspended', 'expire', 'unusual', 'alert'];
    const trustedDomains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'twitter.com', 'github.com', 'linkedin.com', 'paypal.com', 'netflix.com'];
    const phishingKeywords = ['free', 'winner', 'lottery', 'prize', 'claim', 'reward', 'gift', 'bitcoin', 'crypto', 'investment', 'opportunity'];
    const malwareDomains = ['malware-test.com', 'phishing-example.com', 'suspicious-site.net'];

    // Security tips database
    const securityTips = {
        https: 'Always ensure websites use HTTPS encryption. Install a browser extension like HTTPS Everywhere for automatic HTTPS enforcement.',
        characters: 'Be wary of URLs with special characters like @, %, or hidden characters. Attackers use these to disguise malicious links.',
        ipAddress: 'Legitimate websites use domain names, not IP addresses. Avoid clicking on URLs that use raw IP addresses.',
        suspiciousTLD: 'Suspicious top-level domains (.xyz, .top, .click) are commonly used by scammers. Be extra cautious with these.',
        keywords: 'Phishing sites often use urgent keywords like "verify", "login", "secure" to trick users. Always verify the sender.',
        phishing: 'Keywords like "free", "winner", "lottery" are red flags. Never trust offers that seem too good to be true.',
        length: 'Unusually long URLs often indicate obfuscation. Shorten URLs before clicking using a URL shortener service.',
        obfuscation: 'The @ symbol in URLs can trick users into visiting malicious sites. Always check the actual destination.',
        subdomains: 'Many subdomains can indicate a fake site. Check the main domain carefully.',
        malware: 'This domain is known for malware distribution. Do not visit this site and ensure your antivirus is updated.'
    };

    const barCtx = document.getElementById('riskBarChart').getContext('2d');
    const dashBarCtx = document.getElementById('dashboardBarChart')?.getContext('2d');

    // Risk Level Bar Chart
    let riskBarChart = new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: ['Safe', 'Suspicious'],
            datasets: [{
                label: 'URL Count',
                data: [0, 0],
                backgroundColor: ['#00aa00', '#ff0000'],
                borderColor: ['#00ff00', '#ff4444'],
                borderWidth: 2,
                borderRadius: 6,
                barThickness: 50
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                title: {
                    display: true,
                    text: 'Risk Assessment Results',
                    color: '#ff0000',
                    font: { size: 14 }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#888' },
                    grid: { color: '#333' }
                },
                x: {
                    ticks: { color: '#888', font: { size: 11 } },
                    grid: { display: false }
                }
            }
        }
    });

    // Dashboard Bar Chart (horizontal)
    let dashboardBarChart = null;
    if (dashBarCtx) {
        dashboardBarChart = new Chart(dashBarCtx, {
            type: 'bar',
            data: {
                labels: ['Safe', 'Suspicious', 'High Risk'],
                datasets: [{
                    label: 'Count',
                    data: [0, 0, 0],
                    backgroundColor: ['#00aa00', '#ffaa00', '#ff0000'],
                    borderColor: ['#00ff00', '#ffcc00', '#ff4444'],
                    borderWidth: 1,
                    borderRadius: 4,
                    barThickness: 25
                }]
            },
            options: {
                responsive: true,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { color: '#888' }, grid: { color: '#333' } },
                    y: { ticks: { color: '#888', font: { size: 11 } }, grid: { display: false } }
                }
            }
        });
    }

    // Navigation functionality
    const navLinks = document.querySelectorAll('.nav-link');
    const scannerSections = document.querySelectorAll('.scanner-section');
    const toolCards = document.querySelectorAll('.tool-card');
    const backBtns = document.querySelectorAll('.back-btn');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            if (link.getAttribute('href') === '#') e.preventDefault();
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            scannerSections.forEach(section => section.classList.remove('active'));
            const targetId = link.getAttribute('data-target');
            if (targetId) document.getElementById(targetId).classList.add('active');
        });
    });

    toolCards.forEach(card => {
        card.addEventListener('click', () => {
            const toolName = card.getAttribute('data-tool');
            document.getElementById('home').classList.remove('active');
            document.getElementById(toolName).classList.add('active');
        });
    });

    backBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            scannerSections.forEach(section => section.classList.remove('active'));
            document.getElementById('home').classList.add('active');
            navLinks.forEach(l => l.classList.remove('active'));
            document.querySelector('[data-target="home"]').classList.add('active');
        });
    });

    // Footer links handler for Privacy Policy and Terms of Service
    const footerLinks = document.querySelectorAll('.footer-link');
    footerLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('data-target');
            if (targetId) {
                scannerSections.forEach(section => section.classList.remove('active'));
                document.getElementById(targetId).classList.add('active');
                navLinks.forEach(l => l.classList.remove('active'));
            }
        });
    });

    // Drag & Drop
    dropArea.addEventListener('dragover', e => { e.preventDefault(); dropArea.classList.add('hover'); });
    dropArea.addEventListener('dragleave', e => { e.preventDefault(); dropArea.classList.remove('hover'); });
    dropArea.addEventListener('drop', e => {
        e.preventDefault(); dropArea.classList.remove('hover');
        const files = e.dataTransfer.files;
        for (let f of files) {
            const reader = new FileReader();
            reader.onload = () => { urlInput.value += reader.result + "\n"; };
            reader.readAsText(f);
        }
    });

    // Press Enter to scan (not create new line)
    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            scanBtn.click();
        }
    });

    // Advanced URL Analysis
    function analyzeURL(url) {
        const analysis = { url: url, checks: [], riskScore: 0, maxScore: 100, indicators: [], details: {}, tips: [] };

        const hasHTTPS = url.startsWith('https://');
        analysis.checks.push({ name: 'HTTPS', status: hasHTTPS ? 'pass' : 'fail', description: hasHTTPS ? 'Encrypted' : 'Not encrypted', tip: securityTips.https });
        if (!hasHTTPS) analysis.riskScore += 20;

        if (/[@%]/.test(url)) {
            analysis.checks.push({ name: 'Characters', status: 'fail', description: 'Suspicious characters', tip: securityTips.characters });
            analysis.riskScore += 15;
        }

        if (/(\d{1,3}\.){3}\d{1,3}/.test(url)) {
            analysis.checks.push({ name: 'Domain', status: 'fail', description: 'Uses IP address', tip: securityTips.ipAddress });
            analysis.riskScore += 25;
        }

        const urlLower = url.toLowerCase();
        if (suspiciousTLDs.some(tld => urlLower.includes(tld))) {
            analysis.checks.push({ name: 'TLD', status: 'warning', description: 'Suspicious TLD', tip: securityTips.suspiciousTLD });
            analysis.riskScore += 15;
        }

        const found = suspiciousKeywords.filter(kw => urlLower.includes(kw));
        if (found.length > 0) {
            analysis.checks.push({ name: 'Keywords', status: 'warning', description: `Found: ${found.join(', ')}`, tip: securityTips.keywords });
            analysis.riskScore += found.length * 8;
        }

        const phishFound = phishingKeywords.filter(kw => urlLower.includes(kw));
        if (phishFound.length > 0) {
            analysis.checks.push({ name: 'Phishing', status: 'fail', description: `Found: ${phishFound.join(', ')}`, tip: securityTips.phishing });
            analysis.riskScore += phishFound.length * 10;
        }

        if (url.length > 100) {
            analysis.checks.push({ name: 'Length', status: 'warning', description: 'Unusually long', tip: securityTips.length });
            analysis.riskScore += 10;
        }

        const isMalware = malwareDomains.some(d => urlLower.includes(d));
        const isTrusted = trustedDomains.some(d => urlLower.includes(d));
        if (isMalware) {
            analysis.checks.push({ name: 'Reputation', status: 'fail', description: 'Known malware', tip: securityTips.malware });
            analysis.riskScore += 50;
        } else if (isTrusted) {
            analysis.checks.push({ name: 'Reputation', status: 'pass', description: 'Trusted domain' });
        }

        if (url.includes('@')) {
            analysis.checks.push({ name: 'Obfuscation', status: 'fail', description: '@ symbol detected', tip: securityTips.obfuscation });
            analysis.riskScore += 25;
        }

        const dotCount = (url.match(/\./g) || []).length;
        if (dotCount > 3) {
            analysis.checks.push({ name: 'Subdomains', status: 'warning', description: 'Many subdomains', tip: securityTips.subdomains });
            analysis.riskScore += 10;
        }

        analysis.riskScore = Math.min(analysis.riskScore, 100);
        analysis.riskLevel = analysis.riskScore >= 50 ? 'High' : (analysis.riskScore >= 25 ? 'Medium' : 'Low');
        
        // Generate summary
        analysis.summary = generateURLSummary(analysis);
        
        return analysis;
    }

    function generateURLSummary(analysis) {
        let summary = '';
        if (analysis.riskLevel === 'Low') {
            summary = 'This URL appears to be safe. It uses proper HTTPS encryption and does not contain suspicious indicators commonly associated with phishing or malware sites.';
        } else if (analysis.riskLevel === 'Medium') {
            summary = 'This URL has some suspicious characteristics. It may contain potentially dangerous keywords or unusual URL patterns. Exercise caution when visiting this site.';
        } else {
            summary = '⚠️ HIGH RISK DETECTED! This URL exhibits multiple dangerous characteristics commonly found in phishing and malware sites. Do NOT visit this website.';
        }
        return summary;
    }

    function displayDetailedResults(analyses) {
        let html = '<div class="detailed-results">';
        
        // Summary section
        const highRisk = analyses.filter(a => a.riskLevel === 'High').length;
        const mediumRisk = analyses.filter(a => a.riskLevel === 'Medium').length;
        const lowRisk = analyses.filter(a => a.riskLevel === 'Low').length;
        
        html += `<div class="scan-summary" style="background: linear-gradient(135deg, #1a1a2e, #16213e); border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #333;">
            <h3 style="color: #ff3333; margin: 0 0 15px 0; font-size: 18px;">📊 Scan Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; text-align: center;">
                <div style="background: rgba(0,170,0,0.1); padding: 12px; border-radius: 8px;">
                    <div style="font-size: 24px; color: #00aa00; font-weight: bold;">${lowRisk}</div>
                    <div style="color: #888; font-size: 12px;">Safe</div>
                </div>
                <div style="background: rgba(255,170,0,0.1); padding: 12px; border-radius: 8px;">
                    <div style="font-size: 24px; color: #ffaa00; font-weight: bold;">${mediumRisk}</div>
                    <div style="color: #888; font-size: 12px;">Medium Risk</div>
                </div>
                <div style="background: rgba(255,0,0,0.1); padding: 12px; border-radius: 8px;">
                    <div style="font-size: 24px; color: #ff3333; font-weight: bold;">${highRisk}</div>
                    <div style="color: #888; font-size: 12px;">High Risk</div>
                </div>
            </div>
        </div>`;
        
        analyses.forEach(analysis => {
            const riskColor = analysis.riskLevel === 'High' ? '#ff3333' : (analysis.riskLevel === 'Medium' ? '#ffaa00' : '#00aa00');
            const riskBg = analysis.riskLevel === 'High' ? 'rgba(255,0,0,0.1)' : (analysis.riskLevel === 'Medium' ? 'rgba(255,170,0,0.1)' : 'rgba(0,170,0,0.1)');
            html += `<div class="url-analysis" style="background: ${riskBg}; border-left: 4px solid ${riskColor}; margin: 10px 0; padding: 15px; border-radius: 8px;">
                <h4 style="color: ${riskColor}; margin: 0 0 10px 0; font-size: 16px;">${analysis.riskLevel} Risk (${analysis.riskScore}%) - ${analysis.url.substring(0, 50)}${analysis.url.length > 50 ? '...' : ''}</h4>
                <p style="color: #888; font-size: 12px; word-break: break-all; margin-bottom: 12px;">${analysis.url}</p>
                
                <div style="background: #151515; padding: 12px; border-radius: 8px; margin-bottom: 12px;">
                    <h5 style="color: #ff3333; margin: 0 0 8px 0; font-size: 13px;">📋 Analysis Summary</h5>
                    <p style="color: #aaa; font-size: 12px; line-height: 1.6;">${analysis.summary}</p>
                </div>
                
                <div class="checks-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; margin-bottom: 12px;">`;
            analysis.checks.forEach(check => {
                const cColor = check.status === 'pass' ? '#00aa00' : (check.status === 'warning' ? '#ffaa00' : '#ff3333');
                const icon = check.status === 'pass' ? '✓' : (check.status === 'warning' ? '⚠' : '✗');
                html += `<div style="background: #1a1a1a; padding: 10px; border-radius: 6px;">
                    <span style="color: ${cColor}; font-weight: bold; font-size: 12px;">${icon} ${check.name}</span>
                    <p style="color: #666; font-size: 10px; margin: 4px 0 0 0;">${check.description}</p>
                </div>`;
            });
            html += '</div>';
            
            // Security tips
            const tips = analysis.checks.filter(c => c.tip).map(c => c.tip);
            if (tips.length > 0) {
                html += `<div style="background: rgba(255,51,51,0.1); padding: 12px; border-radius: 8px; border: 1px solid rgba(255,51,51,0.3);">
                    <h5 style="color: #ff3333; margin: 0 0 8px 0; font-size: 13px;">🛡️ Security Tips</h5>
                    <ul style="color: #aaa; font-size: 11px; margin: 0; padding-left: 20px; line-height: 1.8;">`;
                tips.forEach(tip => {
                    html += `<li>${tip}</li>`;
                });
                html += '</ul></div>';
            }
            html += '</div>';
        });
        html += '</div>';
        const riskMeter = document.getElementById('riskMeter');
        const existing = document.querySelector('.detailed-results');
        if (existing) existing.remove();
        riskMeter.insertAdjacentHTML('afterend', html);
    }

    function showScanProgress() {
        const progress = document.getElementById('scanProgress');
        progress.classList.add('active');
        const steps = ['step1', 'step2', 'step3', 'step4'];
        const progressFill = document.getElementById('progressFill');
        let currentStep = 0;
        progressFill.style.width = '0%';
        const interval = setInterval(() => {
            if (currentStep > 0) document.getElementById(steps[currentStep - 1]).classList.add('completed');
            if (currentStep < steps.length) {
                document.getElementById(steps[currentStep]).classList.add('active');
                progressFill.style.width = ((currentStep + 1) * 25) + '%';
                currentStep++;
            } else {
                clearInterval(interval);
                setTimeout(() => {
                    progress.classList.remove('active');
                    steps.forEach(step => document.getElementById(step).classList.remove('active', 'completed'));
                    progressFill.style.width = '0%';
                }, 500);
            }
        }, 600);
    }

    scanBtn.addEventListener('click', () => {
        const lines = urlInput.value.split('\n').filter(l=>l.trim());
        if(lines.length===0){ alert('Please enter URLs or content'); return; }
        showScanProgress();
        setTimeout(() => {
            let analyses = lines.map(url => analyzeURL(url));
            let safeCountLocal = 0, suspiciousCountLocal = 0;
            analyses.forEach(analysis => {
                if(analysis.riskLevel === 'Low') safeCountLocal++;
                else suspiciousCountLocal++;
            });

            riskBarChart.data.datasets[0].data = [safeCountLocal, suspiciousCountLocal];
            riskBarChart.update();
            displayDetailedResults(analyses);

            totalScans++;
            safeCount += safeCountLocal;
            suspiciousCount += suspiciousCountLocal;
            highRiskCount += analyses.filter(a => a.riskLevel === 'High').length;
            updateDashboard();

            scanHistory.push({
                id: 'URL-' + Date.now(),
                date: new Date().toLocaleString(),
                type: 'url',
                total: lines.length,
                safe: safeCountLocal,
                suspicious: suspiciousCountLocal,
                risk: suspiciousCountLocal > 0 ? 'High' : 'Low',
                analyses: analyses
            });
            updateReports();

            if(suspiciousCountLocal > 0){
                const riskPercentage = Math.round((suspiciousCountLocal / lines.length) * 100);
                riskText.innerText = `${riskPercentage}% RISK`;
                riskText.style.color = '#ff0000';
                aiPopup.style.display = 'block';
                const highRisk = analyses.filter(a => a.riskLevel === 'High').length;
                aiPopup.innerHTML = `🚨 <strong>${highRisk} High, ${suspiciousCountLocal - highRisk} Medium</strong> detected`;
            } else {
                riskText.innerText = 'SAFE ✅';
                riskText.style.color = '#00ff00';
                aiPopup.style.display = 'none';
                confetti({particleCount: 100, spread: 70, origin: {y: 0.6}});
            }
        }, 2500);
    });

    function updateDashboard() {
        document.getElementById('totalScans').innerText = totalScans;
        document.getElementById('highRiskCount').innerText = highRiskCount;
        document.getElementById('suspiciousCount').innerText = suspiciousCount;
        document.getElementById('safeCount').innerText = safeCount;

        if (dashboardBarChart) {
            dashboardBarChart.data.datasets[0].data = [safeCount, suspiciousCount, highRiskCount];
            dashboardBarChart.update();
        }

        const activityList = document.getElementById('activityList');
        if (scanHistory.length > 0 || fileScanHistory.length > 0) {
            let html = '';
            const allHistory = [...scanHistory, ...fileScanHistory].sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 5);
            allHistory.forEach(scan => {
                const riskClass = scan.risk === 'High' ? 'high' : 'low';
                html += `<div class="activity-item"><span>${scan.date}</span><span class="report-risk ${riskClass}">${scan.risk}</span><span>${scan.type === 'url' ? scan.total + ' URLs' : scan.total + ' Files'}</span></div>`;
            });
            activityList.innerHTML = html;
        }
    }

    function updateReports() {
        const reportsList = document.getElementById('reportsList');
        const allHistory = [...scanHistory, ...fileScanHistory].sort((a, b) => new Date(b.date) - new Date(a.date));
        
        if (allHistory.length > 0) {
            let html = '';
            allHistory.forEach((scan, index) => {
                const riskClass = scan.risk === 'High' ? 'high' : 'low';
                const typeIcon = scan.type === 'url' ? '🔍' : '📁';
                html += `<div class="report-item">
                    <div class="report-info">
                        <div class="report-name">${typeIcon} ${scan.id}</div>
                        <div class="report-date">${scan.date} - ${scan.type === 'url' ? 'URL Scan' : 'File Scan'}</div>
                    </div>
                    <div><span>${scan.safe} Safe, ${scan.suspicious} Risks</span></div>
                    <span class="report-risk ${riskClass}">${scan.risk}</span>
                    <button onclick="viewReport(${index})" class="view-report-btn">View</button>
                </div>`;
            });
            reportsList.innerHTML = html;
        }
    }

    // Enhanced PDF Export with detailed explanations
    exportPdfBtn.addEventListener('click', () => {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Header
        doc.setFillColor(26, 0, 0);
        doc.rect(0, 0, 210, 40, 'F');
        doc.setTextColor(255, 51, 51);
        doc.setFontSize(24);
        doc.text('AM CyberScan', 20, 20);
        doc.setFontSize(12);
        doc.setTextColor(255, 255, 255);
        doc.text('URL Security Scan Report', 20, 30);
        
        // Scan Info
        doc.setTextColor(0, 0, 0);
        doc.setFontSize(11);
        doc.text(`Scan ID: ${scanHistory[scanHistory.length-1]?.id || 'N/A'}`, 20, 50);
        doc.text(`Date: ${new Date().toLocaleString()}`, 20, 57);
        
        const lines = urlInput.value.split('\n').filter(l=>l.trim());
        const analyses = lines.map(url => analyzeURL(url));
        const highRisk = analyses.filter(a => a.riskLevel === 'High').length;
        const mediumRisk = analyses.filter(a => a.riskLevel === 'Medium').length;
        const lowRisk = analyses.filter(a => a.riskLevel === 'Low').length;
        
        // Summary Box
        doc.setFillColor(240, 240, 240);
        doc.rect(15, 65, 180, 30, 'F');
        doc.setFontSize(12);
        doc.setTextColor(255, 51, 51);
        doc.text('SCAN SUMMARY', 20, 73);
        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        doc.text(`Total URLs Scanned: ${lines.length}`, 20, 82);
        doc.text(`High Risk: ${highRisk} | Medium Risk: ${mediumRisk} | Safe: ${lowRisk}`, 20, 89);
        
        // Detailed Analysis
        doc.setFontSize(14);
        doc.setTextColor(255, 51, 51);
        doc.text('DETAILED ANALYSIS', 20, 108);
        
        let yPos = 118;
        analyses.forEach((analysis) => {
            if (yPos > 250) { doc.addPage(); yPos = 20; }
            
            // URL and Risk Level
            const riskColor = analysis.riskLevel === 'High' ? [255, 0, 0] : (analysis.riskLevel === 'Medium' ? [255, 170, 0] : [0, 170, 0]);
            doc.setFontSize(11);
            doc.setTextColor(...riskColor);
            doc.text(`${analysis.riskLevel.toUpperCase()} RISK (${analysis.riskScore}%)`, 20, yPos);
            yPos += 6;
            
            doc.setFontSize(9);
            doc.setTextColor(100, 100, 100);
            doc.text(analysis.url.substring(0, 80), 20, yPos);
            yPos += 8;
            
            // Summary
            doc.setTextColor(0, 0, 0);
            const summaryLines = doc.splitTextToSize(analysis.summary, 170);
            doc.text(summaryLines, 20, yPos);
            yPos += summaryLines.length * 5 + 5;
            
            // Check Results
            doc.setFontSize(10);
            doc.setTextColor(255, 51, 51);
            doc.text('Check Results:', 20, yPos);
            yPos += 6;
            
            analysis.checks.forEach(check => {
                if (yPos > 280) { doc.addPage(); yPos = 20; }
                const cColor = check.status === 'pass' ? [0, 170, 0] : (check.status === 'warning' ? [255, 170, 0] : [255, 0, 0]);
                doc.setFontSize(8);
                doc.setTextColor(...cColor);
                const icon = check.status === 'pass' ? '[PASS]' : (check.status === 'warning' ? '[WARNING]' : '[FAIL]');
                doc.text(`${icon} ${check.name}: ${check.description}`, 25, yPos);
                yPos += 5;
            });
            yPos += 5;
            
            // Security Tips
            const tips = analysis.checks.filter(c => c.tip);
            if (tips.length > 0) {
                if (yPos > 250) { doc.addPage(); yPos = 20; }
                doc.setFontSize(9);
                doc.setTextColor(255, 51, 51);
                doc.text('Security Tips:', 20, yPos);
                yPos += 5;
                tips.forEach(tip => {
                    if (yPos > 280) { doc.addPage(); yPos = 20; }
                    doc.setFontSize(7);
                    doc.setTextColor(100, 100, 100);
                    const tipLines = doc.splitTextToSize('• ' + tip.tip, 165);
                    doc.text(tipLines, 25, yPos);
                    yPos += tipLines.length * 4;
                });
            }
            yPos += 10;
        });
        
        // Footer
        doc.setFontSize(8);
        doc.setTextColor(150, 150, 150);
        doc.text('Generated by AM CyberScan - Stay Safe Online!', 20, 290);
        doc.save("AMCyberScan_URL_Report.pdf");
    });

    // FILE SCANNER
    const fileInput = document.getElementById('fileInput');
    const fileDropArea = document.getElementById('fileDropArea');
    const scanFileBtn = document.getElementById('scanFileBtn');
    const fileResults = document.getElementById('fileResults');
    const maxFileSizeInput = document.getElementById('maxFileSize');

    const malwareDatabase = { 'sha256': ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'], 'md5': ['d41d8cd98f00b204e9800998ecf8427e'] };
    const dangerousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.pif', '.com', '.jar', '.js', '.jse', '.vbe', '.msi', '.dll'];
    const suspiciousExtensions = ['.zip', '.rar', '.7z', '.doc', '.docm', '.xls', '.xlsm', '.pdf', '.ppt', '.pptm', '.html', '.htm'];

    // File security tips
    const fileSecurityTips = {
        dangerous: 'This file type is commonly used by malware. Never execute .exe, .scr, .bat files from unknown sources. Delete immediately.',
        suspicious: 'This file type can contain macros or scripts that may be malicious. Scan thoroughly and disable macros before opening.',
        largeFile: 'Unusually large files may contain hidden malware or be used in DDoS attacks. Verify the source before processing.',
        highEntropy: 'High entropy suggests the file may be packed or encrypted, often used to hide malware. Exercise extreme caution.',
        malwareMatch: '⚠️ This file matches known malware signatures! Delete immediately and run a full system scan.',
        sizeWarning: 'Files exceeding the size limit may be used to cause system issues or contain embedded malware.'
    };

    function showFileScanProgress() {
        const progress = document.getElementById('fileScanProgress');
        progress.classList.add('active');
        const steps = ['fstep1', 'fstep2', 'fstep3', 'fstep4'];
        const progressFill = document.getElementById('fileProgressFill');
        let currentStep = 0;
        progressFill.style.width = '0%';
        const interval = setInterval(() => {
            if (currentStep > 0) document.getElementById(steps[currentStep - 1]).classList.add('completed');
            if (currentStep < steps.length) {
                document.getElementById(steps[currentStep]).classList.add('active');
                progressFill.style.width = ((currentStep + 1) * 25) + '%';
                currentStep++;
            } else {
                clearInterval(interval);
                setTimeout(() => {
                    progress.classList.remove('active');
                    steps.forEach(step => document.getElementById(step).classList.remove('active', 'completed'));
                    progressFill.style.width = '0%';
                }, 500);
            }
        }, 500);
    }

    fileDropArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => { fileDropArea.innerText = `Selected: ${Array.from(fileInput.files).map(f => f.name).join(', ')}`; });
    fileDropArea.addEventListener('dragover', e => { e.preventDefault(); fileDropArea.classList.add('hover'); });
    fileDropArea.addEventListener('dragleave', e => { e.preventDefault(); fileDropArea.classList.remove('hover'); });
    fileDropArea.addEventListener('drop', e => { e.preventDefault(); fileDropArea.classList.remove('hover'); fileDropArea.innerText = `Selected: ${Array.from(e.dataTransfer.files).map(f => f.name).join(', ')}`; });

    async function generateHash(buffer, algorithm) {
        const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function analyzeFile(file) {
        const analysis = { name: file.name, size: file.size, type: 'Unknown', risk: 'safe', message: '', hash: {}, indicators: [], metadata: {}, checks: [], tips: [], summary: '' };
        const ext = '.' + file.name.split('.').pop().toLowerCase();
        analysis.type = ext;

        const maxSize = parseInt(maxFileSizeInput.value) * 1024 * 1024;
        if (file.size > maxSize) {
            analysis.checks.push({ name: 'File Size', status: 'warning', description: `Exceeds ${maxFileSizeInput.value} MB limit`, tip: fileSecurityTips.sizeWarning });
            if (analysis.risk !== 'danger') analysis.risk = 'warning';
        } else {
            analysis.checks.push({ name: 'File Size', status: 'pass', description: 'Within acceptable limits' });
        }

        if (dangerousExtensions.includes(ext)) {
            analysis.checks.push({ name: 'File Type', status: 'danger', description: `Dangerous: ${ext} - Executable file`, tip: fileSecurityTips.dangerous });
            analysis.risk = 'danger';
        } else if (suspiciousExtensions.includes(ext)) {
            analysis.checks.push({ name: 'File Type', status: 'warning', description: `Suspicious: ${ext} - May contain macros`, tip: fileSecurityTips.suspicious });
            if (analysis.risk !== 'danger') analysis.risk = 'warning';
        } else {
            analysis.checks.push({ name: 'File Type', status: 'pass', description: 'Standard file type' });
        }

        try {
            const buffer = await file.arrayBuffer();
            analysis.hash.sha256 = await generateHash(buffer, 'SHA-256');
            analysis.hash.md5 = await generateHash(buffer, 'MD5');
            analysis.checks.push({ name: 'Hash', status: 'pass', description: 'SHA-256 & MD5 generated' });

            if (malwareDatabase.sha256.includes(analysis.hash.sha256)) {
                analysis.checks.push({ name: 'Malware DB', status: 'danger', description: '⚠️ MATCH FOUND IN MALWARE DATABASE!', tip: fileSecurityTips.malwareMatch });
                analysis.risk = 'danger';
            } else {
                analysis.checks.push({ name: 'Malware DB', status: 'pass', description: 'No match found' });
            }

            const entropy = calculateEntropy(new Uint8Array(buffer));
            analysis.metadata.entropy = entropy.toFixed(2);
            if (entropy > 7.5) {
                analysis.checks.push({ name: 'Entropy', status: 'warning', description: `High entropy: ${entropy.toFixed(2)} (possibly packed/encrypted)`, tip: fileSecurityTips.highEntropy });
                if (analysis.risk !== 'danger') analysis.risk = 'warning';
            } else {
                analysis.checks.push({ name: 'Entropy', status: 'pass', description: `Normal entropy: ${entropy.toFixed(2)}` });
            }
        } catch (err) {
            analysis.checks.push({ name: 'Error', status: 'fail', description: err.message });
        }

        // Generate summary
        if (analysis.risk === 'danger') {
            analysis.summary = '⚠️ DANGER! This file has been identified as potentially malicious. It contains dangerous characteristics or matches known malware signatures. DO NOT open or execute this file. Delete immediately and run a full antivirus scan.';
        } else if (analysis.risk === 'warning') {
            analysis.summary = '⚠️ CAUTION: This file has some suspicious characteristics. While not definitively malicious, it should be handled with care. Disable macros if opening document files and avoid executing any scripts.';
        } else {
            analysis.summary = '✅ This file appears to be safe. It does not contain dangerous extensions, is within size limits, and shows no signs of being packed or encrypted. However, always verify the source before opening.';
        }

        analysis.message = analysis.risk === 'danger' ? '⚠️ DANGER!' : (analysis.risk === 'warning' ? '⚠️ CAUTION' : '✅ SAFE');
        return analysis;
    }

    function calculateEntropy(data) {
        const frequency = {};
        for (const byte of data) frequency[byte] = (frequency[byte] || 0) + 1;
        let entropy = 0;
        for (const byte in frequency) entropy -= (frequency[byte] / data.length) * Math.log2(frequency[byte] / data.length);
        return entropy;
    }

    scanFileBtn.addEventListener('click', async () => {
        if (fileInput.files.length === 0) { fileResults.innerHTML = '<div class="file-error">Select files first</div>'; return; }
        showFileScanProgress();
        setTimeout(async () => {
            let resultsHTML = '<div class="file-results-header"><h3>Analysis Results</h3></div>';
            let fileAnalyses = [];
            
            for (let file of fileInput.files) {
                const a = await analyzeFile(file);
                fileAnalyses.push(a);
                const color = a.risk === 'danger' ? '#ff3333' : (a.risk === 'warning' ? '#ffaa00' : '#00aa00');
                resultsHTML += `<div class="file-result-item ${a.risk}" style="border-color: ${color}; margin: 10px 0; padding: 15px; border-radius: 10px; border: 1px solid;">
                    <div style="color: ${color}; font-weight: bold; font-size: 16px; margin-bottom: 8px;">${a.name}</div>
                    <div style="font-size: 11px; color: #888; margin-bottom: 8px;">Size: ${(a.size/1024).toFixed(2)} KB | Type: ${a.type}</div>
                    
                    <div style="background: #151515; padding: 10px; border-radius: 6px; margin-bottom: 8px;">
                        <div style="font-size: 11px; color: #ff3333; margin-bottom: 5px;">📋 Analysis Summary:</div>
                        <div style="font-size: 11px; color: #aaa; line-height: 1.5;">${a.summary}</div>
                    </div>
                    
                    <div style="font-size: 10px; color: #666; margin-bottom: 5px;">SHA-256: <span style="font-family: monospace; word-break: break-all;">${a.hash.sha256 || 'N/A'}</span></div>
                    <div style="font-size: 10px; color: #666; margin-bottom: 8px;">MD5: <span style="font-family: monospace;">${a.hash.md5 || 'N/A'}</span></div>
                    
                    <div style="font-size: 10px; color: #666; margin-bottom: 8px;">${a.checks.map(c => `<span style="color:${c.status==='pass'?'#00aa00':(c.status==='warning'?'#ffaa00':'#ff3333')}">${c.status==='pass'?'✓':(c.status==='warning'?'⚠':'✗')} ${c.name}</span>`).join(' | ')}</div>`;
                
                // Add security tips
                const tips = a.checks.filter(c => c.tip);
                if (tips.length > 0) {
                    resultsHTML += `<div style="background: rgba(255,51,51,0.1); padding: 10px; border-radius: 6px; border: 1px solid rgba(255,51,51,0.3);">
                        <div style="font-size: 11px; color: #ff3333; margin-bottom: 5px;">🛡️ Security Recommendations:</div>
                        <ul style="font-size: 10px; color: #aaa; margin: 0; padding-left: 15px; line-height: 1.6;">`;
                    tips.forEach(tip => {
                        resultsHTML += `<li>${tip.tip}</li>`;
                    });
                    resultsHTML += '</ul></div>';
                }
                
                resultsHTML += `<div style="margin-top: 10px; padding: 10px; border-radius: 6px; text-align: center; color: #fff; background: ${color}; font-weight: bold;">${a.message}</div>
                </div>`;
            }
            fileResults.innerHTML = resultsHTML;
            
            // Store in history
            let safeCountLocal = fileAnalyses.filter(a => a.risk === 'safe').length;
            let suspiciousCountLocal = fileAnalyses.filter(a => a.risk !== 'safe').length;
            
            fileScanHistory.push({
                id: 'FILE-' + Date.now(),
                date: new Date().toLocaleString(),
                type: 'file',
                total: fileAnalyses.length,
                safe: safeCountLocal,
                suspicious: suspiciousCountLocal,
                risk: suspiciousCountLocal > 0 ? 'High' : 'Low',
                analyses: fileAnalyses
            });
            
            updateDashboard();
            updateReports();
        }, 2200);
    });

    // File PDF Export with detailed explanations
    exportFilePdfBtn.addEventListener('click', () => {
        if (fileScanHistory.length === 0) {
            alert('No file scan results to export. Please scan files first.');
            return;
        }
        
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Get latest file scan
        const latestScan = fileScanHistory[fileScanHistory.length - 1];
        
        // Header
        doc.setFillColor(26, 0, 0);
        doc.rect(0, 0, 210, 40, 'F');
        doc.setTextColor(255, 51, 51);
        doc.setFontSize(24);
        doc.text('AM CyberScan', 20, 20);
        doc.setFontSize(12);
        doc.setTextColor(255, 255, 255);
        doc.text('File Security Scan Report', 20, 30);
        
        // Scan Info
        doc.setTextColor(0, 0, 0);
        doc.setFontSize(11);
        doc.text(`Scan ID: ${latestScan.id}`, 20, 50);
        doc.text(`Date: ${latestScan.date}`, 20, 57);
        
        const highRisk = latestScan.analyses.filter(a => a.risk === 'danger').length;
        const warningRisk = latestScan.analyses.filter(a => a.risk === 'warning').length;
        const safeRisk = latestScan.analyses.filter(a => a.risk === 'safe').length;
        
        // Summary Box
        doc.setFillColor(240, 240, 240);
        doc.rect(15, 65, 180, 30, 'F');
        doc.setFontSize(12);
        doc.setTextColor(255, 51, 51);
        doc.text('SCAN SUMMARY', 20, 73);
        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        doc.text(`Total Files Scanned: ${latestScan.total}`, 20, 82);
        doc.text(`Dangerous: ${highRisk} | Warnings: ${warningRisk} | Safe: ${safeRisk}`, 20, 89);
        
        // Detailed Analysis
        doc.setFontSize(14);
        doc.setTextColor(255, 51, 51);
        doc.text('DETAILED FILE ANALYSIS', 20, 108);
        
        let yPos = 118;
        latestScan.analyses.forEach((analysis) => {
            if (yPos > 250) { doc.addPage(); yPos = 20; }
            
            // File name and risk
            const riskColor = analysis.risk === 'danger' ? [255, 0, 0] : (analysis.risk === 'warning' ? [255, 170, 0] : [0, 170, 0]);
            doc.setFontSize(12);
            doc.setTextColor(...riskColor);
            doc.text(`${analysis.risk.toUpperCase()} - ${analysis.name}`, 20, yPos);
            yPos += 8;
            
            // File info
            doc.setFontSize(9);
            doc.setTextColor(100, 100, 100);
            doc.text(`Size: ${(analysis.size/1024).toFixed(2)} KB | Type: ${analysis.type}`, 20, yPos);
            yPos += 8;
            
            // Hash values
            doc.setTextColor(0, 0, 0);
            doc.text('SHA-256: ' + (analysis.hash.sha256 || 'N/A').substring(0, 50), 20, yPos);
            yPos += 5;
            doc.text('MD5: ' + (analysis.hash.md5 || 'N/A').substring(0, 50), 20, yPos);
            yPos += 10;
            
            // Summary
            doc.setFillColor(245, 245, 245);
            doc.rect(15, yPos - 3, 180, 15, 'F');
            doc.setFontSize(9);
            doc.setTextColor(0, 0, 0);
            doc.text('Analysis:', 20, yPos + 4);
            yPos += 12;
            
            const summaryLines = doc.splitTextToSize(analysis.summary, 170);
            doc.setFontSize(8);
            doc.text(summaryLines, 20, yPos);
            yPos += summaryLines.length * 4 + 8;
            
            // Check Results
            doc.setFontSize(10);
            doc.setTextColor(255, 51, 51);
            doc.text('Security Checks:', 20, yPos);
            yPos += 6;
            
            analysis.checks.forEach(check => {
                if (yPos > 280) { doc.addPage(); yPos = 20; }
                const cColor = check.status === 'pass' ? [0, 170, 0] : (check.status === 'warning' ? [255, 170, 0] : [255, 0, 0]);
                doc.setFontSize(8);
                doc.setTextColor(...cColor);
                const icon = check.status === 'pass' ? '[PASS]' : (check.status === 'warning' ? '[WARNING]' : '[FAIL]');
                doc.text(`${icon} ${check.name}: ${check.description}`, 25, yPos);
                yPos += 5;
            });
            yPos += 5;
            
            // Security Tips
            const tips = analysis.checks.filter(c => c.tip);
            if (tips.length > 0) {
                if (yPos > 250) { doc.addPage(); yPos = 20; }
                doc.setFontSize(10);
                doc.setTextColor(255, 51, 51);
                doc.text('Security Recommendations:', 20, yPos);
                yPos += 6;
                tips.forEach(tip => {
                    if (yPos > 280) { doc.addPage(); yPos = 20; }
                    doc.setFontSize(7);
                    doc.setTextColor(100, 100, 100);
                    const tipLines = doc.splitTextToSize('• ' + tip.tip, 165);
                    doc.text(tipLines, 25, yPos);
                    yPos += tipLines.length * 4;
                });
            }
            yPos += 15;
        });
        
        // Footer
        doc.setFontSize(8);
        doc.setTextColor(150, 150, 150);
        doc.text('Generated by AM CyberScan - Stay Safe Online!', 20, 290);
        doc.save("AMCyberScan_File_Report.pdf");
    });

    window.viewReport = function(index) {
        const allHistory = [...scanHistory, ...fileScanHistory].sort((a, b) => new Date(b.date) - new Date(a.date));
        const scan = allHistory[index];
        
        if (scan && scan.analyses) {
            if (scan.type === 'url') {
                displayDetailedResults(scan.analyses);
            } else {
                // Display file results
                let html = '<div class="detailed-results">';
                scan.analyses.forEach(analysis => {
                    const color = analysis.risk === 'danger' ? '#ff3333' : (analysis.risk === 'warning' ? '#ffaa00' : '#00aa00');
                    html += `<div class="file-result-item" style="border-color: ${color}; margin: 10px 0; padding: 15px; border-radius: 10px; border: 1px solid;">
                        <div style="color: ${color}; font-weight: bold; font-size: 16px;">${analysis.name}</div>
                        <div style="font-size: 12px; color: #888; margin: 8px 0;">${analysis.summary}</div>
                        <div style="font-size: 11px;">${analysis.checks.map(c => `<span style="color:${c.status==='pass'?'#00aa00':(c.status==='warning'?'#ffaa00':'#ff3333')}">${c.status==='pass'?'✓':(c.status==='warning'?'⚠':'✗')} ${c.name}</span>`).join(' | ')}</div>
                    </div>`;
                });
                html += '</div>';
                
                const riskMeter = document.getElementById('riskMeter');
                const existing = document.querySelector('.detailed-results');
                if (existing) existing.remove();
                riskMeter.insertAdjacentHTML('afterend', html);
            }
            document.getElementById('reports').classList.remove('active');
            document.getElementById('urlScanner').classList.add('active');
        }
    };
};
