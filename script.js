// Global variables
let scannedCount = 0;
let currentRequest = null;

// DOM elements
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const clearBtn = document.getElementById('clearBtn');
const loadingContainer = document.getElementById('loadingContainer');
const resultsContainer = document.getElementById('resultsContainer');
const scannedCountEl = document.getElementById('scannedCount');

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Set up event listeners
    setupEventListeners();
    
    // Load saved scan count
    loadScanCount();
    
    // Focus on input
    urlInput.focus();
});

function setupEventListeners() {
    // URL input events
    urlInput.addEventListener('input', handleInputChange);
    urlInput.addEventListener('keypress', handleKeyPress);
    
    // Button events
    scanBtn.addEventListener('click', scanUrl);
    clearBtn.addEventListener('click', clearInput);
    
    // Prevent form submission on enter
    urlInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            scanUrl();
        }
    });
}

function handleInputChange() {
    const hasValue = urlInput.value.trim().length > 0;
    clearBtn.style.opacity = hasValue ? '1' : '0';
    scanBtn.disabled = !hasValue;
}

function handleKeyPress(e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        scanUrl();
    }
}

function clearInput() {
    urlInput.value = '';
    urlInput.focus();
    handleInputChange();
    hideResults();
}

function testUrl(url) {
    urlInput.value = url;
    handleInputChange();
    scanUrl();
}

async function scanUrl() {
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a URL to scan');
        return;
    }
    
    // Cancel any ongoing request
    if (currentRequest) {
        currentRequest.abort();
    }
    
    // Show loading state
    showLoading();
    
    try {
        // Create new AbortController for this request
        const controller = new AbortController();
        currentRequest = controller;
        
        // Prepare form data
        const formData = new FormData();
        formData.append('url', url);
        
        // Make API request
        const response = await fetch('/predict', {
            method: 'POST',
            body: formData,
            signal: controller.signal
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        // Update scan count
        updateScanCount();
        
        // Show results
        showResults(result);
        
    } catch (error) {
        if (error.name === 'AbortError') {
            console.log('Request was cancelled');
        } else {
            console.error('Error scanning URL:', error);
            showError('Failed to scan URL. Please try again.');
        }
    } finally {
        hideLoading();
        currentRequest = null;
    }
}

function showLoading() {
    loadingContainer.style.display = 'block';
    resultsContainer.style.display = 'none';
    scanBtn.disabled = true;
    
    // Animate loading steps
    animateLoadingSteps();
}

function hideLoading() {
    loadingContainer.style.display = 'none';
    scanBtn.disabled = false;
    handleInputChange(); // Re-enable button if input has value
}

function animateLoadingSteps() {
    const steps = document.querySelectorAll('.loading-steps .step');
    let currentStep = 0;
    
    // Reset all steps
    steps.forEach(step => step.classList.remove('active'));
    
    const interval = setInterval(() => {
        if (currentStep < steps.length) {
            steps[currentStep].classList.add('active');
            if (currentStep > 0) {
                steps[currentStep - 1].classList.remove('active');
            }
            currentStep++;
        } else {
            clearInterval(interval);
        }
    }, 800);
}

function showResults(result) {
    hideLoading();
    
    const classification = result.result.toLowerCase();
    let confidence;
    
    // Handle confidence calculation based on classification
    if (classification.includes('legitimate') || classification.includes('whitelisted')) {
        // For legitimate/whitelisted sites, show confidence as legitimacy confidence
        confidence = (result.phishing_probability * 100);
    } else {
        // For phishing/suspicious, show as phishing confidence
        confidence = (result.phishing_probability * 100);
    }
    
    const url = result.url;
    const riskFactors = result.advanced_risk_factors || [];
    
    // Determine result type and styling
    let resultClass, iconClass, iconColor, confidenceClass;
    
    if (classification.includes('phishing')) {
        resultClass = 'phishing';
        iconClass = 'fas fa-exclamation-triangle';
        iconColor = '#e53e3e';
        confidenceClass = 'danger';
    } else if (classification.includes('suspicious')) {
        resultClass = 'suspicious';
        iconClass = 'fas fa-exclamation-circle';
        iconColor = '#ed8936';
        confidenceClass = 'warning';
    } else {
        resultClass = 'safe';
        iconClass = 'fas fa-check-circle';
        iconColor = '#48bb78';
        confidenceClass = 'success';
    }
    
    // Generate risk factors HTML
    const riskFactorsHtml = riskFactors.length > 0 
        ? `<div class="risk-factors">
             <h4><i class="fas fa-exclamation-triangle"></i> Risk Factors Detected</h4>
             <ul class="risk-list">
               ${riskFactors.map(factor => `<li><i class="fas fa-times-circle"></i> ${factor}</li>`).join('')}
             </ul>
           </div>`
        : '';
    
    // Create result HTML
    const resultHtml = `
        <div class="result-card ${resultClass}">
            <div class="result-header">
                <i class="${iconClass} result-icon" style="color: ${iconColor}"></i>
                <div class="result-title">${getResultTitle(classification)}</div>
                <div class="result-confidence ${confidenceClass}">
                    ${confidence.toFixed(1)}% ${classification.includes('legitimate') || classification.includes('whitelisted') ? 'Legitimate' : 'Risk'}
                </div>
            </div>
            
            <div class="result-url">
                <strong>Scanned URL:</strong> ${escapeHtml(url)}
            </div>
            
            <div class="result-details">
                <div class="detail-item">
                    <div class="detail-icon" style="background: ${getClassificationColor(classification)}">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div>
                        <strong>Security Status</strong><br>
                        <span style="color: ${iconColor}">${result.result}</span>
                    </div>
                </div>
                
                <div class="detail-item">
                    <div class="detail-icon" style="background: ${getConfidenceColor(confidence)}">
                        <i class="fas fa-percentage"></i>
                    </div>
                    <div>
                        <strong>Confidence Score</strong><br>
                        ${confidence.toFixed(1)}% ${classification.includes('legitimate') || classification.includes('whitelisted') ? 'Legitimate' : 'Risk'} (${getConfidenceLevel(confidence)})
                    </div>
                </div>
                
                <div class="detail-item">
                    <div class="detail-icon" style="background: #667eea">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div>
                        <strong>Scan Time</strong><br>
                        ${new Date().toLocaleTimeString()}
                    </div>
                </div>
                
                <div class="detail-item">
                    <div class="detail-icon" style="background: #f093fb">
                        <i class="fas fa-bug"></i>
                    </div>
                    <div>
                        <strong>Threats Found</strong><br>
                        ${riskFactors.length} risk factor(s)
                    </div>
                </div>
            </div>
            
            ${riskFactorsHtml}
            
            <div class="result-actions" style="margin-top: 1.5rem; display: flex; gap: 1rem; justify-content: center;">
                <button class="test-btn safe" onclick="scanAnotherUrl()" style="background: var(--primary-gradient);">
                    <i class="fas fa-redo"></i>
                    Scan Another URL
                </button>
                <button class="test-btn warning" onclick="shareResult()" style="background: var(--secondary-gradient);">
                    <i class="fas fa-share"></i>
                    Share Result
                </button>
            </div>
        </div>
    `;
    
    resultsContainer.innerHTML = resultHtml;
    resultsContainer.style.display = 'block';
    
    // Scroll to results
    resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function hideResults() {
    resultsContainer.style.display = 'none';
}

function showError(message) {
    hideLoading();
    
    const errorHtml = `
        <div class="result-card phishing">
            <div class="result-header">
                <i class="fas fa-exclamation-triangle result-icon" style="color: #e53e3e"></i>
                <div class="result-title">Error</div>
            </div>
            <div class="result-url">
                ${escapeHtml(message)}
            </div>
            <div style="margin-top: 1rem; text-align: center;">
                <button class="test-btn safe" onclick="clearInput()" style="background: var(--primary-gradient);">
                    <i class="fas fa-redo"></i>
                    Try Again
                </button>
            </div>
        </div>
    `;
    
    resultsContainer.innerHTML = errorHtml;
    resultsContainer.style.display = 'block';
}

function getResultTitle(classification) {
    switch (classification) {
        case 'phishing':
            return '🚨 PHISHING DETECTED';
        case 'suspicious':
            return '⚠️ SUSPICIOUS URL';
        default:
            return '✅ SAFE URL';
    }
}

function getClassificationColor(classification) {
    switch (classification) {
        case 'phishing':
            return '#e53e3e';
        case 'suspicious':
            return '#ed8936';
        default:
            return '#48bb78';
    }
}

function getConfidenceColor(confidence) {
    if (confidence >= 80) return '#48bb78';
    if (confidence >= 60) return '#ed8936';
    return '#e53e3e';
}

function getConfidenceLevel(confidence) {
    if (confidence >= 90) return 'Very High';
    if (confidence >= 75) return 'High';
    if (confidence >= 60) return 'Medium';
    if (confidence >= 40) return 'Low';
    return 'Very Low';
}

function updateScanCount() {
    scannedCount++;
    scannedCountEl.textContent = scannedCount.toLocaleString();
    
    // Save to localStorage
    localStorage.setItem('phishguard_scan_count', scannedCount.toString());
    
    // Add animation
    scannedCountEl.style.transform = 'scale(1.2)';
    setTimeout(() => {
        scannedCountEl.style.transform = 'scale(1)';
    }, 200);
}

function loadScanCount() {
    const saved = localStorage.getItem('phishguard_scan_count');
    if (saved) {
        scannedCount = parseInt(saved) || 0;
        scannedCountEl.textContent = scannedCount.toLocaleString();
    }
}

function scanAnotherUrl() {
    clearInput();
    urlInput.focus();
}

function shareResult() {
    const resultCard = document.querySelector('.result-card');
    if (resultCard) {
        const classification = resultCard.classList.contains('phishing') ? 'PHISHING' :
                            resultCard.classList.contains('suspicious') ? 'SUSPICIOUS' : 'SAFE';
        
        const text = `🛡️ PhishGuard Pro Security Scan Result: ${classification}\\n\\nScanned with advanced AI-powered phishing detection.\\n\\n#PhishGuard #CyberSecurity #URLScanner`;
        
        if (navigator.share) {
            navigator.share({
                title: 'PhishGuard Pro - URL Security Scan',
                text: text
            });
        } else {
            // Fallback: copy to clipboard
            navigator.clipboard.writeText(text).then(() => {
                showToast('Result copied to clipboard!');
            }).catch(() => {
                showToast('Unable to share result');
            });
        }
    }
}

function showToast(message) {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--primary-gradient);
        color: white;
        padding: 1rem 1.5rem;
        border-radius: var(--border-radius);
        box-shadow: var(--shadow-lg);
        z-index: 1000;
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    // Show toast
    setTimeout(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateX(0)';
    }, 100);
    
    // Hide toast
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K to focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        urlInput.focus();
        urlInput.select();
    }
    
    // Escape to clear
    if (e.key === 'Escape') {
        clearInput();
    }
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    .toast {
        font-family: 'Inter', sans-serif;
        font-weight: 500;
    }
    
    #scannedCount {
        transition: transform 0.2s ease;
    }
    
    .result-actions button {
        transition: all 0.3s ease;
    }
    
    .result-actions button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
    }
`;
document.head.appendChild(style);
