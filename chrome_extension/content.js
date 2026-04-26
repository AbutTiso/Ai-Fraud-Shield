// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzePage") {
        const pageContent = extractPageContent();
        sendResponse({ 
            content: pageContent,
            url: window.location.href 
        });
    }
    return true;
});

function extractPageContent() {
    // Get visible text from page
    const bodyText = document.body.innerText || document.body.textContent;
    
    // Get all links
    const links = Array.from(document.querySelectorAll('a'))
        .map(a => a.href)
        .filter(href => href && href.startsWith('http'));
    
    // Get forms
    const forms = Array.from(document.forms).length;
    
    // Get input fields
    const inputFields = Array.from(document.querySelectorAll('input[type="text"], input[type="email"], input[type="password"]')).length;
    
    // Get suspicious elements
    const suspiciousElements = findSuspiciousElements();
    
    return {
        text: bodyText.substring(0, 10000), // Limit length
        links: links.slice(0, 100),
        forms: forms,
        inputFields: inputFields,
        title: document.title,
        suspiciousElements: suspiciousElements
    };
}

function findSuspiciousElements() {
    const suspiciousKeywords = [
        'click here', 'verify', 'urgent', 'account', 'suspended',
        'congratulations', 'winner', 'prize', 'limited time',
        'act now', 'verify your account', 'update your payment'
    ];
    
    const elements = document.querySelectorAll('p, div, span, a, button');
    const suspicious = [];
    
    elements.forEach((element, index) => {
        const text = (element.innerText || element.textContent || '').toLowerCase();
        if (suspiciousKeywords.some(keyword => text.includes(keyword))) {
            suspicious.push({
                tag: element.tagName,
                text: text.substring(0, 100),
                hasLink: element.querySelector('a') !== null
            });
            
            // Highlight suspicious elements
            if (suspicious.length < 20) { // Limit highlighting
                element.style.backgroundColor = '#fff3cd';
                element.style.borderLeft = '3px solid #ffc107';
                element.style.padding = '2px 5px';
                element.style.transition = 'all 0.3s';
            }
        }
    });
    
    return suspicious;
}

// Auto-highlight suspicious elements on page load
function autoHighlight() {
    const suspiciousKeywords = [
        'click here', 'verify', 'urgent', 'account', 'suspended',
        'congratulations', 'winner', 'prize', 'limited time'
    ];
    
    const elements = document.querySelectorAll('p, div, span, a, button');
    
    elements.forEach(element => {
        const text = (element.innerText || element.textContent || '').toLowerCase();
        if (suspiciousKeywords.some(keyword => text.includes(keyword))) {
            element.style.backgroundColor = '#fff3cd';
            element.style.borderLeft = '3px solid #ffc107';
            element.style.padding = '2px 5px';
        }
    });
}

// Watch for dynamically loaded content
const observer = new MutationObserver((mutations) => {
    // Only highlight if we haven't already highlighted too many elements
    const highlightedCount = document.querySelectorAll('[style*="#fff3cd"]').length;
    if (highlightedCount < 50) {
        autoHighlight();
    }
});

// Start observing when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        autoHighlight();
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    });
} else {
    autoHighlight();
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

console.log('AI Fraud Shield: Content script loaded and monitoring');