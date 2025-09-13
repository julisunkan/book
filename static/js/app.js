/* Custom JavaScript for Tutorial Platform */

document.addEventListener('DOMContentLoaded', function() {
    console.log('Tutorial Platform loaded successfully');
    
    // Initialize all interactive features
    initModuleCards();
    initCodeBlocks();
    initProgressTracking();
    initNavigation();
    initImageModal();
});

// Module card interactions
function initModuleCards() {
    const moduleCards = document.querySelectorAll('.module-card');
    
    moduleCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
            this.style.transition = 'transform 0.2s ease';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
}

// Code block enhancements
function initCodeBlocks() {
    const codeBlocks = document.querySelectorAll('pre code');
    
    codeBlocks.forEach((block, index) => {
        // Add copy button
        if (!block.parentNode.querySelector('.copy-btn')) {
            const button = document.createElement('button');
            button.className = 'btn btn-sm btn-outline-secondary copy-btn';
            button.innerHTML = '<i class="fas fa-copy"></i>';
            button.title = 'Copy code';
            
            button.addEventListener('click', function() {
                copyToClipboard(block.textContent, button);
            });
            
            block.parentNode.style.position = 'relative';
            block.parentNode.appendChild(button);
        }
        
        // Add line numbers for longer code blocks
        const lines = block.textContent.split('\n');
        if (lines.length > 5) {
            block.classList.add('line-numbers');
        }
    });
}

// Copy to clipboard functionality
function copyToClipboard(text, button) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showCopySuccess(button);
        }).catch(err => {
            fallbackCopy(text, button);
        });
    } else {
        fallbackCopy(text, button);
    }
}

function fallbackCopy(text, button) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showCopySuccess(button);
    } catch (err) {
        console.error('Copy failed:', err);
        button.innerHTML = '<i class="fas fa-times"></i>';
        setTimeout(() => {
            button.innerHTML = '<i class="fas fa-copy"></i>';
        }, 2000);
    }
    
    document.body.removeChild(textArea);
}

function showCopySuccess(button) {
    const originalContent = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check"></i>';
    button.classList.add('btn-success');
    button.classList.remove('btn-outline-secondary');
    
    setTimeout(() => {
        button.innerHTML = originalContent;
        button.classList.remove('btn-success');
        button.classList.add('btn-outline-secondary');
    }, 2000);
}

// Progress tracking
function initProgressTracking() {
    const markCompleteForm = document.querySelector('form[action*="mark_complete"]');
    
    if (markCompleteForm) {
        markCompleteForm.addEventListener('submit', function(e) {
            const button = this.querySelector('button[type="submit"]');
            
            if (button) {
                button.innerHTML = '<span class="loading"></span> Marking Complete...';
                button.disabled = true;
            }
        });
    }
    
    // Auto-save reading position
    saveReadingPosition();
    restoreReadingPosition();
}

function saveReadingPosition() {
    let saveTimeout;
    
    window.addEventListener('scroll', function() {
        clearTimeout(saveTimeout);
        saveTimeout = setTimeout(() => {
            const scrollPosition = window.scrollY;
            const moduleId = getCurrentModuleId();
            
            if (moduleId) {
                localStorage.setItem(`scroll_${moduleId}`, scrollPosition);
            }
        }, 1000);
    });
}

function restoreReadingPosition() {
    const moduleId = getCurrentModuleId();
    
    if (moduleId) {
        const savedPosition = localStorage.getItem(`scroll_${moduleId}`);
        if (savedPosition) {
            setTimeout(() => {
                window.scrollTo(0, parseInt(savedPosition));
            }, 100);
        }
    }
}

function getCurrentModuleId() {
    const path = window.location.pathname;
    const match = path.match(/\/module\/(\d+)/);
    return match ? match[1] : null;
}

// Smooth navigation
function initNavigation() {
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
                
                // Update URL without jumping
                if (history.pushState) {
                    history.pushState(null, null, this.getAttribute('href'));
                }
            }
        });
    });
    
    // Keyboard navigation
    document.addEventListener('keydown', function(e) {
        // Alt + Left Arrow: Previous module
        if (e.altKey && e.key === 'ArrowLeft') {
            const prevBtn = document.querySelector('a[href*="module"]:has(i.fa-chevron-left)');
            if (prevBtn) {
                window.location.href = prevBtn.href;
            }
        }
        
        // Alt + Right Arrow: Next module
        if (e.altKey && e.key === 'ArrowRight') {
            const nextBtn = document.querySelector('a[href*="module"]:has(i.fa-chevron-right)');
            if (nextBtn) {
                window.location.href = nextBtn.href;
            }
        }
        
        // Alt + H: Home
        if (e.altKey && e.key === 'h') {
            window.location.href = '/';
        }
    });
}

// Image modal for larger viewing
function initImageModal() {
    const images = document.querySelectorAll('.module-content img');
    
    images.forEach(img => {
        img.style.cursor = 'pointer';
        img.addEventListener('click', function() {
            createImageModal(this);
        });
    });
}

function createImageModal(img) {
    // Remove existing modal if present
    const existingModal = document.querySelector('#imageModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Create modal
    const modal = document.createElement('div');
    modal.id = 'imageModal';
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Image Viewer</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body text-center">
                    <img src="${img.src}" alt="${img.alt}" class="img-fluid">
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Show modal
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();
    
    // Clean up after modal is hidden
    modal.addEventListener('hidden.bs.modal', () => {
        modal.remove();
    });
}

// Utility functions
function showToast(message, type = 'success') {
    // Create toast if it doesn't exist
    let toastContainer = document.querySelector('.toast-container');
    
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    const toastInstance = new bootstrap.Toast(toast);
    toastInstance.show();
    
    // Clean up after toast is hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// Loading indicator
function showLoading(element) {
    const originalContent = element.innerHTML;
    element.innerHTML = '<span class="loading"></span> Loading...';
    element.disabled = true;
    
    return function() {
        element.innerHTML = originalContent;
        element.disabled = false;
    };
}

// Module progress API
function updateProgress(moduleId, status) {
    fetch('/progress_api', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            module_id: moduleId,
            status: status
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Progress updated successfully');
        }
    })
    .catch(error => {
        console.error('Error updating progress:', error);
        showToast('Failed to update progress', 'error');
    });
}