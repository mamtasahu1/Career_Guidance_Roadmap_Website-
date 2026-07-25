/* ==========================================================
   config.js — Xyverra API Configuration
   Automatically switches between local dev and production.
   ========================================================== */

const _isLocal = window.location.hostname === 'localhost' ||
                 window.location.hostname === '127.0.0.1' ||
                 window.location.protocol === 'file:';

window.XYVERRA_CONFIG = {
    API_BASE: _isLocal
        ? 'http://localhost:5000'                                   // Local development
        : 'https://career-guidance-roadmap-website.onrender.com'   // Production (Render)
};

// Convenience getter used by all JS files
window.XYVERRA_API_BASE = window.XYVERRA_CONFIG.API_BASE;
