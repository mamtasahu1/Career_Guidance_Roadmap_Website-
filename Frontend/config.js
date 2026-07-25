/* ==========================================================
   config.js — Xyverra API Configuration
   Load this as the FIRST script on every HTML page.
   Change ONLY this file to switch between dev and production.
   ========================================================== */

window.XYVERRA_CONFIG = {
    // ── Production (Render URL) ──
    API_BASE: 'https://career-guidance-roadmap-website.onrender.com'
};

// Convenience getter used by all JS files
window.XYVERRA_API_BASE = window.XYVERRA_CONFIG.API_BASE;
