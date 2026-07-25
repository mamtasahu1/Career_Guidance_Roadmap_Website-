/* ==========================================================
   config.js — Xyverra API Configuration
   Load this as the FIRST script on every HTML page.
   Change ONLY this file to switch between dev and production.
   ========================================================== */

window.XYVERRA_CONFIG = {
    // ── Development (localhost) ──────────────────────────────────
    // API_BASE: 'http://localhost:5000',

    // ── Production (update this after deploying backend to Render) ──
    API_BASE: 'http://localhost:5000'  // ← Replace with your Render URL before deploying
};

// Convenience getter used by all JS files
window.XYVERRA_API_BASE = window.XYVERRA_CONFIG.API_BASE;
window.XYVERRA_CONFIG = {
  API_BASE: "https://career-guidance-roadmap-website.onrender.com" // ← your Render URL
};

