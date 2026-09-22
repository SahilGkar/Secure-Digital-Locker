/**
 * scroll_restore.js — Preserves vertical scroll position across dashboard actions.
 * 
 * When actions on the dashboard (Upload, Delete, Search, Clear Search, etc.) cause
 * a page reload or redirect back to the dashboard, the page restores the previous
 * scroll position instead of jumping to the top.
 * 
 * Normal navigation between different tabs (How It Works, Cryptography Lab) starts at the top.
 */

(function() {
    const STORAGE_KEY = 'sdl_dashboard_scroll_pos';

    function isDashboard() {
        const path = window.location.pathname;
        return path === '/' || path.endsWith('/dashboard');
    }

    // Restore scroll on page load if on dashboard
    if (isDashboard()) {
        const savedPos = sessionStorage.getItem(STORAGE_KEY);
        if (savedPos !== null) {
            const scrollY = parseInt(savedPos, 10);
            if (!isNaN(scrollY) && scrollY > 0) {
                // Use requestAnimationFrame to ensure DOM is painted before scrolling
                window.requestAnimationFrame(() => {
                    window.scrollTo({
                        top: scrollY,
                        behavior: 'instant'
                    });
                });
            }
            // Clear immediately after restoration so subsequent fresh visits start at top
            sessionStorage.removeItem(STORAGE_KEY);
        }
    } else {
        // If we landed on a non-dashboard page, ensure no stale dashboard scroll is stored
        sessionStorage.removeItem(STORAGE_KEY);
    }

    document.addEventListener('DOMContentLoaded', () => {
        // 1. Capture scroll on any dashboard form submission (Upload, Search, Delete)
        if (isDashboard()) {
            document.querySelectorAll('form').forEach((form) => {
                form.addEventListener('submit', () => {
                    sessionStorage.setItem(STORAGE_KEY, window.scrollY.toString());
                });
            });

            // 2. Capture scroll on action links that redirect back to the dashboard (e.g. Clear Search)
            document.querySelectorAll('a').forEach((link) => {
                const href = link.getAttribute('href');
                // If link is within dashboard (like Clear search button)
                if (href && (href === '/' || href.includes('search=') || href.includes('/dashboard'))) {
                    link.addEventListener('click', () => {
                        sessionStorage.setItem(STORAGE_KEY, window.scrollY.toString());
                    });
                }
            });
        }

        // 3. Clear stored scroll position when navigating to other tabs
        document.querySelectorAll('.main-nav a, nav a').forEach((tabLink) => {
            const href = tabLink.getAttribute('href') || '';
            if (href.includes('how-it-works') || href.includes('cryptography-lab') || href.includes('logout')) {
                tabLink.addEventListener('click', () => {
                    sessionStorage.removeItem(STORAGE_KEY);
                });
            }
        });
    });
})();
