// ── CONFIGUARDS THEME SWITCHER ──

const THEMES = [
    {
        id: 'aws-pro',
        name: 'AWS Professional',
        desc: 'Dark charcoal, AWS orange accents',
        preview: ['#0f1117', '#ff9900', '#1a1d27'],
        file: 'aws-pro.css'
    },
    {
        id: 'dark-glass',
        name: 'Dark Glassmorphism',
        desc: 'Navy background, frosted glass cards',
        preview: ['#0a0e1a', '#ff9900', '#00d4ff'],
        file: 'dark-glass.css'
    },
    {
        id: 'cyber',
        name: 'Cyber Matrix',
        desc: 'Pure black, green matrix terminal',
        preview: ['#000000', '#00ff41', '#00aaff'],
        file: 'cyber.css'
    },
    {
        id: 'midnight-blue',
        name: 'Midnight Blue',
        desc: 'Deep blue gradient, electric blue & gold',
        preview: ['#020818', '#63b3ed', '#d4af37'],
        file: 'midnight-blue.css'
    },
    {
        id: 'neon-cyberpunk',
        name: 'Neon Cyberpunk',
        desc: 'Dark purple, hot pink & electric blue',
        preview: ['#0d0015', '#ff00c8', '#00c8ff'],
        file: 'neon-cyberpunk.css'
    },
    {
        id: 'slate-emerald',
        name: 'Slate & Emerald',
        desc: 'Dark slate, emerald green accents',
        preview: ['#0e1117', '#10b981', '#38bdf8'],
        file: 'slate-emerald.css'
    },
    {
        id: 'style',
        name: 'Classic Purple',
        desc: 'Original purple gradient theme',
        preview: ['#667eea', '#764ba2', '#ffffff'],
        file: 'style.css'
    }
];

const DEFAULT_THEME = 'aws-pro';

function getActiveTheme() {
    return localStorage.getItem('configuards_theme') || DEFAULT_THEME;
}

function applyTheme(themeId) {
    const theme = THEMES.find(t => t.id === themeId) || THEMES[0];
    const link = document.getElementById('theme-css');
    if (link) {
        // Extract base URL from current href
        const currentHref = link.href;
        const base = currentHref.substring(0, currentHref.lastIndexOf('/') + 1);
        link.href = base + theme.file;
    }
    localStorage.setItem('configuards_theme', themeId);

    // Update active state in popup if open
    document.querySelectorAll('.theme-option').forEach(el => {
        el.classList.toggle('active', el.dataset.themeId === themeId);
    });
}

function loadSavedTheme() {
    const saved = getActiveTheme();
    applyTheme(saved);
}

function openThemePopup() {
    // Remove existing popup
    const existing = document.getElementById('theme-popup-overlay');
    if (existing) { existing.remove(); return; }

    const activeTheme = getActiveTheme();

    const overlay = document.createElement('div');
    overlay.id = 'theme-popup-overlay';
    overlay.innerHTML = `
        <div id="theme-popup">
            <div class="tp-header">
                <div class="tp-title">
                    <span class="tp-icon">🎨</span>
                    <div>
                        <h3>Choose Theme</h3>
                        <p>Select a visual theme for your dashboard</p>
                    </div>
                </div>
                <button class="tp-close" onclick="closeThemePopup()">✕</button>
            </div>
            <div class="tp-grid">
                ${THEMES.map(t => `
                    <div class="theme-option ${t.id === activeTheme ? 'active' : ''}" 
                         data-theme-id="${t.id}"
                         onclick="selectTheme('${t.id}')">
                        <div class="theme-preview">
                            <div class="tp-swatch" style="background:${t.preview[0]}">
                                <div class="tp-bar" style="background:${t.preview[1]}"></div>
                                <div class="tp-card" style="background:${t.preview[0]}; border-color:${t.preview[1]}40">
                                    <div class="tp-dot" style="background:${t.preview[1]}"></div>
                                    <div class="tp-dot" style="background:${t.preview[2]}"></div>
                                    <div class="tp-line" style="background:${t.preview[1]}40"></div>
                                    <div class="tp-line" style="background:${t.preview[1]}25"></div>
                                </div>
                            </div>
                        </div>
                        <div class="theme-info">
                            <strong>${t.name}</strong>
                            <small>${t.desc}</small>
                        </div>
                        <div class="theme-check">✓</div>
                    </div>
                `).join('')}
            </div>
            <div class="tp-footer">
                <span class="tp-note">Theme is saved automatically and persists across sessions</span>
            </div>
        </div>
    `;

    // Close on overlay click
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) closeThemePopup();
    });

    document.body.appendChild(overlay);

    // Animate in
    requestAnimationFrame(() => overlay.classList.add('visible'));
}

function closeThemePopup() {
    const overlay = document.getElementById('theme-popup-overlay');
    if (overlay) {
        overlay.classList.remove('visible');
        setTimeout(() => overlay.remove(), 250);
    }
}

function selectTheme(themeId) {
    applyTheme(themeId);
}

// Run on page load
document.addEventListener('DOMContentLoaded', function() {
    loadSavedTheme();

    // Close popup on Escape
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeThemePopup();
    });
});
