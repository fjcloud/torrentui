// TorrentUI - Modern UI
class TorrentUI {
    constructor() {
        this.selectedTorrent = null;
        this.authenticated = false;
        this.authRequired = false;
        this.init();
    }

    async init() {
        await this.checkAuth();
        
        if (this.authRequired && !this.authenticated) {
            this.showLoginScreen();
        } else {
            this.showMainApp();
            this.setupEventListeners();
            this.startPolling();
        }
    }

    async checkAuth() {
        try {
            const response = await fetch('/api/auth/check');
            if (!response.ok) {
                this.authRequired = true;
                this.authenticated = false;
                return;
            }
            
            const data = await response.json();
            this.authenticated = data.authenticated;
            this.authRequired = data.authRequired !== undefined ? data.authRequired : false;
        } catch (error) {
            // If auth check fails completely, assume no auth required
            this.authRequired = false;
            this.authenticated = true;
        }
    }

    showLoginScreen() {
        document.getElementById('loginOverlay').classList.remove('hidden');
        document.getElementById('mainApp').classList.add('hidden');
        
        const loginForm = document.getElementById('loginForm');
        if (!this.loginHandlerAttached) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
            this.loginHandlerAttached = true;
        }
    }

    showMainApp() {
        const loginOverlay = document.getElementById('loginOverlay');
        const mainApp = document.getElementById('mainApp');
        
        loginOverlay.classList.add('hidden');
        mainApp.classList.remove('hidden');
        
        if (this.authRequired && !this.logoutHandlerAttached) {
            const logoutBtn = document.getElementById('logoutBtn');
            logoutBtn.classList.remove('hidden');
            logoutBtn.addEventListener('click', () => this.handleLogout());
            this.logoutHandlerAttached = true;
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorDiv = document.getElementById('loginError');
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Login failed');
            }

            await response.json();

            this.authenticated = true;
            errorDiv.classList.add('hidden');
            this.showMainApp();
            this.setupEventListeners();
            this.startPolling();
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.classList.remove('hidden');
        }
    }

    async handleLogout() {
        try {
            await fetch('/api/logout', { method: 'POST' });
            this.authenticated = false;
            this.showLoginScreen();
            
            // Stop polling
            if (this.pollingInterval) {
                clearInterval(this.pollingInterval);
            }
        } catch (error) {
            this.showToast('Logout failed', 'error');
        }
    }

    setupEventListeners() {
        if (this.listenersAttached) return;
        this.listenersAttached = true;
        
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('torrentFile');

        dropZone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => this.handleFileUpload());

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0 && files[0].name.endsWith('.torrent')) {
                fileInput.files = files;
                this.handleFileUpload();
            } else {
                this.showToast('Please select a .torrent file', 'error');
            }
        });
    }

    async handleFileUpload() {
        const fileInput = document.getElementById('torrentFile');
        if (fileInput.files.length === 0) return;

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        try {
            const response = await fetch('/api/torrents', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to add torrent');
            }

            this.showToast('Torrent added successfully', 'success');
            fileInput.value = '';
            this.loadTorrents();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    async loadTorrents() {
        try {
            const response = await fetch('/api/torrents');
            const torrents = await response.json();
            this.renderTorrents(torrents);
            this.updateTotalUpload(torrents);
        } catch (error) {
            console.error('Error loading torrents:', error);
        }
    }

    updateTotalUpload(torrents) {
        const totalBytes = torrents.reduce((sum, t) => sum + (t.seededBytes || 0), 0);
        const totalRate = torrents.reduce((sum, t) => sum + (t.uploadRate || 0), 0);
        const el = document.getElementById('totalUpload');
        if (el) {
            let text = `⬆️ Total upload: ${this.formatBytes(totalBytes)}`;
            if (totalRate > 0) {
                text += ` (${this.formatSpeed(totalRate)})`;
            }
            el.textContent = text;
        }
    }

    renderTorrents(torrents) {
        const container = document.getElementById('torrentsContainer');
        
        if (torrents.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">🌊</div>
                    <div>No torrents yet. Add one to get started.</div>
                </div>
            `;
            return;
        }

        container.innerHTML = `<div class="torrents-list">${torrents.map(t => {
            const progressPct = Math.round(t.progress * 100);
            const statusEmoji = {
                'downloading': '⬇️',
                'seeding': '⬆️',
                'paused': '⏸️',
                'stopped': '⏹️'
            }[t.status] || '•';
            
            return `
            <div class="torrent-item status-${t.status}">
                <div class="status-indicator"></div>
                
                <div class="torrent-main">
                    <div class="torrent-header">
                        <div class="torrent-name" title="${this.escapeHtml(t.name)}">
                            ${this.escapeHtml(t.name)}
                        </div>
                        <span class="torrent-status status-${t.status}">
                            ${statusEmoji} ${t.status}
                        </span>
                    </div>
                    
                    <div class="progress">
                        <div class="progress-bar" style="width: ${progressPct}%"></div>
                    </div>
                    
                    <div class="torrent-stats">
                        <div class="stat">
                            <span class="stat-value">${progressPct}%</span>
                            <span class="stat-label">• ${this.formatBytes(t.size)}</span>
                        </div>
                        ${t.ratio !== undefined ? `
                        <div class="stat stat-ratio">
                            <span class="stat-icon">📊</span>
                            <span class="stat-label">Ratio:</span>
                            <span class="stat-value ratio-${this.getRatioClass(t.ratio)}">${this.formatRatio(t.ratio)}</span>
                        </div>
                        ` : ''}
                        ${t.downloadRate > 0 ? `
                        <div class="stat">
                            <span class="stat-icon">⬇</span>
                            <span class="stat-value">${this.formatSpeed(t.downloadRate)}</span>
                        </div>
                        ` : ''}
                        ${t.seeding || t.uploadRate > 0 || t.seededBytes > 0 ? `
                        <div class="stat stat-upload">
                            <span class="stat-icon">⬆</span>
                            <span class="stat-value">${t.uploadRate > 0 ? this.formatSpeed(t.uploadRate) : '0 B/s'}</span>
                            <span class="stat-label">• ${this.formatBytes(t.seededBytes || 0)} total</span>
                        </div>
                        ` : ''}
                        ${t.peers > 0 ? `
                        <div class="stat">
                            <span class="stat-icon">👥</span>
                            <span class="stat-value">${t.peers}</span>
                        </div>
                        ` : ''}
                    </div>
                </div>
                
                <div class="torrent-actions">
                    <button class="btn-${t.seeding ? 'danger' : 'success'}" 
                            onclick="torrentUI.toggleSeeding('${t.infoHash}', ${!t.seeding})">
                        ${t.seeding ? '⏸ Stop' : '▶ Seed'}
                    </button>
                    <button class="btn-primary" 
                            onclick="torrentUI.downloadTorrent('${t.infoHash}')">
                        💾 Download
                    </button>
                    <button class="btn-danger" 
                            onclick="torrentUI.deleteTorrent('${t.infoHash}', false)">
                        🗑 Delete
                    </button>
                </div>
            </div>
        `;
        }).join('')}</div>`;
    }

    async selectTorrent(infoHash) {
        this.selectedTorrent = infoHash;
        this.loadTorrents();
        this.loadFiles(infoHash);
    }

    async loadFiles(infoHash) {
        try {
            const response = await fetch(`/api/torrents/${infoHash}/files`);
            const files = await response.json();
            this.renderFiles(files, infoHash);
        } catch (error) {
            console.error('Error loading files:', error);
        }
    }

    renderFiles(files, infoHash) {
        const panel = document.getElementById('filesPanel');
        const filesList = document.getElementById('filesList');
        
        if (files.length === 0) {
            panel.classList.add('hidden');
            return;
        }

        panel.classList.remove('hidden');
        filesList.innerHTML = files.map(f => `
            <div class="file-item">
                <div>
                    <div class="file-name">${this.escapeHtml(f.path)}</div>
                    <div class="file-size">${this.formatBytes(f.length)} • ${Math.round(f.progress * 100)}%</div>
                </div>
                <div class="file-actions">
                    <button onclick="torrentUI.downloadFile('${infoHash}', '${this.escapeHtml(f.path)}')">
                        Download
                    </button>
                </div>
            </div>
        `).join('');
    }

    async toggleSeeding(infoHash, start) {
        try {
            const response = await fetch(`/api/torrents/${infoHash}/seed`, {
                method: start ? 'POST' : 'DELETE'
            });

            if (!response.ok) throw new Error('Failed to toggle seeding');

            this.showToast(`Seeding ${start ? 'started' : 'stopped'}`, 'success');
            this.loadTorrents();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    async downloadTorrent(infoHash) {
        try {
            const response = await fetch(`/api/torrents/${infoHash}/export`);
            if (!response.ok) throw new Error('Failed to download');

            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${infoHash}.torrent`;
            a.click();
            URL.revokeObjectURL(url);

            this.showToast('Torrent file downloaded', 'success');
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    async deleteTorrent(infoHash, deleteFiles) {
        if (!confirm('Delete this torrent?')) return;

        try {
            const response = await fetch(`/api/torrents/${infoHash}?deleteFiles=${deleteFiles}`, {
                method: 'DELETE'
            });

            if (!response.ok) throw new Error('Failed to delete');

            this.showToast('Torrent deleted', 'success');
            if (this.selectedTorrent === infoHash) {
                this.selectedTorrent = null;
                document.getElementById('filesPanel').classList.add('hidden');
            }
            this.loadTorrents();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    downloadFile(infoHash, path) {
        const url = `/api/torrents/${infoHash}/file?path=${encodeURIComponent(path)}`;
        window.open(url, '_blank');
    }

    startPolling() {
        this.loadTorrents();
        this.loadDiskSpace();
        this.pollingInterval = setInterval(() => {
            this.loadTorrents();
            this.loadDiskSpace();
            if (this.selectedTorrent) {
                this.loadFiles(this.selectedTorrent);
            }
        }, 5000);
    }

    async loadDiskSpace() {
        try {
            const response = await fetch('/api/disk-space');
            if (!response.ok) return;
            
            const data = await response.json();
            const diskSpaceEl = document.getElementById('diskSpace');
            if (diskSpaceEl) {
                const available = this.formatBytes(data.available);
                const total = this.formatBytes(data.total);
                const usedPct = data.usedPct.toFixed(1);
                diskSpaceEl.textContent = `💾 Disk space: ${available} free of ${total} (${usedPct}% used)`;
            }
        } catch (error) {
            // Silent fail
        }
    }

    showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }

    formatSpeed(bytesPerSecond) {
        return this.formatBytes(bytesPerSecond) + '/s';
    }

    formatRatio(ratio) {
        if (ratio >= 999) return '∞';
        if (ratio >= 10) return ratio.toFixed(1);
        return ratio.toFixed(2);
    }

    getRatioClass(ratio) {
        if (ratio >= 2.0) return 'excellent'; // 2.0+ = excellent
        if (ratio >= 1.0) return 'good';      // 1.0-2.0 = good
        if (ratio >= 0.5) return 'fair';      // 0.5-1.0 = fair
        return 'poor';                         // < 0.5 = poor
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize
const torrentUI = new TorrentUI();






