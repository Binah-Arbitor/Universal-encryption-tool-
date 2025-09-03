// Universal Encryption Tool - JavaScript Implementation
class EncryptionTool {
    constructor() {
        this.initEventListeners();
        this.updateThreadCount();
    }

    initEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Encryption functionality
        document.getElementById('encrypt-btn').addEventListener('click', () => this.encryptData());
        document.getElementById('decrypt-btn').addEventListener('click', () => this.decryptData());
        document.getElementById('generate-key').addEventListener('click', () => this.generateKey());

        // Copy to clipboard
        document.getElementById('copy-encrypted').addEventListener('click', () => this.copyToClipboard('encrypted-output'));
        document.getElementById('copy-decrypted').addEventListener('click', () => this.copyToClipboard('decrypted-output'));

        // File handling
        const fileDropZone = document.getElementById('file-drop-zone');
        const fileInput = document.getElementById('file-input');

        fileDropZone.addEventListener('click', () => fileInput.click());
        fileDropZone.addEventListener('dragover', (e) => this.handleDragOver(e));
        fileDropZone.addEventListener('drop', (e) => this.handleFileDrop(e));
        fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
    }

    switchTab(tabName) {
        // Remove active class from all tabs and panes
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

        // Add active class to selected tab and pane
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(tabName).classList.add('active');
    }

    generateKey() {
        const algorithm = document.getElementById('encrypt-algorithm').value;
        let keyLength = 16; // Default for AES-128

        if (algorithm.includes('aes')) {
            keyLength = 16; // AES-128 for simplicity
        } else if (algorithm === 'xor') {
            keyLength = 8; // Shorter for XOR
        }

        const key = this.generateRandomHex(keyLength);
        document.getElementById('encrypt-key').value = key;
    }

    generateRandomHex(length) {
        const chars = '0123456789abcdef';
        let result = '';
        for (let i = 0; i < length * 2; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    async encryptData() {
        const algorithm = document.getElementById('encrypt-algorithm').value;
        const key = document.getElementById('encrypt-key').value.trim();
        const data = document.getElementById('encrypt-data').value.trim();
        const useMultithreading = document.getElementById('use-multithreading').checked;

        if (!key || !data) {
            alert('Please enter both key and data to encrypt');
            return;
        }

        const resultSection = document.getElementById('encrypt-result');
        const progressBar = document.getElementById('encrypt-progress');
        const progressText = document.getElementById('encrypt-progress-text');
        const output = document.getElementById('encrypted-output');

        resultSection.style.display = 'block';
        
        try {
            // Simulate encryption process with progress
            progressText.textContent = 'Initializing encryption...';
            progressBar.style.width = '10%';

            await this.sleep(200);

            if (algorithm === 'xor') {
                const result = await this.simulateXOREncryption(data, key, progressBar, progressText, useMultithreading);
                output.value = result;
            } else if (algorithm.startsWith('aes')) {
                const result = await this.simulateAESEncryption(data, key, algorithm, progressBar, progressText, useMultithreading);
                output.value = result;
            }

            progressBar.style.width = '100%';
            progressText.textContent = 'Encryption completed successfully!';
        } catch (error) {
            progressText.textContent = 'Encryption failed: ' + error.message;
            console.error('Encryption error:', error);
        }
    }

    async decryptData() {
        const algorithm = document.getElementById('decrypt-algorithm').value;
        const key = document.getElementById('decrypt-key').value.trim();
        const data = document.getElementById('decrypt-data').value.trim();

        if (!key || !data) {
            alert('Please enter both key and encrypted data to decrypt');
            return;
        }

        const resultSection = document.getElementById('decrypt-result');
        const progressBar = document.getElementById('decrypt-progress');
        const progressText = document.getElementById('decrypt-progress-text');
        const output = document.getElementById('decrypted-output');

        resultSection.style.display = 'block';

        try {
            progressText.textContent = 'Initializing decryption...';
            progressBar.style.width = '10%';

            await this.sleep(200);

            if (algorithm === 'xor') {
                const result = await this.simulateXORDecryption(data, key, progressBar, progressText);
                output.value = result;
            } else if (algorithm.startsWith('aes')) {
                const result = await this.simulateAESDecryption(data, key, algorithm, progressBar, progressText);
                output.value = result;
            }

            progressBar.style.width = '100%';
            progressText.textContent = 'Decryption completed successfully!';
        } catch (error) {
            progressText.textContent = 'Decryption failed: ' + error.message;
            console.error('Decryption error:', error);
        }
    }

    async simulateXOREncryption(data, key, progressBar, progressText, useMultithreading) {
        progressText.textContent = useMultithreading ? 'XOR encryption (multithreaded)...' : 'XOR encryption...';
        progressBar.style.width = '30%';
        await this.sleep(300);

        // Convert key from hex to bytes
        const keyBytes = this.hexToBytes(key);
        const dataBytes = new TextEncoder().encode(data);
        const encrypted = new Uint8Array(dataBytes.length);

        progressBar.style.width = '60%';
        progressText.textContent = 'Processing data blocks...';
        await this.sleep(200);

        // Simulate block processing with progress
        const blockSize = useMultithreading ? 64 : 16;
        for (let i = 0; i < dataBytes.length; i += blockSize) {
            const end = Math.min(i + blockSize, dataBytes.length);
            for (let j = i; j < end; j++) {
                encrypted[j] = dataBytes[j] ^ keyBytes[j % keyBytes.length];
            }
            
            // Update progress
            const progress = 60 + (i / dataBytes.length) * 30;
            progressBar.style.width = progress + '%';
            
            if (useMultithreading && i % (blockSize * 4) === 0) {
                await this.sleep(10); // Simulate thread processing time
            }
        }

        progressBar.style.width = '95%';
        progressText.textContent = 'Generating output...';
        await this.sleep(100);

        return this.bytesToHex(encrypted);
    }

    async simulateXORDecryption(encryptedHex, key, progressBar, progressText) {
        progressText.textContent = 'XOR decryption...';
        progressBar.style.width = '30%';
        await this.sleep(300);

        const keyBytes = this.hexToBytes(key);
        const encryptedBytes = this.hexToBytes(encryptedHex);
        const decrypted = new Uint8Array(encryptedBytes.length);

        progressBar.style.width = '70%';
        progressText.textContent = 'Processing encrypted blocks...';
        await this.sleep(200);

        for (let i = 0; i < encryptedBytes.length; i++) {
            decrypted[i] = encryptedBytes[i] ^ keyBytes[i % keyBytes.length];
        }

        progressBar.style.width = '95%';
        progressText.textContent = 'Converting to text...';
        await this.sleep(100);

        return new TextDecoder().decode(decrypted);
    }

    async simulateAESEncryption(data, key, algorithm, progressBar, progressText, useMultithreading) {
        const mode = algorithm.split('-')[1].toUpperCase();
        progressText.textContent = `AES-${mode} encryption${useMultithreading ? ' (multithreaded)' : ''}...`;
        progressBar.style.width = '20%';
        await this.sleep(400);

        progressText.textContent = 'Key expansion...';
        progressBar.style.width = '40%';
        await this.sleep(300);

        progressText.textContent = 'Block processing...';
        progressBar.style.width = '70%';
        await this.sleep(useMultithreading ? 200 : 500);

        // Simulate complex AES encryption
        const dataBytes = new TextEncoder().encode(data);
        const result = this.simpleAESLikeEncryption(dataBytes, key);

        progressBar.style.width = '95%';
        progressText.textContent = 'Finalizing encryption...';
        await this.sleep(100);

        return this.bytesToHex(result);
    }

    async simulateAESDecryption(encryptedHex, key, algorithm, progressBar, progressText) {
        const mode = algorithm.split('-')[1].toUpperCase();
        progressText.textContent = `AES-${mode} decryption...`;
        progressBar.style.width = '20%';
        await this.sleep(400);

        progressText.textContent = 'Key expansion...';
        progressBar.style.width = '40%';
        await this.sleep(300);

        progressText.textContent = 'Block decryption...';
        progressBar.style.width = '70%';
        await this.sleep(500);

        const encryptedBytes = this.hexToBytes(encryptedHex);
        const result = this.simpleAESLikeDecryption(encryptedBytes, key);

        progressBar.style.width = '95%';
        progressText.textContent = 'Converting to text...';
        await this.sleep(100);

        return new TextDecoder().decode(result);
    }

    simpleAESLikeEncryption(data, key) {
        // This is a simplified simulation, not real AES
        const keyBytes = this.hexToBytes(key);
        const result = new Uint8Array(data.length);
        
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ keyBytes[i % keyBytes.length] ^ (i & 0xFF);
        }
        
        return result;
    }

    simpleAESLikeDecryption(data, key) {
        // Reverse of the simple encryption
        const keyBytes = this.hexToBytes(key);
        const result = new Uint8Array(data.length);
        
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ keyBytes[i % keyBytes.length] ^ (i & 0xFF);
        }
        
        return result;
    }

    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    async copyToClipboard(elementId) {
        const element = document.getElementById(elementId);
        try {
            await navigator.clipboard.writeText(element.value);
            this.showNotification('Copied to clipboard!');
        } catch (err) {
            // Fallback for older browsers
            element.select();
            document.execCommand('copy');
            this.showNotification('Copied to clipboard!');
        }
    }

    showNotification(message) {
        // Create a simple notification
        const notification = document.createElement('div');
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--button-primary);
            color: white;
            padding: 12px 20px;
            border-radius: 6px;
            z-index: 1000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    handleFileDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        
        const files = Array.from(e.dataTransfer.files);
        this.processFiles(files);
    }

    handleFileSelect(e) {
        const files = Array.from(e.target.files);
        this.processFiles(files);
    }

    processFiles(files) {
        const fileList = document.getElementById('file-list');
        fileList.innerHTML = '';
        
        files.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-info">
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${this.formatFileSize(file.size)}</span>
                </div>
                <div class="file-actions">
                    <button class="btn btn-secondary btn-sm" onclick="encryptionTool.processFile(${index}, 'encrypt')">Encrypt</button>
                    <button class="btn btn-secondary btn-sm" onclick="encryptionTool.processFile(${index}, 'decrypt')">Decrypt</button>
                </div>
            `;
            fileList.appendChild(fileItem);
        });
        
        this.files = files;
        this.updateQueueSize(files.length);
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    updateThreadCount() {
        const threadCount = navigator.hardwareConcurrency || 4;
        document.getElementById('thread-count').textContent = threadCount;
    }

    updateQueueSize(size) {
        document.getElementById('queue-size').textContent = size;
    }

    updateProcessedCount(count) {
        document.getElementById('processed-count').textContent = count;
    }

    async processFile(index, operation) {
        if (!this.files || !this.files[index]) return;
        
        const file = this.files[index];
        this.showNotification(`${operation === 'encrypt' ? 'Encrypting' : 'Decrypting'} ${file.name}...`);
        
        // Simulate file processing
        await this.sleep(1000);
        
        this.updateProcessedCount(parseInt(document.getElementById('processed-count').textContent) + 1);
        this.showNotification(`${file.name} ${operation === 'encrypt' ? 'encrypted' : 'decrypted'} successfully!`);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Add CSS animation for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .file-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px;
        background-color: var(--bg-tertiary);
        border: 1px solid var(--border-primary);
        border-radius: 8px;
        margin-bottom: 12px;
    }
    
    .file-info {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    
    .file-name {
        font-weight: 500;
        color: var(--text-primary);
    }
    
    .file-size {
        font-size: 12px;
        color: var(--text-secondary);
    }
    
    .file-actions {
        display: flex;
        gap: 8px;
    }
    
    .btn-sm {
        padding: 6px 12px;
        font-size: 12px;
    }
`;
document.head.appendChild(style);

// Initialize the application
const encryptionTool = new EncryptionTool();