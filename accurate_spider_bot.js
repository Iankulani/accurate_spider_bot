#!/usr/bin/env node

/**
 * Spider Bot - Cybersecurity Tool
 * Author: Ian Carter Kulani
 * Version: v0.0.1
 * JavaScript/Node.js Version
 */

const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const util = require('util');
const readline = require('readline');
const os = require('os');
const dns = require('dns');
const net = require('net');
const crypto = require('crypto');
const { performance } = require('perf_hooks');

// Promisify functions
const execAsync = util.promisify(exec);
const writeFileAsync = util.promisify(fs.writeFile);
const readFileAsync = util.promisify(fs.readFile);
const mkdirAsync = util.promisify(fs.mkdir);

// =====================
// CONFIGURATION
// =====================
const CONFIG_DIR = '.accurateos';
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const TELEGRAM_CONFIG_FILE = path.join(CONFIG_DIR, 'telegram_config.json');
const DATABASE_FILE = path.join(CONFIG_DIR, 'network_data.db');
const LOG_FILE = path.join(CONFIG_DIR, 'accurateos.log');
const REPORT_DIR = 'reports';
const SCAN_RESULTS_DIR = 'scan_results';
const ALERTS_DIR = 'alerts';
const TEMPLATES_DIR = 'templates';
const CRYPTO_DIR = 'crypto';
const STEGANO_DIR = 'stegano';
const EXPLOITS_DIR = 'exploits';
const PAYLOADS_DIR = 'payloads';
const WORDLISTS_DIR = 'wordlists';
const CAPTURES_DIR = 'captures';
const BACKUPS_DIR = 'backups';
const IOT_SCANS_DIR = path.join(SCAN_RESULTS_DIR, 'iot');
const SOCIAL_ENG_DIR = 'social_engineering';

// Nmap scan types
const NMAP_SCAN_TYPES = {
    'quick': '-T4 -F',
    'stealth': '-sS -T2',
    'comprehensive': '-sS -sV -sC -A -O',
    'udp': '-sU',
    'vulnerability': '-sV --script vuln',
    'full': '-p- -sV -sC -A -O',
    'syn': '-sS',
    'aggressive': '-A',
    'os_detection': '-O',
    'service_detection': '-sV',
    'discovery': '-sn',
    'idle': '-sI'
};

// =====================
// DATA CLASSES
// =====================
class ScanResult {
    constructor(scan_id, success, target, scan_type, cmd, execution_time, result, vulnerabilities, raw_output) {
        this.scan_id = scan_id;
        this.success = success;
        this.target = target;
        this.scan_type = scan_type;
        this.cmd = cmd;
        this.execution_time = execution_time;
        this.result = result || {};
        this.vulnerabilities = vulnerabilities || [];
        this.raw_output = raw_output;
        this.timestamp = new Date().toISOString();
    }
}

class PortInfo {
    constructor(port, protocol, state, service, version = null) {
        this.port = port;
        this.protocol = protocol;
        this.state = state;
        this.service = service;
        this.version = version;
    }
}

class Vulnerability {
    constructor(port, issues) {
        this.port = port;
        this.issues = issues || [];
    }
}

class ThreatIntel {
    constructor(ip, threat_type, severity, confidence, description, source) {
        this.ip = ip;
        this.threat_type = threat_type;
        this.severity = severity;
        this.confidence = confidence;
        this.description = description;
        this.timestamp = new Date().toISOString();
        this.source = source;
    }
}

// =====================
// TELEGRAM CONFIG
// =====================
class TelegramConfig {
    constructor() {
        this.token = null;
        this.chat_id = null;
        this.bot_username = null;
        this.enabled = false;
        this.loadConfig();
    }

    loadConfig() {
        try {
            if (fs.existsSync(TELEGRAM_CONFIG_FILE)) {
                const config = JSON.parse(fs.readFileSync(TELEGRAM_CONFIG_FILE, 'utf8'));
                this.token = config.token;
                this.chat_id = config.chat_id;
                this.bot_username = config.bot_username;
                this.enabled = config.enabled || false;
                console.log('✅ Telegram config loaded');
            }
        } catch (error) {
            console.error('❌ Failed to load Telegram config:', error.message);
        }
    }

    saveConfig() {
        try {
            const config = {
                token: this.token,
                chat_id: this.chat_id,
                bot_username: this.bot_username,
                enabled: !!(this.token && this.chat_id),
                last_updated: new Date().toISOString()
            };

            fs.writeFileSync(TELEGRAM_CONFIG_FILE, JSON.stringify(config, null, 4));
            console.log('✅ Telegram config saved');
            return true;
        } catch (error) {
            console.error('❌ Failed to save Telegram config:', error.message);
            return false;
        }
    }

    validateConfig() {
        if (!this.token) {
            return { valid: false, message: 'Token is required' };
        }

        if (!this.chat_id) {
            return { valid: false, message: 'Chat ID is required' };
        }

        const tokenPattern = /^\d{8,11}:[A-Za-z0-9_-]{35}$/;
        if (!tokenPattern.test(this.token)) {
            return { valid: false, message: 'Invalid token format' };
        }

        return { valid: true, message: 'Configuration is valid' };
    }

    async testConnection() {
        if (!this.token || !this.chat_id) {
            return { success: false, message: 'Token or Chat ID not configured' };
        }

        try {
            const axios = require('axios');
            const url = `https://api.telegram.org/bot${this.token}/getMe`;
            const response = await axios.get(url, { timeout: 10000 });

            if (response.status === 200) {
                const data = response.data;
                if (data.ok) {
                    const botInfo = data.result;
                    this.bot_username = botInfo.username;
                    this.saveConfig();

                    const testMsg = await this.sendMessage('🕸️ Spider Bot v.0.0.1 connected!');
                    
                    return {
                        success: true,
                        message: testMsg ? `✅ Connected as @${this.bot_username}` : '✅ Bot verified but message sending failed'
                    };
                } else {
                    return { success: false, message: `API error: ${data.description}` };
                }
            } else {
                return { success: false, message: `HTTP error: ${response.status}` };
            }
        } catch (error) {
            return { success: false, message: `Connection error: ${error.message}` };
        }
    }

    async sendMessage(message, parse_mode = 'HTML', disable_preview = true) {
        if (!this.token || !this.chat_id) {
            return false;
        }

        try {
            const axios = require('axios');
            const url = `https://api.telegram.org/bot${this.token}/sendMessage`;

            if (message.length > 4096) {
                const messages = [];
                for (let i = 0; i < message.length; i += 4000) {
                    messages.push(message.substring(i, i + 4000));
                }

                for (const msg of messages) {
                    const payload = {
                        chat_id: this.chat_id,
                        text: msg,
                        parse_mode: parse_mode,
                        disable_web_page_preview: disable_preview
                    };

                    const response = await axios.post(url, payload, { timeout: 10000 });
                    if (response.status !== 200) {
                        console.error('❌ Telegram send failed:', response.data);
                        return false;
                    }
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
                return true;
            } else {
                const payload = {
                    chat_id: this.chat_id,
                    text: message,
                    parse_mode: parse_mode,
                    disable_web_page_preview: disable_preview
                };

                const response = await axios.post(url, payload, { timeout: 10000 });
                return response.status === 200;
            }
        } catch (error) {
            console.error('❌ Telegram send error:', error.message);
            return false;
        }
    }

    async interactiveSetup() {
        console.log('\n' + '='.repeat(60));
        console.log('🤖 TELEGRAM BOT SETUP WIZARD');
        console.log('='.repeat(60));

        console.log('\nTo enable 500+ Telegram commands:');
        console.log('1. Open Telegram and search for @BotFather');
        console.log('2. Send /newbot to create a new bot');
        console.log('3. Choose a name for your bot');
        console.log('4. Choose a username (must end with \'bot\')');
        console.log('5. Copy the token provided by BotFather');
        console.log('\nFor Chat ID:');
        console.log('1. Search for @userinfobot on Telegram');
        console.log('2. Send /start to the bot');
        console.log('3. Copy your numerical chat ID');
        console.log('\n' + '-'.repeat(60));

        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        try {
            while (true) {
                const token = await new Promise(resolve => {
                    rl.question('\nEnter bot token (or \'skip\' to skip): ', resolve);
                });

                if (token.toLowerCase() === 'skip') {
                    console.log('⚠️ Telegram setup skipped');
                    rl.close();
                    return false;
                }

                if (!token) {
                    console.log('❌ Token cannot be empty');
                    continue;
                }

                const tokenPattern = /^\d{8,11}:[A-Za-z0-9_-]{35}$/;
                if (!tokenPattern.test(token)) {
                    console.log('❌ Invalid token format. Example: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz');
                    continue;
                }

                this.token = token;

                const chat_id = await new Promise(resolve => {
                    rl.question('\nEnter your chat ID (or \'skip\' to skip): ', resolve);
                });

                if (chat_id.toLowerCase() === 'skip') {
                    console.log('⚠️ Telegram setup incomplete');
                    rl.close();
                    return false;
                }

                if (!/^\d+$/.test(chat_id)) {
                    console.log('❌ Chat ID must be numeric');
                    continue;
                }

                this.chat_id = chat_id;

                console.log('\n🔌 Testing connection...');
                const { success, message } = await this.testConnection();

                if (success) {
                    this.enabled = true;
                    this.saveConfig();

                    console.log('\n' + '='.repeat(60));
                    console.log('✅ TELEGRAM SETUP COMPLETE!');
                    console.log('='.repeat(60));
                    console.log(`\nBot: @${this.bot_username}`);
                    console.log(`Chat ID: ${this.chat_id}`);
                    console.log('Status: Connected');
                    console.log('\nSend /start to your bot to begin!');
                    rl.close();
                    return true;
                } else {
                    console.log(`❌ Connection failed: ${message}`);
                    const retry = await new Promise(resolve => {
                        rl.question('\nRetry setup? (y/n): ', resolve);
                    });

                    if (retry.toLowerCase() !== 'y') {
                        rl.close();
                        return false;
                    }
                }
            }
        } catch (error) {
            rl.close();
            console.error('❌ Setup error:', error.message);
            return false;
        }
    }
}

// =====================
// DATABASE MANAGER (SQLite3)
// =====================
class DatabaseManager {
    constructor() {
        this.dbFile = DATABASE_FILE;
        this.initDatabase();
    }

    initDatabase() {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            const tables = [
                `CREATE TABLE IF NOT EXISTS monitored_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    threat_level INTEGER DEFAULT 0,
                    last_scan TIMESTAMP,
                    hostname TEXT,
                    os TEXT,
                    country TEXT,
                    notes TEXT
                )`,
                `CREATE TABLE IF NOT EXISTS threat_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT 0,
                    source TEXT,
                    confidence REAL DEFAULT 0.0,
                    FOREIGN KEY (ip_address) REFERENCES monitored_ips (ip_address)
                )`,
                `CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command TEXT NOT NULL,
                    source TEXT DEFAULT 'local',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1,
                    output TEXT,
                    execution_time REAL,
                    user TEXT
                )`,
                `CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    open_ports TEXT,
                    services TEXT,
                    os_info TEXT,
                    vulnerabilities TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    raw_output TEXT,
                    duration REAL,
                    risk_level TEXT
                )`,
                `CREATE TABLE IF NOT EXISTS network_discovery (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network_cidr TEXT NOT NULL,
                    discovered_hosts TEXT,
                    scan_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    host_count INTEGER
                )`,
                `CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    network_sent REAL,
                    network_recv REAL,
                    connections_count INTEGER,
                    processes_count INTEGER
                )`,
                `CREATE TABLE IF NOT EXISTS telegram_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    chat_id TEXT,
                    user_id TEXT,
                    command TEXT NOT NULL,
                    success BOOLEAN DEFAULT 1,
                    response_time REAL,
                    ip_address TEXT
                )`
            ];

            db.serialize(() => {
                tables.forEach(tableSql => {
                    db.run(tableSql);
                });
            });

            db.close();
            console.log('✅ Database initialized');
        } catch (error) {
            console.error('❌ Database initialization failed:', error.message);
        }
    }

    logCommand(command, source = 'local', success = true, output = '', execution_time = 0, user = null) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);
            user = user || os.userInfo().username;

            db.run(
                `INSERT INTO command_history (command, source, success, output, execution_time, user) VALUES (?, ?, ?, ?, ?, ?)`,
                [command, source, success ? 1 : 0, output.substring(0, 5000), execution_time, user],
                function(err) {
                    if (err) console.error('❌ Error logging command:', err.message);
                }
            );

            db.close();
        } catch (error) {
            console.error('❌ Database error:', error.message);
        }
    }

    saveScanResult(scan_id, target, scan_type, open_ports, services, os_info, vulnerabilities, raw_output, duration = 0, risk_level = 'unknown') {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.run(
                `INSERT INTO scan_results (scan_id, target, scan_type, open_ports, services, os_info, vulnerabilities, raw_output, duration, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    scan_id,
                    target,
                    scan_type,
                    JSON.stringify(open_ports),
                    JSON.stringify(services),
                    os_info,
                    JSON.stringify(vulnerabilities),
                    raw_output.substring(0, 10000),
                    duration,
                    risk_level
                ],
                function(err) {
                    if (err) console.error('❌ Error saving scan result:', err.message);
                }
            );

            db.close();
        } catch (error) {
            console.error('❌ Database error:', error.message);
        }
    }

    getScanResults(limit = 20, callback) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.all(
                'SELECT scan_id, target, scan_type, timestamp, risk_level FROM scan_results ORDER BY timestamp DESC LIMIT ?',
                [limit],
                (err, rows) => {
                    callback(err, rows || []);
                    db.close();
                }
            );
        } catch (error) {
            console.error('❌ Database error:', error.message);
            callback(error, []);
        }
    }

    getScanDetails(scan_id, callback) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.get(
                'SELECT * FROM scan_results WHERE scan_id = ?',
                [scan_id],
                (err, row) => {
                    callback(err, row);
                    db.close();
                }
            );
        } catch (error) {
            console.error('❌ Database error:', error.message);
            callback(error, null);
        }
    }

    logThreat(ip_address, threat_type, severity, description = '', source = 'system', confidence = 0.0) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.run(
                'INSERT INTO threat_logs (ip_address, threat_type, severity, description, source, confidence) VALUES (?, ?, ?, ?, ?, ?)',
                [ip_address, threat_type, severity, description, source, confidence],
                function(err) {
                    if (err) console.error('❌ Error logging threat:', err.message);
                }
            );

            db.close();
        } catch (error) {
            console.error('❌ Database error:', error.message);
        }
    }

    getRecentThreats(limit = 20, callback) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.all(
                'SELECT ip_address, threat_type, severity, timestamp, source, confidence FROM threat_logs ORDER BY timestamp DESC LIMIT ?',
                [limit],
                (err, rows) => {
                    callback(err, rows || []);
                    db.close();
                }
            );
        } catch (error) {
            console.error('❌ Database error:', error.message);
            callback(error, []);
        }
    }

    getMonitoredIps(callback) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.all(
                'SELECT ip_address FROM monitored_ips WHERE is_active = 1',
                [],
                (err, rows) => {
                    const results = rows ? rows.map(row => row.ip_address) : [];
                    callback(err, results);
                    db.close();
                }
            );
        } catch (error) {
            console.error('❌ Database error:', error.message);
            callback(error, []);
        }
    }

    addMonitoredIp(ip, hostname = '', os = '', country = '', notes = '') {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.run(
                `INSERT OR REPLACE INTO monitored_ips (ip_address, hostname, os, country, notes, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
                [ip, hostname, os, country, notes],
                function(err) {
                    if (err) console.error('❌ Error adding monitored IP:', err.message);
                }
            );

            db.close();
        } catch (error) {
            console.error('❌ Database error:', error.message);
        }
    }

    removeMonitoredIp(ip) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.run(
                'UPDATE monitored_ips SET is_active = 0 WHERE ip_address = ?',
                [ip],
                function(err) {
                    if (err) console.error('❌ Error removing monitored IP:', err.message);
                }
            );

            db.close();
        } catch (error) {
            console.error('❌ Database error:', error.message);
        }
    }

    getCommandHistory(limit = 100, callback) {
        try {
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);

            db.all(
                'SELECT * FROM command_history ORDER BY timestamp DESC LIMIT ?',
                [limit],
                (err, rows) => {
                    callback(err, rows || []);
                    db.close();
                }
            );
        } catch (error) {
            console.error('❌ Database error:', error.message);
            callback(error, []);
        }
    }

    saveSystemMetrics() {
        try {
            const osUtils = require('os-utils');
            const diskusage = require('diskusage');
            
            const cpuPercent = osUtils.cpuUsage() * 100;
            const memoryPercent = (1 - osUtils.freememPercentage()) * 100;
            
            let diskPercent = 0;
            try {
                const info = diskusage.checkSync('/');
                diskPercent = (1 - (info.free / info.total)) * 100;
            } catch (diskErr) {
                diskPercent = 0;
            }
            
            const networkInterfaces = os.networkInterfaces();
            let networkSent = 0;
            let networkRecv = 0;
            
            Object.values(networkInterfaces).forEach(iface => {
                iface.forEach(alias => {
                    if (alias.family === 'IPv4' && !alias.internal) {
                        networkSent += alias.bytes || 0;
                        networkRecv += alias.bytes || 0;
                    }
                });
            });
            
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database(this.dbFile);
            
            db.run(
                `INSERT INTO system_metrics (cpu_percent, memory_percent, disk_percent, network_sent, network_recv, connections_count, processes_count) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [cpuPercent, memoryPercent, diskPercent, networkSent, networkRecv, 0, 0],
                function(err) {
                    if (err) console.error('❌ Error saving system metrics:', err.message);
                }
            );
            
            db.close();
        } catch (error) {
            console.error('❌ Failed to save system metrics:', error.message);
        }
    }
}

// =====================
// NETWORK SCANNER
// =====================
class NetworkScanner {
    constructor() {
        this.tracerouteTool = new TracerouteTool();
    }

    isIPv4(ip) {
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipv4Pattern.test(ip)) return false;
        
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }

    isIPv6(ip) {
        const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$/;
        return ipv6Pattern.test(ip);
    }

    async pingIp(ip, count = 4, size = 56, timeout = 10000) {
        try {
            let cmd;
            if (process.platform === 'win32') {
                cmd = `ping -n ${count} -l ${size} -w ${timeout} ${ip}`;
            } else {
                cmd = `ping -c ${count} -s ${size} -W ${Math.ceil(timeout / 1000)} ${ip}`;
            }

            const { stdout, stderr } = await execAsync(cmd, { timeout: timeout + 5000 });
            
            if (stderr) {
                return `Ping ${ip}: failed\n${stderr}`;
            }
            return `Ping ${ip}: successful\n${stdout}`;
        } catch (error) {
            if (error.code === 'ETIMEDOUT' || error.signal === 'SIGTERM') {
                return `Ping ${ip}: timeout`;
            }
            return `Ping error: ${error.message}`;
        }
    }

    async traceroute(target) {
        return await this.tracerouteTool.interactiveTraceroute(target);
    }

    async getIpLocation(ip) {
        try {
            const axios = require('axios');
            const response = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 10000 });
            
            if (response.data.status === 'success') {
                const locationInfo = {
                    ip: ip,
                    country: response.data.country || 'N/A',
                    region: response.data.regionName || 'N/A',
                    city: response.data.city || 'N/A',
                    isp: response.data.isp || 'N/A',
                    org: response.data.org || 'N/A',
                    lat: response.data.lat || 'N/A',
                    lon: response.data.lon || 'N/A',
                    timezone: response.data.timezone || 'N/A'
                };
                return JSON.stringify(locationInfo, null, 2);
            }
            
            // Fallback to DNS
            return new Promise((resolve) => {
                dns.reverse(ip, (err, hostnames) => {
                    if (err || !hostnames) {
                        resolve(JSON.stringify({ ip: ip, error: 'Location lookup failed' }, null, 2));
                    } else {
                        resolve(JSON.stringify({ ip: ip, hostname: hostnames[0] }, null, 2));
                    }
                });
            });
        } catch (error) {
            return `Location error: ${error.message}`;
        }
    }

    async whoisLookup(domain) {
        try {
            const { whois } = require('whois-json');
            const result = await whois(domain);
            return JSON.stringify(result, null, 2);
        } catch (error) {
            return `WHOIS error: ${error.message}. Install with: npm install whois-json`;
        }
    }

    async dnsLookup(domain) {
        try {
            return new Promise((resolve, reject) => {
                dns.resolve4(domain, (err, addresses) => {
                    if (err) {
                        resolve(JSON.stringify({
                            domain: domain,
                            error: err.message
                        }, null, 2));
                    } else {
                        resolve(JSON.stringify({
                            domain: domain,
                            a_records: addresses,
                            mx_records: 'MX lookup requires additional libraries',
                            txt_records: 'TXT lookup requires additional libraries'
                        }, null, 2));
                    }
                });
            });
        } catch (error) {
            return `DNS lookup error: ${error.message}`;
        }
    }

    getNetworkInfo() {
        const info = [];
        info.push('🏢 NETWORK INFORMATION');
        info.push(`System: ${os.type()} ${os.release()}`);
        info.push(`Hostname: ${os.hostname()}`);
        info.push(`Local IP: ${this.getLocalIP()}`);
        
        const interfaces = os.networkInterfaces();
        info.push('\nNetwork Interfaces:');
        
        Object.keys(interfaces).slice(0, 3).forEach(iface => {
            info.push(`  ${iface}:`);
            interfaces[iface].slice(0, 2).forEach(addr => {
                info.push(`    ${addr.family}: ${addr.address}`);
            });
        });
        
        return info.join('\n');
    }

    getLocalIP() {
        const interfaces = os.networkInterfaces();
        for (const iface of Object.values(interfaces)) {
            for (const alias of iface) {
                if (alias.family === 'IPv4' && !alias.internal) {
                    return alias.address;
                }
            }
        }
        return '127.0.0.1';
    }
}

class TracerouteTool {
    isIPv4OrIPv6(address) {
        return this.isIPv4(address) || this.isIPv6(address);
    }

    isIPv4(ip) {
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipv4Pattern.test(ip)) return false;
        
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }

    isIPv6(ip) {
        const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$/;
        return ipv6Pattern.test(ip);
    }

    isValidHostname(name) {
        if (name.length > 255) return false;
        
        if (name.endsWith('.')) {
            name = name.slice(0, -1);
        }
        
        const allowed = /^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/i;
        return allowed.test(name);
    }

    chooseTracerouteCmd(target) {
        if (process.platform === 'win32') {
            return ['tracert', '-d', target];
        }
        return ['traceroute', '-n', '-q', '1', '-w', '2', target];
    }

    async streamSubprocess(cmd) {
        const startTime = performance.now();
        let outputLines = [];
        
        return new Promise((resolve) => {
            const proc = spawn(cmd[0], cmd.slice(1));
            
            proc.stdout.on('data', (data) => {
                const line = data.toString().trim();
                outputLines.push(line);
                console.log(line);
            });
            
            proc.stderr.on('data', (data) => {
                const line = data.toString().trim();
                outputLines.push(line);
                console.log(line);
            });
            
            proc.on('close', (code) => {
                const executionTime = (performance.now() - startTime) / 1000;
                resolve({
                    returncode: code || 0,
                    output: outputLines.join('\n'),
                    execution_time: executionTime
                });
            });
            
            proc.on('error', (err) => {
                const errorMsg = `[!] Error running command: ${err.message}`;
                console.log(errorMsg);
                outputLines.push(errorMsg);
                
                const executionTime = (performance.now() - startTime) / 1000;
                resolve({
                    returncode: -2,
                    output: outputLines.join('\n'),
                    execution_time: executionTime
                });
            });
        });
    }

    async interactiveTraceroute(target = null) {
        if (!target) {
            target = await this.promptTarget();
            if (!target) {
                return 'Traceroute cancelled.';
            }
        }
        
        if (!(this.isIPv4OrIPv6(target) || this.isValidHostname(target))) {
            return `❌ Invalid IP address or hostname: ${target}`;
        }
        
        try {
            const cmd = this.chooseTracerouteCmd(target);
            console.log(`Running: ${cmd.join(' ')}\n`);
            
            const result = await this.streamSubprocess(cmd);
            
            let output = `🛣️ <b>Traceroute to ${target}</b>\n\n`;
            output += `Command: <code>${cmd.join(' ')}</code>\n`;
            output += `Execution time: ${result.execution_time.toFixed(2)}s\n`;
            output += `Return code: ${result.returncode}\n\n`;
            
            if (result.output.length > 3000) {
                output += `<code>${result.output.slice(-3000)}</code>`;
            } else {
                output += `<code>${result.output}</code>`;
            }
            
            return output;
        } catch (error) {
            return `❌ Traceroute error: ${error.message}`;
        }
    }

    async promptTarget() {
        console.log('\n' + '='.repeat(50));
        console.log('🌐 Traceroute Tool');
        console.log('='.repeat(50));
        
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        try {
            while (true) {
                const userInput = await new Promise(resolve => {
                    rl.question('\nEnter target IP address or hostname (or \'quit\' to exit): ', resolve);
                });
                
                if (!userInput) {
                    console.log('Please enter a non-empty value.');
                    continue;
                }
                
                if (userInput.toLowerCase() === 'quit' || userInput.toLowerCase() === 'exit' || userInput.toLowerCase() === 'q') {
                    rl.close();
                    return null;
                }
                
                if (this.isIPv4OrIPv6(userInput) || this.isValidHostname(userInput)) {
                    rl.close();
                    return userInput;
                } else {
                    console.log('Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com');
                }
            }
        } catch (error) {
            rl.close();
            console.log('\nOperation cancelled.');
            return null;
        }
    }
}

// =====================
// ADVANCED NETWORK SCANNER
// =====================
class AdvancedNetworkScanner {
    constructor() {
        this.baseScanner = new NetworkScanner();
        this.nmapAvailable = false;
        this.checkNmapInstallation();
    }

    checkNmapInstallation() {
        try {
            execSync('nmap --version', { stdio: 'pipe' });
            this.nmapAvailable = true;
            console.log('✅ Nmap is installed');
            return true;
        } catch (error) {
            console.log('⚠️ Nmap is not installed or not in PATH');
            this.nmapAvailable = false;
            return false;
        }
    }

    async executeCommand(cmd, timeout = 300000) {
        const startTime = performance.now();
        
        try {
            const { stdout, stderr } = await execAsync(cmd.join(' '), { timeout });
            const executionTime = (performance.now() - startTime) / 1000;
            
            return {
                success: true,
                output: stdout + stderr,
                execution_time: executionTime,
                return_code: 0
            };
        } catch (error) {
            const executionTime = (performance.now() - startTime) / 1000;
            
            if (error.code === 'ETIMEDOUT') {
                return {
                    success: false,
                    output: 'Command timed out after 5 minutes',
                    execution_time: executionTime,
                    return_code: -1
                };
            }
            
            return {
                success: false,
                output: `Error: ${error.message}`,
                execution_time: executionTime,
                return_code: -2
            };
        }
    }

    async performNmapScan(target, scanType, options = {}) {
        const scanId = crypto.createHash('md5').update(`${target}${scanType}${Date.now()}`).digest('hex').slice(0, 16);
        
        let scanOptions = NMAP_SCAN_TYPES[scanType] || scanType;
        let cmd = ['nmap', target, ...scanOptions.split(' ')];
        
        if (options.ports) {
            cmd = cmd.filter(arg => arg !== '-F');
            cmd.push('-p', options.ports);
        }
        
        if (options.timing) {
            cmd.push('-T', options.timing.toString());
        }
        
        console.log(`Running Nmap scan: ${cmd.join(' ')}`);
        
        const startTime = performance.now();
        try {
            const result = await this.executeCommand(cmd);
            
            const parsedResult = this.parseNmapOutput(result.output);
            const vulnerabilities = this.analyzeVulnerabilities(parsedResult);
            
            return new ScanResult(
                scanId,
                result.success,
                target,
                scanType,
                cmd.join(' '),
                result.execution_time,
                parsedResult,
                vulnerabilities,
                result.output
            );
        } catch (error) {
            const executionTime = (performance.now() - startTime) / 1000;
            return new ScanResult(
                scanId,
                false,
                target,
                scanType,
                cmd.join(' '),
                executionTime,
                {},
                [],
                `Error: ${error.message}`
            );
        }
    }

    parseNmapOutput(output) {
        const lines = output.split('\n');
        const result = {
            host: '',
            status: '',
            addresses: [],
            ports: [],
            os: '',
            services: []
        };
        
        let currentPort = null;
        
        for (const line of lines) {
            if (line.includes('Nmap scan report for')) {
                result.host = line.replace('Nmap scan report for', '').trim();
            } else if (line.includes('Host is up')) {
                result.status = 'up';
            } else if (line.includes('Host seems down')) {
                result.status = 'down';
            } else if (/^\d+\/(tcp|udp)\s+(open|closed|filtered)/.test(line)) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 3) {
                    const portParts = parts[0].split('/');
                    currentPort = {
                        port: parseInt(portParts[0]),
                        protocol: portParts[1],
                        state: parts[1],
                        service: parts[2] || 'unknown'
                    };
                    result.ports.push(currentPort);
                }
            } else if (line.includes('Service Info:')) {
                result.os = line.replace('Service Info:', '').trim();
            } else if (currentPort && line.trim().startsWith('|')) {
                currentPort.version = line.trim().slice(1).trim();
            }
        }
        
        return result;
    }

    analyzeVulnerabilities(scanResult) {
        const vulnerabilities = [];
        const criticalPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5900, 8080, 8443];
        const weakServices = ['telnet', 'ftp', 'smtp', 'pop3', 'imap', 'vnc', 'snmp'];
        
        for (const portInfo of scanResult.ports || []) {
            const vuln = { port: portInfo.port, issues: [] };
            
            if (criticalPorts.includes(portInfo.port) && portInfo.state === 'open') {
                vuln.issues.push(`Critical port ${portInfo.port} is open`);
            }
            
            if (weakServices.some(weak => portInfo.service.toLowerCase().includes(weak))) {
                vuln.issues.push(`Weak service ${portInfo.service} detected`);
            }
            
            if (portInfo.service.toLowerCase().includes('http') || portInfo.service.toLowerCase().includes('web')) {
                vuln.issues.push('Web service detected - check for default credentials');
            }
            
            if (portInfo.version && ['old', 'beta', 'test', 'debug'].some(x => portInfo.version.toLowerCase().includes(x))) {
                vuln.issues.push(`Potential outdated version: ${portInfo.version}`);
            }
            
            if (vuln.issues.length > 0) {
                vulnerabilities.push(vuln);
            }
        }
        
        return vulnerabilities;
    }

    async networkDiscovery(networkRange) {
        const cmd = ['nmap', '-sn', networkRange];
        
        try {
            const result = await this.executeCommand(cmd);
            
            if (!result.success) {
                return { success: false, error: result.output };
            }
            
            const lines = result.output.split('\n');
            const hosts = [];
            
            for (const line of lines) {
                const ipMatch = line.match(/Nmap scan report for (?:[a-zA-Z0-9.-]+ )?\(?(\d+\.\d+\.\d+\.\d+)\)?/);
                if (ipMatch) {
                    hosts.push(ipMatch[1]);
                }
            }
            
            return {
                success: true,
                network: networkRange,
                hosts: hosts,
                count: hosts.length,
                execution_time: result.execution_time,
                raw_output: result.output
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async stealthScan(target) {
        const cmd = ['nmap', '-sS', '-T2', '-f', target];
        
        try {
            const result = await this.executeCommand(cmd);
            
            return {
                success: result.success,
                target: target,
                scan_type: 'stealth',
                execution_time: result.execution_time,
                output: result.output,
                raw_output: result.output.slice(0, 3000)
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async osDetection(target) {
        const cmd = ['nmap', '-O', '--osscan-guess', target];
        
        try {
            const result = await this.executeCommand(cmd);
            
            return {
                success: result.success,
                target: target,
                scan_type: 'os_detection',
                execution_time: result.execution_time,
                output: result.output,
                raw_output: result.output.slice(0, 3000)
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async serviceDetection(target) {
        const cmd = ['nmap', '-sV', '--version-intensity', '5', target];
        
        try {
            const result = await this.executeCommand(cmd);
            
            return {
                success: result.success,
                target: target,
                scan_type: 'service_detection',
                execution_time: result.execution_time,
                output: result.output,
                raw_output: result.output.slice(0, 3000)
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    saveScanToFile(scanResult, filename = null) {
        if (!filename) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            filename = `scan_${scanResult.target.replace(/\./g, '_')}_${timestamp}.json`;
        }
        
        const filepath = path.join(SCAN_RESULTS_DIR, filename);
        
        fs.writeFileSync(filepath, JSON.stringify(scanResult, null, 2));
        
        console.log(`Scan saved to: ${filepath}`);
        return filepath;
    }
}

// =====================
// TELEGRAM BOT HANDLER
// =====================
class TelegramBotHandler {
    constructor(config, dbManager, scanner, advancedScanner) {
        this.config = config;
        this.db = dbManager;
        this.scanner = scanner;
        this.advancedScanner = advancedScanner;
        this.lastUpdateId = 0;
        this.commandHandlers = this.setupCommandHandlers();
    }

    setupCommandHandlers() {
        const handlers = {
            // Basic commands
            '/start': this.handleStart.bind(this),
            '/help': this.handleHelp.bind(this),
            '/commands': this.handleCommands.bind(this),
            
            // Ping commands
            '/ping': this.handlePing.bind(this),
            
            // Nmap commands
            '/nmap': this.handleNmap.bind(this),
            
            // Quick scans
            '/quick_scan': this.handleQuickScan.bind(this),
            '/deep_scan': this.handleDeepScan.bind(this),
            '/stealth_scan': this.handleStealthScan.bind(this),
            '/vuln_scan': this.handleVulnScan.bind(this),
            '/full_scan': this.handleFullScan.bind(this),
            
            // Network tools
            '/traceroute': this.handleTraceroute.bind(this),
            '/whois': this.handleWhois.bind(this),
            '/dns': this.handleDns.bind(this),
            '/analyze': this.handleAnalyze.bind(this),
            '/location': this.handleLocation.bind(this),
            
            // System commands
            '/system': this.handleSystem.bind(this),
            '/network': this.handleNetwork.bind(this),
            '/status': this.handleStatus.bind(this),
            '/metrics': this.handleMetrics.bind(this),
            
            // Management
            '/history': this.handleHistory.bind(this),
            '/scans': this.handleScans.bind(this),
            '/threats': this.handleThreats.bind(this),
            '/report': this.handleReport.bind(this),
            
            // Utilities
            '/test': this.handleTest.bind(this),
        };
        
        return handlers;
    }

    async handleStart(args) {
        return this.getCommandsList();
    }

    async handleHelp(args) {
        return `
<b>🕸️ Spider Bot v.0.0.1</b>

<b>🔧 AVAILABLE COMMANDS</b>

<code>/ping 8.8.8.8</code> - Basic ping
<code>/nmap 192.168.1.1</code> - Basic scan
<code>/quick_scan 192.168.1.1</code> - Quick scan
<code>/deep_scan 192.168.1.1</code> - Deep scan
<code>/stealth_scan 192.168.1.1</code> - Stealth scan
<code>/vuln_scan 192.168.1.1</code> - Vulnerability scan
<code>/full_scan 192.168.1.1</code> - Full port scan

<code>/traceroute example.com</code> - Route tracing
<code>/whois example.com</code> - WHOIS lookup
<code>/analyze 1.1.1.1</code> - IP analysis
<code>/location 8.8.8.8</code> - Geolocation

<code>/system</code> - System information
<code>/network</code> - Network info
<code>/status</code> - Bot status
<code>/metrics</code> - System metrics

<code>/history</code> - Command history
<code>/scans</code> - Scan history
<code>/threats</code> - Threat summary
<code>/report</code> - Generate report

💡 All commands execute instantly! Type any command to use.
        `;
    }

    getCommandsList() {
        const commands = {
            "🏓 Ping Commands": [
                "/ping [ip] - Basic ping"
            ],
            "🔍 Scanning": [
                "/nmap [ip] - Basic scan",
                "/quick_scan [ip] - Quick scan",
                "/deep_scan [ip] - Deep scan",
                "/stealth_scan [ip] - Stealth scan",
                "/vuln_scan [ip] - Vulnerability scan",
                "/full_scan [ip] - Full port scan"
            ],
            "🌐 Network Tools": [
                "/traceroute [target] - Route tracing",
                "/whois [domain] - WHOIS lookup",
                "/dns [domain] - DNS lookup",
                "/analyze [ip] - IP analysis",
                "/location [ip] - Geolocation"
            ],
            "💻 System Info": [
                "/system - System information",
                "/network - Network info",
                "/metrics - System metrics",
                "/status - Bot status",
                "/history - Command history"
            ],
            "📊 Management": [
                "/scans - Scan history",
                "/threats - Threat summary",
                "/report - Generate report"
            ]
        };
        
        let result = "🕸️ <b>Spider Bot v0.0.1🕷️</b>\n\n";
        result += "📋 <b>AVAILABLE COMMANDS</b>\n\n";
        
        for (const [category, cmdList] of Object.entries(commands)) {
            result += `<b>${category}</b>\n`;
            cmdList.forEach(cmd => {
                result += `• ${cmd}\n`;
            });
            result += "\n";
        }
        
        result += "💡 <i>Type any command to execute instantly!</i>";
        
        return result;
    }

    async handleCommands(args) {
        return this.getCommandsList();
    }

    async handlePing(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/ping [IP]</code>";
        }
        
        const result = await this.scanner.pingIp(args[0]);
        return `🏓 <b>Ping Results</b>\n\n<pre>${result.slice(-1000)}</pre>`;
    }

    async handleNmap(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/nmap [IP]</code>";
        }
        
        await this.config.sendMessage("🔍 <b>Starting Nmap scan...</b>");
        const result = await this.advancedScanner.executeCommand(['nmap', ...args]);
        
        if (!result.success) {
            return `❌ Scan failed: ${result.output}`;
        }
        
        return `🔍 <b>Nmap Results</b>\n\n<pre>${result.output.slice(-3000)}</pre>`;
    }

    async handleQuickScan(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/quick_scan [IP]</code>";
        }
        
        const target = args[0];
        await this.config.sendMessage(`🔍 <b>Starting quick scan on ${target}...</b>`);
        
        const result = await this.advancedScanner.performNmapScan(target, 'quick');
        
        if (!result.success) {
            return `❌ Quick scan failed: ${result.raw_output}`;
        }
        
        let response = `⚡ <b>Quick Scan Results: ${target}</b>\n\n`;
        response += `Time: ${result.execution_time.toFixed(2)}s\n\n`;
        
        const openPorts = result.result.ports ? result.result.ports.filter(p => p.state === 'open') : [];
        response += `🔓 <b>Open Ports: ${openPorts.length}</b>\n`;
        
        openPorts.slice(0, 10).forEach(port => {
            response += `Port ${port.port}/${port.protocol}: ${port.service}\n`;
        });
        
        this.db.saveScanResult(
            result.scan_id,
            target,
            'quick',
            result.result.ports || [],
            result.result.services || [],
            result.result.os || '',
            result.vulnerabilities,
            result.raw_output,
            result.execution_time
        );
        
        const savePath = this.advancedScanner.saveScanToFile(result);
        response += `\n💾 Scan saved to: ${savePath}`;
        response += `\n📄 Scan ID: <code>${result.scan_id}</code>`;
        
        return response;
    }

    async handleDeepScan(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/deep_scan [IP]</code>";
        }
        
        const target = args[0];
        await this.config.sendMessage(`🔍 <b>Starting deep scan on ${target}...</b>`);
        
        const result = await this.advancedScanner.performNmapScan(target, 'comprehensive');
        
        if (!result.success) {
            return `❌ Deep scan failed: ${result.raw_output}`;
        }
        
        let response = `🔍 <b>Deep Scan Results: ${target}</b>\n\n`;
        response += `Time: ${result.execution_time.toFixed(2)}s\n`;
        response += `Status: ${result.result.status || 'unknown'}\n\n`;
        
        const openPorts = result.result.ports ? result.result.ports.filter(p => p.state === 'open') : [];
        response += `🔓 <b>Open Ports: ${openPorts.length}</b>\n`;
        
        openPorts.slice(0, 15).forEach(port => {
            let portStr = `Port ${port.port}/${port.protocol}: ${port.service}`;
            if (port.version) {
                portStr += ` (${port.version})`;
            }
            response += `${portStr}\n`;
        });
        
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            response += `\n⚠️ <b>Vulnerabilities: ${result.vulnerabilities.length}</b>\n`;
            result.vulnerabilities.slice(0, 5).forEach(vuln => {
                response += `Port ${vuln.port}: ${vuln.issues[0]}\n`;
            });
        }
        
        this.db.saveScanResult(
            result.scan_id,
            target,
            'deep',
            result.result.ports || [],
            result.result.services || [],
            result.result.os || '',
            result.vulnerabilities,
            result.raw_output,
            result.execution_time
        );
        
        const savePath = this.advancedScanner.saveScanToFile(result);
        response += `\n💾 Scan saved to: ${savePath}`;
        response += `\n📄 Scan ID: <code>${result.scan_id}</code>`;
        
        return response;
    }

    async handleStealthScan(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/stealth_scan [IP]</code>";
        }
        
        const target = args[0];
        await this.config.sendMessage(`🕵️ <b>Starting stealth scan on ${target}...</b>`);
        
        const result = await this.advancedScanner.stealthScan(target);
        
        if (!result.success) {
            return `❌ Stealth scan failed: ${result.error}`;
        }
        
        let response = `🕵️ <b>Stealth Scan Results: ${target}</b>\n\n`;
        response += `Time: ${result.execution_time.toFixed(2)}s\n\n`;
        response += `<pre>${result.output.slice(-2000)}</pre>`;
        
        return response;
    }

    async handleVulnScan(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/vuln_scan [IP]</code>";
        }
        
        const target = args[0];
        await this.config.sendMessage(`⚠️ <b>Starting vulnerability scan on ${target}...</b>`);
        
        const result = await this.advancedScanner.performNmapScan(target, 'vulnerability');
        
        if (!result.success) {
            return `❌ Vulnerability scan failed: ${result.raw_output}`;
        }
        
        let response = `⚠️ <b>Vulnerability Scan: ${target}</b>\n\n`;
        response += `Time: ${result.execution_time.toFixed(2)}s\n`;
        
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            response += `⚠️ <b>Found ${result.vulnerabilities.length} potential vulnerabilities:</b>\n\n`;
            
            result.vulnerabilities.slice(0, 10).forEach((vuln, i) => {
                response += `${i + 1}. Port ${vuln.port}:\n`;
                vuln.issues.slice(0, 3).forEach(issue => {
                    response += `   - ${issue}\n`;
                });
                response += "\n";
            });
            
            if (result.vulnerabilities.length > 10) {
                response += `... and ${result.vulnerabilities.length - 10} more vulnerabilities\n`;
            }
        } else {
            response += "✅ No vulnerabilities detected";
        }
        
        this.db.saveScanResult(
            result.scan_id,
            target,
            'vulnerability',
            result.result.ports || [],
            result.result.services || [],
            result.result.os || '',
            result.vulnerabilities,
            result.raw_output,
            result.execution_time
        );
        
        const savePath = this.advancedScanner.saveScanToFile(result);
        response += `\n💾 Scan saved to: ${savePath}`;
        response += `\n📄 Scan ID: <code>${result.scan_id}</code>`;
        
        return response;
    }

    async handleFullScan(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/full_scan [IP]</code>\nWarning: This scans ALL 65535 ports!";
        }
        
        const target = args[0];
        await this.config.sendMessage(`⏳ <b>Starting FULL port scan on ${target}... This may take several minutes.</b>`);
        
        const result = await this.advancedScanner.performNmapScan(target, 'full');
        
        if (!result.success) {
            return `❌ Full scan failed: ${result.raw_output}`;
        }
        
        let response = `🔍 <b>Full Port Scan: ${target}</b>\n\n`;
        response += `Time: ${result.execution_time.toFixed(2)}s\n`;
        
        const openPorts = result.result.ports ? result.result.ports.filter(p => p.state === 'open') : [];
        response += `🔓 <b>Total Open Ports: ${openPorts.length}</b>\n\n`;
        
        openPorts.slice(0, 20).forEach(port => {
            let portStr = `Port ${port.port}/${port.protocol}: ${port.service}`;
            if (port.version) {
                portStr += ` (${port.version})`;
            }
            response += `${portStr}\n`;
        });
        
        if (openPorts.length > 20) {
            response += `... and ${openPorts.length - 20} more\n`;
        }
        
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            response += `\n⚠️ <b>Vulnerabilities: ${result.vulnerabilities.length}</b>\n`;
            result.vulnerabilities.slice(0, 5).forEach(vuln => {
                response += `Port ${vuln.port}: ${vuln.issues[0]}\n`;
            });
        }
        
        this.db.saveScanResult(
            result.scan_id,
            target,
            'full',
            result.result.ports || [],
            result.result.services || [],
            result.result.os || '',
            result.vulnerabilities,
            result.raw_output,
            result.execution_time
        );
        
        const savePath = this.advancedScanner.saveScanToFile(result);
        response += `\n💾 Scan saved to: ${savePath}`;
        response += `\n📄 Scan ID: <code>${result.scan_id}</code>`;
        
        return response;
    }

    async handleTraceroute(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/traceroute [target]</code>";
        }
        
        await this.config.sendMessage("🛣️ <b>Starting traceroute...</b>");
        const result = await this.scanner.traceroute(args[0]);
        return result;
    }

    async handleWhois(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/whois [domain]</code>";
        }
        
        const result = await this.scanner.whoisLookup(args[0]);
        return `🔍 <b>WHOIS: ${args[0]}</b>\n\n<pre>${result.slice(0, 1500)}</pre>`;
    }

    async handleDns(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/dns [domain]</code>";
        }
        
        const result = await this.scanner.dnsLookup(args[0]);
        return `🌐 <b>DNS Lookup: ${args[0]}</b>\n\n<pre>${result.slice(0, 1000)}</pre>`;
    }

    async handleAnalyze(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/analyze [IP]</code>";
        }
        
        const ip = args[0];
        let response = `🔍 <b>Analysis: ${ip}</b>\n\n`;
        
        try {
            const location = await this.scanner.getIpLocation(ip);
            const locData = JSON.parse(location);
            
            response += `📍 <b>Location:</b>\n`;
            response += `  City: ${locData.city || 'N/A'}\n`;
            response += `  Region: ${locData.region || 'N/A'}\n`;
            response += `  Country: ${locData.country || 'N/A'}\n`;
            response += `  ISP: ${locData.isp || locData.org || 'N/A'}\n\n`;
        } catch (error) {
            // Continue without location
        }
        
        try {
            const pingResult = await this.scanner.pingIp(ip, 2);
            if (pingResult.includes('successful')) {
                response += `🏓 <b>Ping:</b> ✅ Reachable\n\n`;
            } else {
                response += `🏓 <b>Ping:</b> ❌ Unreachable\n\n`;
            }
        } catch (error) {
            // Continue without ping
        }
        
        this.db.getRecentThreats(5, (err, threats) => {
            if (!err && threats) {
                const ipThreats = threats.filter(t => t.ip_address === ip);
                if (ipThreats.length > 0) {
                    response += `⚠️ <b>Threats Found: ${ipThreats.length}</b>\n`;
                    ipThreats.slice(0, 3).forEach(threat => {
                        response += `• ${threat.threat_type}: ${threat.severity}\n`;
                    });
                } else {
                    response += "✅ No recent threats detected\n";
                }
            } else {
                response += `⚠️ Could not check threats\n`;
            }
        });
        
        return response;
    }

    async handleLocation(args) {
        if (!args || args.length === 0) {
            return "❌ Usage: <code>/location [IP]</code>";
        }
        
        const result = await this.scanner.getIpLocation(args[0]);
        return `📍 <b>Location: ${args[0]}</b>\n\n<pre>${result}</pre>`;
    }

    async handleSystem(args) {
        const result = this.scanner.getNetworkInfo();
        return `💻 <b>System Information</b>\n\n<pre>${result}</pre>`;
    }

    async handleNetwork(args) {
        const hostname = os.hostname();
        const localIp = this.scanner.getLocalIP();
        
        let result = `🌐 <b>Network Information</b>\n\n`;
        result += `Hostname: ${hostname}\n`;
        result += `Local IP: ${localIp}\n`;
        
        return result;
    }

    async handleStatus(args) {
        const osUtils = require('os-utils');
        const cpuPercent = await new Promise(resolve => {
            osUtils.cpuUsage(resolve);
        });
        
        let result = `📊 <b>System Status</b>\n\n`;
        result += `✅ Bot: ${this.config.token ? 'Online' : 'Offline'}\n`;
        result += `🔍 Nmap: ${this.advancedScanner.nmapAvailable ? 'Available' : 'Not Available'}\n`;
        result += `💻 CPU: ${(cpuPercent * 100).toFixed(1)}%\n`;
        result += `🧠 Memory: ${(100 - (osUtils.freememPercentage() * 100)).toFixed(1)}%\n`;
        
        return result;
    }

    async handleMetrics(args) {
        const osUtils = require('os-utils');
        const diskusage = require('diskusage');
        
        const cpuPercent = await new Promise(resolve => {
            osUtils.cpuUsage(resolve);
        });
        
        const memPercent = (1 - osUtils.freememPercentage()) * 100;
        
        let diskPercent = 0;
        try {
            const info = diskusage.checkSync('/');
            diskPercent = (1 - (info.free / info.total)) * 100;
        } catch (error) {
            diskPercent = 0;
        }
        
        let result = `📈 <b>System Metrics</b>\n\n`;
        result += `💻 <b>CPU:</b>\n`;
        result += `  Total Usage: ${(cpuPercent * 100).toFixed(1)}%\n\n`;
        
        result += `🧠 <b>Memory:</b>\n`;
        result += `  Total: ${(os.totalmem() / (1024 ** 3)).toFixed(2)} GB\n`;
        result += `  Used: ${((os.totalmem() - os.freemem()) / (1024 ** 3)).toFixed(2)} GB (${memPercent.toFixed(1)}%)\n`;
        result += `  Available: ${(os.freemem() / (1024 ** 3)).toFixed(2)} GB\n\n`;
        
        result += `💾 <b>Disk:</b>\n`;
        result += `  Used: ${diskPercent.toFixed(1)}%\n`;
        
        return result;
    }

    async handleHistory(args) {
        return new Promise((resolve) => {
            this.db.getCommandHistory(15, (err, history) => {
                if (err || !history || history.length === 0) {
                    resolve("📜 No commands recorded");
                    return;
                }
                
                let response = "📜 <b>Command History</b>\n\n";
                
                history.slice(0, 15).forEach((row, i) => {
                    const status = row.success ? "✅" : "❌";
                    const timestamp = row.timestamp.split('.')[0];
                    response += `${i + 1}. ${status} [${row.source}] ${row.command.slice(0, 50)} | ${timestamp}\n`;
                });
                
                resolve(response);
            });
        });
    }

    async handleScans(args) {
        return new Promise((resolve) => {
            this.db.getScanResults(10, (err, scans) => {
                if (err || !scans || scans.length === 0) {
                    resolve("📊 No scan results found");
                    return;
                }
                
                let response = "📄 <b>Scan History</b>\n\n";
                
                scans.forEach((scan, i) => {
                    response += `${i + 1}. <b>${scan.target}</b>\n`;
                    response += `   Type: ${scan.scan_type}\n`;
                    response += `   Time: ${scan.timestamp}\n`;
                    response += `   Risk: ${scan.risk_level || 'unknown'}\n`;
                    response += `   ID: <code>${scan.scan_id}</code>\n\n`;
                });
                
                resolve(response);
            });
        });
    }

    async handleThreats(args) {
        return new Promise((resolve) => {
            this.db.getRecentThreats(10, (err, threats) => {
                if (err || !threats || threats.length === 0) {
                    resolve("✅ No recent threats detected");
                    return;
                }
                
                let response = "⚠️ <b>Recent Threats</b>\n\n";
                
                threats.forEach(threat => {
                    response += `• <code>${threat.ip_address}</code>\n`;
                    response += `  Type: ${threat.threat_type} | Severity: ${threat.severity}\n`;
                    response += `  Source: ${threat.source || 'unknown'}\n`;
                    response += `  Time: ${threat.timestamp}\n\n`;
                });
                
                resolve(response);
            });
        });
    }

    async handleReport(args) {
        return new Promise((resolve) => {
            this.db.getRecentThreats(50, (err, threats) => {
                this.db.getScanResults(50, (err2, scanResults) => {
                    this.db.getCommandHistory(100, (err3, history) => {
                        const report = {
                            generated_at: new Date().toISOString(),
                            system: {
                                nmap_available: this.advancedScanner.nmapAvailable,
                                telegram_configured: !!(this.config.token && this.config.chat_id)
                            },
                            statistics: {
                                total_threats: threats ? threats.length : 0,
                                total_scans: scanResults ? scanResults.length : 0,
                                high_severity: threats ? threats.filter(t => t.severity === 'high').length : 0,
                                medium_severity: threats ? threats.filter(t => t.severity === 'medium').length : 0,
                                low_severity: threats ? threats.filter(t => t.severity === 'low').length : 0,
                                commands_executed: history ? history.length : 0
                            }
                        };
                        
                        const filename = `security_report_${Date.now()}.json`;
                        const filepath = path.join(REPORT_DIR, filename);
                        
                        fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
                        
                        let response = "📊 <b>Security Report Generated</b>\n\n";
                        response += `Total Threats: ${report.statistics.total_threats}\n`;
                        response += `Total Scans: ${report.statistics.total_scans}\n`;
                        response += `High Severity: ${report.statistics.high_severity}\n`;
                        response += `Medium Severity: ${report.statistics.medium_severity}\n`;
                        response += `Low Severity: ${report.statistics.low_severity}\n`;
                        response += `Commands Executed: ${report.statistics.commands_executed}\n`;
                        response += `\n✅ Report saved: <code>${filename}</code>`;
                        
                        resolve(response);
                    });
                });
            });
        });
    }

    async handleTest(args) {
        return "✅ Bot is working correctly!";
    }

    async sendMessage(message, parse_mode = 'HTML', disable_preview = true) {
        return this.config.sendMessage(message, parse_mode, disable_preview);
    }

    async processUpdates() {
        if (!this.config.token || !this.config.chat_id) {
            return;
        }
        
        try {
            const axios = require('axios');
            const url = `https://api.telegram.org/bot${this.config.token}/getUpdates`;
            const params = {
                offset: this.lastUpdateId + 1,
                timeout: 30
            };
            
            const response = await axios.get(url, { params, timeout: 35000 });
            
            if (response.status === 200) {
                const data = response.data;
                if (data.ok) {
                    const updates = data.result || [];
                    
                    for (const update of updates) {
                        if (update.message) {
                            await this.processMessage(update.message);
                        }
                        
                        if (update.update_id) {
                            this.lastUpdateId = update.update_id;
                        }
                    }
                }
            }
        } catch (error) {
            console.error('❌ Telegram update error:', error.message);
        }
    }

    async processMessage(message) {
        if (!message.text) {
            return;
        }
        
        const text = message.text;
        const chat_id = message.chat.id;
        
        if (!this.config.chat_id) {
            this.config.chat_id = chat_id.toString();
            this.config.saveConfig();
        }
        
        const parts = text.split(/\s+/);
        if (parts.length === 0) {
            return;
        }
        
        const command = parts[0];
        const args = parts.slice(1);
        
        this.db.logCommand(text, 'telegram', true);
        
        if (this.commandHandlers[command]) {
            try {
                const response = await this.commandHandlers[command](args);
                await this.sendMessage(response);
                console.log(`✅ Telegram command executed: ${command}`);
            } catch (error) {
                const errorMsg = `❌ Error executing command: ${error.message.slice(0, 200)}`;
                await this.sendMessage(errorMsg);
                console.error(`❌ Command error: ${error.message}`);
            }
        } else {
            await this.sendMessage("❌ Unknown command. Type /help for available commands.");
        }
    }

    async run() {
        console.log("Starting Telegram bot");
        
        if (!this.config.token || !this.config.chat_id) {
            console.log("⚠️ Telegram not configured. Bot not started.");
            return;
        }
        
        await this.sendMessage(
            "🚀 <b>Spider Bot v0.0.1</b>\n\n" +
            "✅ Bot is online and ready!\n" +
            "🔧 Commands available\n" +
            "🛡️ Security monitoring active\n\n" +
            "Type /help for complete command list"
        );
        
        while (true) {
            try {
                await this.processUpdates();
                await new Promise(resolve => setTimeout(resolve, 2000));
            } catch (error) {
                console.error('❌ Telegram bot error:', error.message);
                await new Promise(resolve => setTimeout(resolve, 10000));
            }
        }
    }
}

// =====================
// MAIN APPLICATION
// =====================
class AccurateOnlineOS {
    constructor() {
        this.db = new DatabaseManager();
        this.telegramConfig = new TelegramConfig();
        this.scanner = new NetworkScanner();
        this.advancedScanner = new AdvancedNetworkScanner();
        this.telegramBot = new TelegramBotHandler(
            this.telegramConfig,
            this.db,
            this.scanner,
            this.advancedScanner
        );
        
        this.running = true;
        this.telegramTask = null;
    }

    printBanner() {
        console.clear();
        
        const banner = `
╔══════════════════════════════════════════════════════╗
║                                                      ║
║                🕸️ Spider Bot 🕸️                      ║
║                                                      ║
║                                                      ║
║                                                      ║
║          🔍 Professional Network Scanner             ║
║          🌐 Telegram Commands                        ║
║          ⚠️ Vulnerability Assessment                 ║
║          💾 Comprehensive Reporting                  ║
║                                                      ║
║          Author: Ian Carter Kulani                   ║
║          Version: v0.0.1                             ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
`;
        console.log(banner);
        
        console.log("\n📊 SYSTEM STATUS:");
        console.log(`  Nmap: ${this.advancedScanner.nmapAvailable ? '✅ READY' : '⚠️ NOT INSTALLED'}`);
        console.log(`  Telegram: ${this.telegramConfig.enabled ? '✅ CONNECTED' : '⚠️ NOT CONFIGURED'}`);
        console.log(`  Database: ✅ READY`);
        console.log(`  Commands: AVAILABLE`);
        console.log("\n" + "=".repeat(80));
    }

    printHelp() {
        const helpText = `
🛠️  ADVANCED CYBERSECURITY COMMANDS 🛠️

🤖 TELEGRAM:
  setup_telegram      - Configure Telegram bot for commands
  test_telegram       - Test Telegram connection

🔍 SCANNING & ANALYSIS:
  ping <ip>           - Ping IP address
  traceroute <ip>     - Traceroute to target
  nmap <ip>           - Nmap scan with options
  quick_scan <ip>     - Quick network scan
  deep_scan <ip>      - Deep comprehensive scan
  stealth_scan <ip>   - Stealth SYN scan
  vuln_scan <ip>      - Vulnerability scan
  full_scan <ip>      - Full port scan (65535 ports)
  network_discovery   - Discover hosts in network
  analyze <ip>        - Comprehensive IP analysis
  whois <domain>      - WHOIS lookup
  dns <domain>        - DNS lookup
  location <ip>       - IP geolocation

🌐 NETWORK TOOLS:
  network_info        - Local network information
  system_info         - Detailed system information
  scan_history        - View scan results
  scan_details <id>   - View scan details
  generate_report     - Generate security report

📊 SYSTEM & MONITORING:
  status              - System status
  metrics             - System metrics
  history             - Command history
  threats             - Threat summary
  monitored_ips       - List monitored IPs
  add_ip <ip>         - Add IP to monitoring
  remove_ip <ip>      - Remove IP from monitoring

⚙️  CONFIGURATION:
  config              - Show configuration
  clear               - Clear screen
  help                - Show this help
  exit                - Exit program
`;
        console.log(helpText);
        
        if (this.telegramConfig.enabled) {
            console.log("✅ Telegram bot is active! Send /start to your bot for commands");
        } else {
            console.log("⚠️ Telegram not configured. Type 'setup_telegram' to enable remote commands");
        }
    }

    startTelegramBot() {
        if (this.telegramConfig.enabled && !this.telegramTask) {
            try {
                this.telegramTask = this.telegramBot.run();
                console.log("✅ Telegram bot started in background");
            } catch (error) {
                console.error(`❌ Failed to start Telegram bot: ${error.message}`);
            }
        }
    }

    async setupTelegram() {
        if (await this.telegramConfig.interactiveSetup()) {
            this.startTelegramBot();
        }
    }

    async testTelegram() {
        if (!this.telegramConfig.token || !this.telegramConfig.chat_id) {
            console.log("❌ Telegram not configured. Run 'setup_telegram' first.");
            return;
        }
        
        console.log("\n🔌 Testing Telegram connection...");
        const { success, message } = await this.telegramConfig.testConnection();
        
        if (success) {
            console.log(`✅ ${message}`);
        } else {
            console.log(`❌ ${message}`);
        }
    }

    async handleLocalCommands() {
        this.printBanner();
        console.log("\n💻 Local terminal commands available");
        console.log("📋 Type 'help' for command list\n");
        console.log(`📁 Scan results directory: ${SCAN_RESULTS_DIR}`);
        console.log(`📁 Reports directory: ${REPORT_DIR}`);
        console.log("\n");
        
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        while (this.running) {
            try {
                const command = await new Promise(resolve => {
                    rl.question('spiderbot🕸️> ', resolve);
                });
                
                if (!command.trim()) {
                    continue;
                }
                
                if (command.toLowerCase() === 'exit') {
                    console.log("👋 Exiting...");
                    this.running = false;
                    break;
                }
                
                await this.processLocalCommand(command.trim());
                
            } catch (error) {
                if (error.message.includes('SIGINT')) {
                    console.log("\n👋 Exiting...");
                    this.running = false;
                    break;
                }
                console.error(`❌ Error: ${error.message}`);
            }
        }
        
        rl.close();
    }

    async processLocalCommand(command) {
        this.db.logCommand(command, 'local', true);
        
        const parts = command.split(/\s+/);
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1);
        
        if (cmd === 'help') {
            this.printHelp();
        } else if (cmd === 'clear') {
            console.clear();
            this.printBanner();
        } else if (cmd === 'setup_telegram') {
            await this.setupTelegram();
        } else if (cmd === 'test_telegram') {
            await this.testTelegram();
        } else if (cmd === 'ping' && args.length > 0) {
            const ip = args[0];
            let count = 4;
            
            if (args.length > 1) {
                count = parseInt(args[1]) || 4;
            }
            
            console.log(`\n🏓 Pinging ${ip} with ${count} packets...`);
            const result = await this.scanner.pingIp(ip, count);
            console.log(result);
        } else if (cmd === 'traceroute' && args.length > 0) {
            const target = args[0];
            console.log(`\n🛣️ Traceroute to ${target}...`);
            const result = await this.scanner.traceroute(target);
            console.log(result);
        } else if (cmd === 'nmap' && args.length > 0) {
            const target = args[0];
            const nmapArgs = args.slice(1);
            console.log(`\n🔍 Starting Nmap scan on ${target}...`);
            
            const cmdList = ['nmap', target, ...nmapArgs];
            const result = await this.advancedScanner.executeCommand(cmdList);
            
            if (result.success) {
                console.log(result.output.slice(0, 2000));
            } else {
                console.log(`❌ Scan failed: ${result.output}`);
            }
        } else if (cmd === 'quick_scan' && args.length > 0) {
            const target = args[0];
            console.log(`\n⚡ Quick scan on ${target}...`);
            const result = await this.advancedScanner.performNmapScan(target, 'quick');
            this.displayScanResult(result, target, 'quick');
        } else if (cmd === 'deep_scan' && args.length > 0) {
            const target = args[0];
            console.log(`\n🔍 Deep scan on ${target}...`);
            const result = await this.advancedScanner.performNmapScan(target, 'comprehensive');
            this.displayScanResult(result, target, 'deep');
        } else if (cmd === 'stealth_scan' && args.length > 0) {
            const target = args[0];
            console.log(`\n🕵️ Stealth scan on ${target}...`);
            const result = await this.advancedScanner.stealthScan(target);
            
            if (result.success) {
                console.log(`\n✅ Stealth scan completed in ${result.execution_time.toFixed(2)}s`);
                console.log(result.output.slice(0, 2000));
            } else {
                console.log(`❌ Stealth scan failed: ${result.error}`);
            }
        } else if (cmd === 'vuln_scan' && args.length > 0) {
            const target = args[0];
            console.log(`\n⚠️ Vulnerability scan on ${target}...`);
            const result = await this.advancedScanner.performNmapScan(target, 'vulnerability');
            this.displayScanResult(result, target, 'vulnerability');
        } else if (cmd === 'full_scan' && args.length > 0) {
            const target = args[0];
            console.log(`\n🔍 FULL port scan on ${target}... (This may take a while)`);
            const result = await this.advancedScanner.performNmapScan(target, 'full');
            this.displayScanResult(result, target, 'full');
        } else if (cmd === 'network_discovery' && args.length > 0) {
            const networkRange = args[0];
            console.log(`\n🌐 Discovering hosts on ${networkRange}...`);
            const result = await this.advancedScanner.networkDiscovery(networkRange);
            
            if (result.success) {
                console.log(`\n✅ Discovery completed in ${result.execution_time.toFixed(2)}s`);
                console.log(`Hosts Found: ${result.count}`);
                
                if (result.hosts && result.hosts.length > 0) {
                    console.log("\nDiscovered Hosts:");
                    result.hosts.slice(0, 20).forEach((host, i) => {
                        console.log(`  ${i + 1}. ${host}`);
                    });
                    
                    if (result.hosts.length > 20) {
                        console.log(`  ... and ${result.hosts.length - 20} more`);
                    }
                } else {
                    console.log("No hosts found");
                }
            } else {
                console.log(`❌ Discovery failed: ${result.error}`);
            }
        } else if (cmd === 'analyze' && args.length > 0) {
            const ip = args[0];
            console.log(`\n🔍 Analyzing ${ip}...`);
            
            console.log(`\n🏓 Pinging ${ip}...`);
            const pingResult = await this.scanner.pingIp(ip, 2);
            if (pingResult.includes('successful')) {
                console.log("✅ Reachable");
            } else {
                console.log("❌ Unreachable");
            }
            
            console.log(`\n📍 Getting location...`);
            const location = await this.scanner.getIpLocation(ip);
            try {
                const locData = JSON.parse(location);
                console.log(`  Country: ${locData.country || 'N/A'}`);
                console.log(`  Region: ${locData.region || 'N/A'}`);
                console.log(`  City: ${locData.city || 'N/A'}`);
                console.log(`  ISP: ${locData.isp || locData.org || 'N/A'}`);
            } catch (error) {
                console.log(location);
            }
        } else if (cmd === 'whois' && args.length > 0) {
            const domain = args[0];
            console.log(`\n🔍 WHOIS lookup for ${domain}...`);
            const result = await this.scanner.whoisLookup(domain);
            console.log(result.slice(0, 2000));
        } else if (cmd === 'dns' && args.length > 0) {
            const domain = args[0];
            console.log(`\n🌐 DNS lookup for ${domain}...`);
            const result = await this.scanner.dnsLookup(domain);
            console.log(result);
        } else if (cmd === 'location' && args.length > 0) {
            const ip = args[0];
            console.log(`\n📍 Getting location for ${ip}...`);
            const result = await this.scanner.getIpLocation(ip);
            console.log(result);
        } else if (cmd === 'network_info') {
            console.log("\n🌐 Network Information:");
            const result = this.scanner.getNetworkInfo();
            console.log(result);
        } else if (cmd === 'system_info') {
            console.log("\n💻 System Information:");
            const osUtils = require('os-utils');
            const cpuPercent = await new Promise(resolve => {
                osUtils.cpuUsage(resolve);
            });
            
            console.log(`CPU Usage: ${(cpuPercent * 100).toFixed(1)}%`);
            console.log(`Memory: ${(100 - (osUtils.freememPercentage() * 100)).toFixed(1)}%`);
            console.log(`Hostname: ${os.hostname()}`);
            console.log(`OS: ${os.type()} ${os.release()}`);
            console.log(`Platform: ${os.platform()} ${os.arch()}`);
        } else if (cmd === 'status') {
            console.log("\n📊 System Status:");
            console.log(`  Nmap: ${this.advancedScanner.nmapAvailable ? '✅ Available' : '❌ Not available'}`);
            console.log(`  Telegram: ${this.telegramConfig.enabled ? '✅ Connected' : '❌ Not configured'}`);
            console.log(`  Database: ✅ Ready`);
            
            const osUtils = require('os-utils');
            const cpuPercent = await new Promise(resolve => {
                osUtils.cpuUsage(resolve);
            });
            
            console.log(`  CPU: ${(cpuPercent * 100).toFixed(1)}%`);
            console.log(`  Memory: ${(100 - (osUtils.freememPercentage() * 100)).toFixed(1)}%`);
        } else if (cmd === 'metrics') {
            console.log("\n📈 System Metrics:");
            const osUtils = require('os-utils');
            const diskusage = require('diskusage');
            
            const cpuPercent = await new Promise(resolve => {
                osUtils.cpuUsage(resolve);
            });
            
            const memPercent = (1 - osUtils.freememPercentage()) * 100;
            
            let diskPercent = 0;
            try {
                const info = diskusage.checkSync('/');
                diskPercent = (1 - (info.free / info.total)) * 100;
            } catch (error) {
                diskPercent = 0;
            }
            
            console.log(`💻 CPU Usage: ${(cpuPercent * 100).toFixed(1)}%`);
            console.log(`\n🧠 Memory:`);
            console.log(`  Total: ${(os.totalmem() / (1024 ** 3)).toFixed(2)} GB`);
            console.log(`  Used: ${((os.totalmem() - os.freemem()) / (1024 ** 3)).toFixed(2)} GB (${memPercent.toFixed(1)}%)`);
            console.log(`  Available: ${(os.freemem() / (1024 ** 3)).toFixed(2)} GB`);
            
            console.log(`\n💾 Disk:`);
            console.log(`  Used: ${diskPercent.toFixed(1)}%`);
        } else if (cmd === 'history') {
            console.log("\n📜 Command History:");
            this.db.getCommandHistory(15, (err, history) => {
                if (err || !history || history.length === 0) {
                    console.log("No commands recorded");
                } else {
                    history.slice(0, 15).forEach((row, i) => {
                        const status = row.success ? "✅" : "❌";
                        const timestamp = row.timestamp.split('.')[0];
                        console.log(`${i + 1}. ${status} [${row.source}] ${row.command.slice(0, 50)} | ${timestamp}`);
                    });
                }
            });
        } else if (cmd === 'scan_history') {
            console.log("\n📄 Scan History:");
            this.db.getScanResults(10, (err, scans) => {
                if (err || !scans || scans.length === 0) {
                    console.log("No scan results found");
                } else {
                    scans.forEach((scan, i) => {
                        console.log(`${i + 1}. ${scan.target}`);
                        console.log(`   Type: ${scan.scan_type}`);
                        console.log(`   Time: ${scan.timestamp}`);
                        console.log(`   ID: ${scan.scan_id}\n`);
                    });
                }
            });
        } else if (cmd === 'threats') {
            console.log("\n⚠️ Recent Threats:");
            this.db.getRecentThreats(10, (err, threats) => {
                if (err || !threats || threats.length === 0) {
                    console.log("No recent threats detected");
                } else {
                    threats.forEach(threat => {
                        console.log(`• ${threat.ip_address}`);
                        console.log(`  Type: ${threat.threat_type} | Severity: ${threat.severity}`);
                        console.log(`  Time: ${threat.timestamp}\n`);
                    });
                }
            });
        } else if (cmd === 'generate_report') {
            console.log("\n📊 Generating security report...");
            
            this.db.getRecentThreats(50, (err, threats) => {
                this.db.getScanResults(50, (err2, scanResults) => {
                    this.db.getCommandHistory(100, (err3, history) => {
                        const report = {
                            generated_at: new Date().toISOString(),
                            statistics: {
                                total_threats: threats ? threats.length : 0,
                                total_scans: scanResults ? scanResults.length : 0,
                                high_severity: threats ? threats.filter(t => t.severity === 'high').length : 0,
                                medium_severity: threats ? threats.filter(t => t.severity === 'medium').length : 0,
                                low_severity: threats ? threats.filter(t => t.severity === 'low').length : 0,
                                commands_executed: history ? history.length : 0
                            }
                        };
                        
                        const filename = `security_report_${Date.now()}.json`;
                        const filepath = path.join(REPORT_DIR, filename);
                        
                        fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
                        
                        console.log("\n✅ Security Report Generated");
                        console.log(`Total Threats: ${report.statistics.total_threats}`);
                        console.log(`Total Scans: ${report.statistics.total_scans}`);
                        console.log(`High Severity: ${report.statistics.high_severity}`);
                        console.log(`Medium Severity: ${report.statistics.medium_severity}`);
                        console.log(`Low Severity: ${report.statistics.low_severity}`);
                        console.log(`Commands Executed: ${report.statistics.commands_executed}`);
                        console.log(`\n📄 Report saved: ${filename}`);
                    });
                });
            });
        } else if (cmd === 'config') {
            console.log("\n⚙️ Configuration:");
            console.log(`  Telegram: ${this.telegramConfig.enabled ? 'Enabled' : 'Disabled'}`);
            if (this.telegramConfig.enabled) {
                console.log(`  Bot: @${this.telegramConfig.bot_username}`);
                console.log(`  Chat ID: ${this.telegramConfig.chat_id}`);
            }
            console.log(`  Database: ${DATABASE_FILE}`);
            console.log(`  Logs: ${LOG_FILE}`);
            console.log(`  Reports: ${REPORT_DIR}`);
            console.log(`  Scans: ${SCAN_RESULTS_DIR}`);
        } else if (cmd === 'monitored_ips') {
            this.db.getMonitoredIps((err, ips) => {
                console.log(`\n📋 Monitored IPs: ${ips ? ips.length : 0}`);
                if (ips && ips.length > 0) {
                    ips.forEach(ip => {
                        console.log(`  • ${ip}`);
                    });
                }
            });
        } else if (cmd === 'add_ip' && args.length > 0) {
            const ip = args[0];
            if (this.scanner.isIPv4(ip) || this.scanner.isIPv6(ip)) {
                this.db.addMonitoredIp(ip);
                console.log(`✅ Added ${ip} to monitoring`);
            } else {
                console.log(`❌ Invalid IP: ${ip}`);
            }
        } else if (cmd === 'remove_ip' && args.length > 0) {
            const ip = args[0];
            this.db.removeMonitoredIp(ip);
            console.log(`✅ Removed ${ip} from monitoring`);
        } else {
            console.log("❌ Unknown command. Type 'help' for available commands.");
        }
    }

    displayScanResult(result, target, scanType) {
        if (result.success) {
            console.log(`\n✅ ${scanType.charAt(0).toUpperCase() + scanType.slice(1)} scan completed in ${result.execution_time.toFixed(2)}s`);
            console.log(`Target: ${target}`);
            console.log(`Status: ${result.result.status || 'unknown'}`);
            
            const openPorts = result.result.ports ? result.result.ports.filter(p => p.state === 'open') : [];
            console.log(`🔓 Open Ports: ${openPorts.length}`);
            
            openPorts.slice(0, 15).forEach(port => {
                let portStr = `  Port ${port.port}/${port.protocol}: ${port.service}`;
                if (port.version) {
                    portStr += ` (${port.version})`;
                }
                console.log(portStr);
            });
            
            if (openPorts.length > 15) {
                console.log(`  ... and ${openPorts.length - 15} more`);
            }
            
            if (result.vulnerabilities && result.vulnerabilities.length > 0) {
                console.log(`\n⚠️ Vulnerabilities: ${result.vulnerabilities.length}`);
                result.vulnerabilities.slice(0, 5).forEach(vuln => {
                    console.log(`  Port ${vuln.port}: ${vuln.issues[0]}`);
                });
            }
            
            this.db.saveScanResult(
                result.scan_id,
                target,
                scanType,
                result.result.ports || [],
                result.result.services || [],
                result.result.os || '',
                result.vulnerabilities,
                result.raw_output,
                result.execution_time
            );
            
            const savePath = this.advancedScanner.saveScanToFile(result);
            console.log(`\n💾 Scan saved to: ${savePath}`);
            console.log(`📄 Scan ID: ${result.scan_id}`);
        } else {
            console.log(`❌ Scan failed: ${result.raw_output}`);
        }
    }

    async run() {
        try {
            this.printBanner();
            
            if (this.telegramConfig.enabled) {
                this.startTelegramBot();
                console.log("✅ Telegram bot is active! Send /start to your bot for commands");
            } else {
                console.log("⚠️ Telegram not configured. Type 'setup_telegram' to enable remote commands");
            }
            
            console.log("\nType 'help' for available commands");
            console.log("=".repeat(80) + "\n");
            
            await this.handleLocalCommands();
            
        } catch (error) {
            if (error.message.includes('SIGINT')) {
                console.log("\n👋 Thank you for using Spider Bot!");
            } else {
                console.error(`❌ Application error: ${error.message}`);
            }
        } finally {
            console.log("\n✅ Tool shutdown complete");
            process.exit(0);
        }
    }
}

// =====================
// CREATE DIRECTORIES
// =====================
function createDirectories() {
    const directories = [
        CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, ALERTS_DIR, TEMPLATES_DIR,
        CRYPTO_DIR, STEGANO_DIR, EXPLOITS_DIR, PAYLOADS_DIR, WORDLISTS_DIR,
        CAPTURES_DIR, BACKUPS_DIR, IOT_SCANS_DIR, SOCIAL_ENG_DIR
    ];
    
    directories.forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    });
}

// =====================
// CHECK DEPENDENCIES
// =====================
async function checkDependencies() {
    const requiredPackages = ['axios', 'os-utils', 'diskusage', 'whois-json', 'sqlite3'];
    const missingPackages = [];
    
    for (const pkg of requiredPackages) {
        try {
            require(pkg);
        } catch (error) {
            missingPackages.push(pkg);
        }
    }
    
    if (missingPackages.length > 0) {
        console.log(`⚠️ Missing packages: ${missingPackages.join(', ')}`);
        
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        const answer = await new Promise(resolve => {
            rl.question('Install missing packages? (y/n): ', resolve);
        });
        
        rl.close();
        
        if (answer.toLowerCase() === 'y') {
            for (const pkg of missingPackages) {
                try {
                    const { execSync } = require('child_process');
                    execSync(`npm install ${pkg}`, { stdio: 'inherit' });
                    console.log(`✅ ${pkg} installed`);
                } catch (error) {
                    console.error(`❌ Failed to install ${pkg}: ${error.message}`);
                }
            }
        }
    }
}

// =====================
// CHECK NMAP
// =====================
function checkNmap() {
    try {
        const { execSync } = require('child_process');
        execSync('nmap --version', { stdio: 'pipe' });
        return true;
    } catch (error) {
        console.log("\n🔍 NMAP NOT INSTALLED");
        console.log("=".repeat(50));
        console.log("To use advanced scanning features, install Nmap:");
        console.log("\n📦 Windows:");
        console.log("   1. Download from: https://nmap.org/download.html");
        console.log("   2. Run installer");
        console.log("   3. Add Nmap to PATH during installation");
        console.log("\n🍎 macOS:");
        console.log("   brew install nmap");
        console.log("\n🐧 Linux:");
        console.log("   sudo apt-get install nmap  # Ubuntu/Debian");
        console.log("   sudo yum install nmap      # CentOS/RHEL");
        console.log("\n⚠️ Basic commands will work, but scanning features require Nmap");
        console.log("=".repeat(50));
        return false;
    }
}

// =====================
// MAIN ENTRY POINT
// =====================
async function main() {
    console.log("🕸️ Spider Bot - JavaScript/Node.js Version");
    console.log("=".repeat(50));
    
    // Check Node.js version
    const nodeVersion = process.versions.node;
    const majorVersion = parseInt(nodeVersion.split('.')[0]);
    
    if (majorVersion < 12) {
        console.log("❌ Node.js 12 or higher required");
        process.exit(1);
    }
    
    // Create directories
    createDirectories();
    
    // Check dependencies
    await checkDependencies();
    
    // Check Nmap
    const nmapInstalled = checkNmap();
    if (!nmapInstalled) {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        await new Promise(resolve => {
            rl.question('\nPress Enter to continue...', resolve);
        });
        
        rl.close();
    }
    
    // Create and run application
    const app = new AccurateOnlineOS();
    
    try {
        await app.run();
    } catch (error) {
        if (error.message.includes('SIGINT')) {
            console.log("\n👋 Exiting...");
        } else {
            console.error(`❌ Fatal error: ${error.message}`);
        }
        process.exit(1);
    }
}

// Run the application
if (require.main === module) {
    main().catch(error => {
        console.error(`❌ Unhandled error: ${error.message}`);
        process.exit(1);
    });
}

module.exports = {
    NetworkScanner,
    AdvancedNetworkScanner,
    TelegramConfig,
    DatabaseManager,
    AccurateOnlineOS
};