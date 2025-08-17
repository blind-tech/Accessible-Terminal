
import wx
import wx.html2 as webview
import subprocess
import os
import threading
import uuid
import shlex
import json
import time
from pathlib import Path
from datetime import datetime
import getpass
from cryptography.fernet import Fernet
import base64
import queue
import ftplib
import tempfile
import webbrowser
import platform
import shutil
import zipfile
import tarfile

try:
    import paramiko
except ImportError:
    paramiko = None

# Constants
APP_NAME = "Accessible Terminal"
APP_VERSION = "2.1"
APP_CONFIG_DIR = Path(os.path.expanduser("~")) / ".accessible_terminal"
APP_CONFIG_DIR.mkdir(exist_ok=True)
CONFIG_FILE = APP_CONFIG_DIR / "config.json"
KEY_FILE = APP_CONFIG_DIR / ".key"
HISTORY_FILE = APP_CONFIG_DIR / "history.json"
LOG_FILE = APP_CONFIG_DIR / "activity.log"
SCRIPTS_DIR = APP_CONFIG_DIR / "scripts"
SCRIPTS_DIR.mkdir(exist_ok=True)

# Encryption setup
def get_encryption_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    else:
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        KEY_FILE.chmod(0o600)
        return key

CRYPTO = Fernet(get_encryption_key())

def encrypt_data(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return CRYPTO.encrypt(data).decode('utf-8')

def decrypt_data(encrypted_data):
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    return CRYPTO.decrypt(encrypted_data).decode('utf-8')

# Configuration management
def load_config():
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            # Decrypt sensitive data
            if 'private_keys' in config:
                config['private_keys'] = [decrypt_data(k) for k in config['private_keys']]
            if 'ftp_credentials' in config:
                config['ftp_credentials'] = {k: decrypt_data(v) for k, v in config['ftp_credentials'].items()}
            return config
        except Exception as e:
            log_error(f"Failed to load config: {str(e)}")
            return {}
    return {}

def save_config(cfg):
    config = cfg.copy()
    # Encrypt sensitive data before saving
    if 'private_keys' in config:
        config['private_keys'] = [encrypt_data(k) for k in config['private_keys']]
    if 'ftp_credentials' in config:
        config['ftp_credentials'] = {k: encrypt_data(v) for k, v in config['ftp_credentials'].items()}
    
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    try:
        CONFIG_FILE.chmod(0o600)
    except Exception:
        pass

def log_activity(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {message}\n")

def log_error(message):
    log_activity(f"ERROR: {message}")

# Load initial config
CONFIG = load_config()

class FTPSession:
    def __init__(self):
        self.ftp = None
        self.connected = False
        self.last_activity = time.time()

    def connect(self, host, username, password, port=21):
        try:
            self.ftp = ftplib.FTP()
            self.ftp.connect(host, port)
            self.ftp.login(username, password)
            self.connected = True
            self.last_activity = time.time()
            log_activity(f"FTP connected to {username}@{host}:{port}")
            return True, f"Connected to {username}@{host}"
        except Exception as e:
            log_error(f"FTP connection failed: {str(e)}")
            return False, f"FTP connection failed: {e}"

    def list_files(self, path="."):
        try:
            self.last_activity = time.time()
            files = []
            self.ftp.dir(path, files.append)
            return True, "\n".join(files)
        except Exception as e:
            log_error(f"FTP list failed: {str(e)}")
            return False, str(e)

    def download_file(self, remote_path, local_path):
        try:
            self.last_activity = time.time()
            with open(local_path, 'wb') as f:
                self.ftp.retrbinary(f"RETR {remote_path}", f.write)
            return True, f"Downloaded {remote_path} to {local_path}"
        except Exception as e:
            log_error(f"FTP download failed: {str(e)}")
            return False, str(e)

    def upload_file(self, local_path, remote_path):
        try:
            self.last_activity = time.time()
            with open(local_path, 'rb') as f:
                self.ftp.storbinary(f"STOR {remote_path}", f)
            return True, f"Uploaded {local_path} to {remote_path}"
        except Exception as e:
            log_error(f"FTP upload failed: {str(e)}")
            return False, str(e)

    def disconnect(self):
        try:
            if self.ftp:
                self.ftp.quit()
            log_activity("FTP disconnected")
            return True, "FTP disconnected."
        except Exception as e:
            log_error(f"FTP disconnect failed: {str(e)}")
            return False, str(e)
        finally:
            self.connected = False

class SSHSession:
    def __init__(self):
        self.client = None
        self.transport = None
        self.sftp = None
        self.connected = False
        self.last_activity = time.time()

    def connect(self, hostname, username, password=None, port=22, key_filename=None, passphrase=None):
        if paramiko is None:
            return False, "paramiko not installed."
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if key_filename:
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    key_filename=key_filename,
                    passphrase=passphrase,
                    timeout=10
                )
            else:
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=password,
                    timeout=10
                )
            
            self.client = client
            self.transport = client.get_transport()
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            self.connected = True
            self.last_activity = time.time()
            
            log_activity(f"SSH connected to {username}@{hostname}:{port}")
            return True, f"Connected to {username}@{hostname}"
            
        except Exception as e:
            log_error(f"SSH connection failed: {str(e)}")
            return False, f"SSH connection failed: {e}"

    def run_command(self, command, timeout=60):
        if not self.connected or not self.client:
            return False, "No active SSH connection."
            
        try:
            self.last_activity = time.time()
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            out = stdout.read().decode(errors='ignore')
            err = stderr.read().decode(errors='ignore')
            
            if err.strip():
                return False, err
            return True, out
        except Exception as e:
            log_error(f"SSH command failed: {str(e)}")
            return False, str(e)

    def disconnect(self):
        try:
            if self.sftp:
                self.sftp.close()
            if self.client:
                self.client.close()
            log_activity("SSH disconnected")
            return True, "SSH disconnected."
        except Exception as e:
            log_error(f"SSH disconnect failed: {str(e)}")
            return False, str(e)
        finally:
            self.connected = False

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.history = self.load_history()
        self.thread_pool = ThreadPool(5)  # 5 worker threads
        self.cleanup_thread = threading.Thread(target=self._cleanup_sessions, daemon=True)
        self.cleanup_thread.start()

    def _cleanup_sessions(self):
        while True:
            time.sleep(60)  # Check every minute
            now = time.time()
            timeout = CONFIG.get('session_timeout', 3600)  # Default 1 hour
            
            to_delete = []
            for sid, session in self.sessions.items():
                if now - session['last_activity'] > timeout:
                    ssh = session.get('ssh')
                    if ssh and ssh.connected:
                        ssh.disconnect()
                    ftp = session.get('ftp')
                    if ftp and ftp.connected:
                        ftp.disconnect()
                    to_delete.append(sid)
            
            for sid in to_delete:
                del self.sessions[sid]
                log_activity(f"Cleaned up inactive session: {sid}")

    def load_history(self):
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_history(self):
        try:
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            log_error(f"Failed to save history: {str(e)}")

    def new_session(self):
        sid = str(uuid.uuid4())
        self.sessions[sid] = {
            'cwd': os.path.expanduser('~'),
            'history': [],
            'history_pos': None,
            'ssh': None,
            'ftp': None,
            'created': time.time(),
            'last_activity': time.time(),
            'env': os.environ.copy()
        }
        log_activity(f"New session created: {sid}")
        return sid

    def set_cwd(self, sid, cwd):
        if sid in self.sessions:
            self.sessions[sid]['cwd'] = cwd
            self.sessions[sid]['last_activity'] = time.time()

    def get_cwd(self, sid):
        return self.sessions.get(sid, {}).get('cwd', os.path.expanduser('~'))

    def add_history(self, sid, cmd):
        if sid in self.sessions:
            # Add to session history
            self.sessions[sid]['history'].append(cmd)
            self.sessions[sid]['history_pos'] = None
            self.sessions[sid]['last_activity'] = time.time()
            
            # Add to global history
            user = getpass.getuser()
            if user not in self.history:
                self.history[user] = []
            self.history[user].append({
                'command': cmd,
                'timestamp': time.time(),
                'session': sid
            })
            self.save_history()

    def get_history(self, sid, count=10):
        if sid in self.sessions:
            return self.sessions[sid]['history'][-count:]
        return []

    def set_ssh(self, sid, ssh_session):
        if sid in self.sessions:
            self.sessions[sid]['ssh'] = ssh_session
            self.sessions[sid]['last_activity'] = time.time()

    def get_ssh(self, sid):
        return self.sessions.get(sid, {}).get('ssh', None)

    def set_ftp(self, sid, ftp_session):
        if sid in self.sessions:
            self.sessions[sid]['ftp'] = ftp_session
            self.sessions[sid]['last_activity'] = time.time()

    def get_ftp(self, sid):
        return self.sessions.get(sid, {}).get('ftp', None)

    def get_session_info(self, sid):
        return self.sessions.get(sid, None)

    def run_in_thread(self, func, *args, **kwargs):
        self.thread_pool.add_task(func, *args, **kwargs)

class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = queue.Queue()
        self.workers = []
        for _ in range(num_threads):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            self.workers.append(worker)

    def _worker(self):
        while True:
            func, args, kwargs = self.tasks.get()
            try:
                func(*args, **kwargs)
            except Exception as e:
                log_error(f"Thread pool error: {str(e)}")
            finally:
                self.tasks.task_done()

    def add_task(self, func, *args, **kwargs):
        self.tasks.put((func, args, kwargs))

SM = SessionManager()

class MainFrame(wx.Frame):
    def __init__(self):
        super().__init__(None, title=f"{APP_NAME} v{APP_VERSION}", size=(1000, 800))
        
        icon_path = Path(__file__).with_name("AccessibleIcon.png")
        if icon_path.exists():
            self.SetIcon(wx.Icon(str(icon_path)))

        # Initialize UI
        self.init_ui()
        
        # Load settings
        self.load_settings()
        
        # Bind events
        self.Bind(wx.EVT_CLOSE, self.on_close)
        
        # Start session cleanup timer
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.on_timer, self.timer)
        self.timer.Start(60000)  # 1 minute

    def init_ui(self):
        # Create main panel
        self.panel = wx.Panel(self)
        
        # Create menu bar with accessibility improvements
        self.create_menu()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create notebook for tabs
        self.notebook = wx.Notebook(self.panel)
        
        # Create initial tab
        self.add_tab()
        
        # Layout
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.notebook, 1, wx.EXPAND|wx.ALL, 5)
        self.panel.SetSizer(sizer)
        
        # Status bar
        self.statusbar = self.CreateStatusBar(2)
        self.statusbar.SetStatusWidths([-2, -1])
        self.update_statusbar()

    def create_menu(self):
        menubar = wx.MenuBar()
        
        # File menu
        file_menu = wx.Menu()
        mi_new = file_menu.Append(wx.ID_NEW, "New Tab\tCtrl+T", "Create a new terminal tab")
        mi_addkey = file_menu.Append(-1, "Add SSH Key...\tCtrl+K", "Add an SSH private key to the configuration")
        mi_ftp = file_menu.Append(-1, "FTP Connection...", "Connect to an FTP server")
        mi_script = file_menu.Append(-1, "Run Script...", "Run a script file")
        mi_export = file_menu.Append(-1, "Export Session...", "Export terminal session to file")
        mi_settings = file_menu.Append(-1, "Settings...\tCtrl+,", "Configure application settings")
        file_menu.AppendSeparator()
        mi_exit = file_menu.Append(wx.ID_EXIT, "Exit\tCtrl+Q", "Exit the application")
        
        # Edit menu
        edit_menu = wx.Menu()
        mi_copy = edit_menu.Append(wx.ID_COPY, "Copy\tCtrl+C", "Copy selected text to clipboard")
        mi_paste = edit_menu.Append(wx.ID_PASTE, "Paste\tCtrl+V", "Paste from clipboard")
        mi_clear = edit_menu.Append(-1, "Clear\tCtrl+L", "Clear terminal output")
        
        # View menu
        view_menu = wx.Menu()
        self.mi_fullscreen = view_menu.Append(-1, "Full Screen\tF11", "Toggle full screen mode", kind=wx.ITEM_CHECK)
        mi_zoom_in = view_menu.Append(-1, "Zoom In\tCtrl++", "Increase font size")
        mi_zoom_out = view_menu.Append(-1, "Zoom Out\tCtrl+-", "Decrease font size")
        mi_reset_zoom = view_menu.Append(-1, "Reset Zoom\tCtrl+0", "Reset font size to default")
        
        # Help menu with improved accessibility
        help_menu = wx.Menu()
        mi_help = help_menu.Append(wx.ID_HELP, "Help\tF1", "Show help documentation")
        help_menu.AppendSeparator()
        mi_about = help_menu.Append(wx.ID_ABOUT, "About...", "About this application")
        mi_dev_info = help_menu.Append(-1, "Developer Info", "Contact the developer")
        
        # Add menus to menubar
        menubar.Append(file_menu, "&File")
        menubar.Append(edit_menu, "&Edit")
        menubar.Append(view_menu, "&View")
        menubar.Append(help_menu, "&Help")
        
        self.SetMenuBar(menubar)
        
        # Bind menu events
        self.Bind(wx.EVT_MENU, self.on_new_tab, mi_new)
        self.Bind(wx.EVT_MENU, self.on_add_key, mi_addkey)
        self.Bind(wx.EVT_MENU, self.on_ftp_connect, mi_ftp)
        self.Bind(wx.EVT_MENU, self.on_run_script, mi_script)
        self.Bind(wx.EVT_MENU, self.on_export_session, mi_export)
        self.Bind(wx.EVT_MENU, self.on_settings, mi_settings)
        self.Bind(wx.EVT_MENU, self.on_exit, mi_exit)
        self.Bind(wx.EVT_MENU, self.on_copy, mi_copy)
        self.Bind(wx.EVT_MENU, self.on_paste, mi_paste)
        self.Bind(wx.EVT_MENU, self.on_clear, mi_clear)
        self.Bind(wx.EVT_MENU, self.on_fullscreen, self.mi_fullscreen)
        self.Bind(wx.EVT_MENU, self.on_zoom_in, mi_zoom_in)
        self.Bind(wx.EVT_MENU, self.on_zoom_out, mi_zoom_out)
        self.Bind(wx.EVT_MENU, self.on_reset_zoom, mi_reset_zoom)
        self.Bind(wx.EVT_MENU, self.on_help, mi_help)
        self.Bind(wx.EVT_MENU, self.on_about, mi_about)
        self.Bind(wx.EVT_MENU, self.on_dev_info, mi_dev_info)

    def create_toolbar(self):
        toolbar = self.CreateToolBar()
        
        bmp_size = (16, 16)
        new_bmp = wx.ArtProvider.GetBitmap(wx.ART_NEW, wx.ART_TOOLBAR, bmp_size)
        addkey_bmp = wx.ArtProvider.GetBitmap(wx.ART_PLUS, wx.ART_TOOLBAR, bmp_size)
        ftp_bmp = wx.ArtProvider.GetBitmap(wx.ART_GO_DIR_UP, wx.ART_TOOLBAR, bmp_size)
        script_bmp = wx.ArtProvider.GetBitmap(wx.ART_NORMAL_FILE, wx.ART_TOOLBAR, bmp_size)
        export_bmp = wx.ArtProvider.GetBitmap(wx.ART_FILE_SAVE_AS, wx.ART_TOOLBAR, bmp_size)
        settings_bmp = wx.ArtProvider.GetBitmap(wx.ART_EXECUTABLE_FILE, wx.ART_TOOLBAR, bmp_size)
        copy_bmp = wx.ArtProvider.GetBitmap(wx.ART_COPY, wx.ART_TOOLBAR, bmp_size)
        paste_bmp = wx.ArtProvider.GetBitmap(wx.ART_PASTE, wx.ART_TOOLBAR, bmp_size)
        clear_bmp = wx.ArtProvider.GetBitmap(wx.ART_DELETE, wx.ART_TOOLBAR, bmp_size)
        
        toolbar.AddTool(wx.ID_NEW, "New Tab", new_bmp, "Open a new tab")
        toolbar.AddTool(-1, "Add SSH Key", addkey_bmp, "Add an SSH key")
        toolbar.AddTool(-1, "FTP Connect", ftp_bmp, "Connect to FTP server")
        toolbar.AddTool(-1, "Run Script", script_bmp, "Run a script file")
        toolbar.AddTool(-1, "Export Session", export_bmp, "Export terminal session")
        toolbar.AddSeparator()
        toolbar.AddTool(-1, "Settings", settings_bmp, "Open settings")
        toolbar.AddSeparator()
        toolbar.AddTool(wx.ID_COPY, "Copy", copy_bmp, "Copy selected text")
        toolbar.AddTool(wx.ID_PASTE, "Paste", paste_bmp, "Paste from clipboard")
        toolbar.AddTool(-1, "Clear", clear_bmp, "Clear terminal")
        
        toolbar.Realize()
        
        # Bind toolbar events
        self.Bind(wx.EVT_TOOL, self.on_new_tab, id=wx.ID_NEW)
        self.Bind(wx.EVT_TOOL, self.on_add_key, id=-1)
        self.Bind(wx.EVT_TOOL, self.on_ftp_connect, id=-1)
        self.Bind(wx.EVT_TOOL, self.on_run_script, id=-1)
        self.Bind(wx.EVT_TOOL, self.on_export_session, id=-1)
        self.Bind(wx.EVT_TOOL, self.on_copy, id=wx.ID_COPY)
        self.Bind(wx.EVT_TOOL, self.on_paste, id=wx.ID_PASTE)
        self.Bind(wx.EVT_TOOL, self.on_clear, id=-1)

    def add_tab(self, title="Terminal"):
        panel = wx.Panel(self.notebook)
        web = webview.WebView.New(panel)
        
        # Load HTML from file next to script
        html_path = Path(__file__).with_name("ui.html")
        try:
            html_text = html_path.read_text(encoding="utf-8")
        except Exception:
            html_text = """
            <html>
            <head>
                <style>
                    body { font-family: Consolas, monospace; background: #1e1e1e; color: #f0f0f0; }
                    .output { white-space: pre-wrap; margin: 10px; }
                    .prompt { color: #4CAF50; }
                    .error { color: #F44336; }
                    .warning { color: #FFC107; }
                    .info { color: #2196F3; }
                    #input { 
                        width: 80%; 
                        background: #2d2d2d; 
                        color: #f0f0f0; 
                        border: 1px solid #444; 
                        padding: 5px;
                        font-family: Consolas, monospace;
                    }
                </style>
            </head>
            <body>
                <div id="terminal"></div>
                <div id="input-area">
                    <span class="prompt">$ </span>
                    <input type="text" id="input" autofocus aria-label="Command input" />
                </div>
                <script>
                    // JavaScript for terminal functionality
                </script>
            </body>
            </html>
            """
        
        web.SetPage(html_text, "")
        web.Bind(webview.EVT_WEBVIEW_NAVIGATING, self.on_navigate)
        web.Bind(webview.EVT_WEBVIEW_LOADED, self.on_loaded)
        
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(web, 1, wx.EXPAND)
        panel.SetSizer(sizer)
        
        self.notebook.AddPage(panel, title)
        self.notebook.SetSelection(self.notebook.GetPageCount() - 1)
        
        return web

    def get_current_webview(self):
        current_page = self.notebook.GetCurrentPage()
        if current_page:
            for child in current_page.GetChildren():
                if isinstance(child, webview.WebView):
                    return child
        return None

    def run_js_in_current_tab(self, script):
        web = self.get_current_webview()
        if web:
            wx.CallAfter(lambda: web.RunScript(script))

    def load_settings(self):
        # Load theme
        theme = CONFIG.get('theme', 'dark')
        self.apply_theme(theme)
        
        # Load font settings
        font_size = CONFIG.get('font_size', 12)
        font_family = CONFIG.get('font_family', 'Consolas, monospace')
        
        # Update status bar
        self.update_statusbar()

    def apply_theme(self, theme):
        # This would update all tabs with the new theme
        pass

    def update_statusbar(self):
        current_time = time.strftime("%H:%M:%S")
        self.statusbar.SetStatusText(current_time, 1)
        
        # Update connection status
        web = self.get_current_webview()
        if web:
            # This would need to track the current session
            self.statusbar.SetStatusText("Ready", 0)

    # Event handlers
    def on_close(self, event):
        # Clean up all sessions
        for sid in list(SM.sessions.keys()):
            ssh = SM.get_ssh(sid)
            if ssh and ssh.connected:
                ssh.disconnect()
            ftp = SM.get_ftp(sid)
            if ftp and ftp.connected:
                ftp.disconnect()
        
        # Save settings
        self.save_settings()
        
        event.Skip()

    def save_settings(self):
        # Save current configuration
        save_config(CONFIG)

    def on_timer(self, event):
        # Update status bar
        self.update_statusbar()

    def on_new_tab(self, event):
        web = self.add_tab()
        sid = SM.new_session()
        cwd = SM.get_cwd(sid)
        web.RunScript(f'py_createSession("{sid}", "{cwd}")')

    def on_add_key(self, event):
        with wx.FileDialog(
            self, 
            "Select private key file", 
            style=wx.FD_OPEN|wx.FD_FILE_MUST_EXIST
        ) as dlg:
            if dlg.ShowModal() == wx.ID_CANCEL:
                return
            
            path = dlg.GetPath()
            cfg = load_config() or {}
            keys = cfg.get("private_keys", [])
            
            if path not in keys:
                keys.append(path)
                cfg["private_keys"] = keys
                save_config(cfg)
                
                wx.MessageBox(
                    "Private key saved to config.", 
                    "Success", 
                    wx.OK|wx.ICON_INFORMATION
                )
            else:
                wx.MessageBox(
                    "Key already present.", 
                    "Info", 
                    wx.OK|wx.ICON_INFORMATION
                )

    def on_ftp_connect(self, event):
        dlg = wx.Dialog(self, title="FTP Connection", size=(400, 300))
        
        # Create controls
        host_label = wx.StaticText(dlg, label="Host:")
        host_ctrl = wx.TextCtrl(dlg)
        
        port_label = wx.StaticText(dlg, label="Port:")
        port_ctrl = wx.SpinCtrl(dlg, min=1, max=65535, initial=21)
        
        user_label = wx.StaticText(dlg, label="Username:")
        user_ctrl = wx.TextCtrl(dlg)
        
        pass_label = wx.StaticText(dlg, label="Password:")
        pass_ctrl = wx.TextCtrl(dlg, style=wx.TE_PASSWORD)
        
        save_check = wx.CheckBox(dlg, label="Save credentials (encrypted)")
        
        # Layout
        sizer = wx.BoxSizer(wx.VERTICAL)
        grid = wx.FlexGridSizer(cols=2, vgap=5, hgap=5)
        grid.AddMany([
            (host_label), (host_ctrl, 1, wx.EXPAND),
            (port_label), (port_ctrl, 1, wx.EXPAND),
            (user_label), (user_ctrl, 1, wx.EXPAND),
            (pass_label), (pass_ctrl, 1, wx.EXPAND),
            (save_check), (wx.StaticText(dlg, label=""))
        ])
        
        btn_sizer = dlg.CreateButtonSizer(wx.OK|wx.CANCEL)
        sizer.Add(grid, 1, wx.EXPAND|wx.ALL, 10)
        sizer.Add(btn_sizer, 0, wx.EXPAND|wx.ALL, 10)
        dlg.SetSizer(sizer)
        
        if dlg.ShowModal() == wx.ID_OK:
            host = host_ctrl.GetValue()
            port = port_ctrl.GetValue()
            username = user_ctrl.GetValue()
            password = pass_ctrl.GetValue()
            save = save_check.GetValue()
            
            if save:
                cfg = load_config()
                if 'ftp_credentials' not in cfg:
                    cfg['ftp_credentials'] = {}
                cfg['ftp_credentials'][f"{username}@{host}:{port}"] = f"{username}:{password}"
                save_config(cfg)
            
            # Get current session
            web = self.get_current_webview()
            if web:
                sid = None
                for child in web.GetChildren():
                    if hasattr(child, 'GetId'):
                        sid = str(child.GetId())
                        break
                
                if sid:
                    ftp = FTPSession()
                    ok, msg = ftp.connect(host, username, password, port)
                    if ok:
                        SM.set_ftp(sid, ftp)
                        self.send_output_to_js(sid, msg, 'success')
                    else:
                        self.send_output_to_js(sid, msg, 'error')
        
        dlg.Destroy()

    def on_run_script(self, event):
        with wx.FileDialog(
            self, 
            "Select script file", 
            defaultDir=str(SCRIPTS_DIR),
            style=wx.FD_OPEN|wx.FD_FILE_MUST_EXIST
        ) as dlg:
            if dlg.ShowModal() == wx.ID_CANCEL:
                return
            
            path = dlg.GetPath()
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    script = f.read()
                
                # Get current session
                web = self.get_current_webview()
                if web:
                    sid = None
                    for child in web.GetChildren():
                        if hasattr(child, 'GetId'):
                            sid = str(child.GetId())
                            break
                    
                    if sid:
                        # Run each line of the script
                        for line in script.splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                self.send_output_to_js(sid, f"$ {line}", 'info')
                                SM.run_in_thread(self.handle_run, sid, line)
                                time.sleep(0.1)  # Small delay between commands
                
            except Exception as e:
                wx.MessageBox(
                    f"Failed to run script: {str(e)}",
                    "Error",
                    wx.OK|wx.ICON_ERROR
                )

    def on_export_session(self, event):
        web = self.get_current_webview()
        if not web:
            return
            
        # Get current session ID
        sid = None
        for child in web.GetChildren():
            if hasattr(child, 'GetId'):
                sid = str(child.GetId())
                break
        
        if not sid:
            return
        
        # Get the terminal content via JavaScript
        def get_content_callback(content):
            if not content:
                return
                
            with wx.FileDialog(
                self,
                "Export Session As",
                defaultDir=str(APP_CONFIG_DIR),
                wildcard="Text files (*.txt)|*.txt|HTML files (*.html)|*.html|PDF files (*.pdf)|*.pdf",
                style=wx.FD_SAVE|wx.FD_OVERWRITE_PROMPT
            ) as dlg:
                if dlg.ShowModal() == wx.ID_CANCEL:
                    return
                
                path = Path(dlg.GetPath())
                ext = path.suffix.lower()
                
                try:
                    if ext == '.txt':
                        path.write_text(content, encoding='utf-8')
                    elif ext == '.html':
                        html = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Terminal Session Export</title>
                            <style>
                                body {{ font-family: monospace; white-space: pre; }}
                            </style>
                        </head>
                        <body>
                        {content}
                        </body>
                        </html>
                        """
                        path.write_text(html, encoding='utf-8')
                    elif ext == '.pdf':
                        # Requires reportlab or similar PDF library
                        try:
                            from reportlab.lib.pagesizes import letter
                            from reportlab.platypus import SimpleDocTemplate, Paragraph
                            from reportlab.lib.styles import getSampleStyleSheet
                            
                            doc = SimpleDocTemplate(str(path), pagesize=letter)
                            styles = getSampleStyleSheet()
                            story = [Paragraph(content.replace('\n', '<br/>'), styles["Normal"])]
                            doc.build(story)
                        except ImportError:
                            wx.MessageBox(
                                "PDF export requires reportlab package. Install with: pip install reportlab",
                                "Error",
                                wx.OK|wx.ICON_ERROR
                            )
                            return
                    
                    wx.MessageBox(
                        f"Session exported to {path}",
                        "Success",
                        wx.OK|wx.ICON_INFORMATION
                    )
                except Exception as e:
                    wx.MessageBox(
                        f"Failed to export: {str(e)}",
                        "Error",
                        wx.OK|wx.ICON_ERROR
                    )
        
        web.RunScript("document.getElementById('terminal').innerText;", get_content_callback)

    def on_settings(self, event):
        dlg = wx.Dialog(self, title="Settings", size=(400, 300))
        
        # Create settings controls
        theme_label = wx.StaticText(dlg, label="Theme:")
        theme_choice = wx.Choice(dlg, choices=["Dark", "Light", "System"])
        theme_choice.SetSelection(["Dark", "Light", "System"].index(CONFIG.get('theme', 'Dark')))
        
        font_label = wx.StaticText(dlg, label="Font Size:")
        font_spin = wx.SpinCtrl(dlg, min=8, max=24, initial=CONFIG.get('font_size', 12))
        
        timeout_label = wx.StaticText(dlg, label="Session Timeout (minutes):")
        timeout_spin = wx.SpinCtrl(dlg, min=1, max=1440, initial=CONFIG.get('session_timeout', 60)//60)
        
        # Layout
        sizer = wx.BoxSizer(wx.VERTICAL)
        grid = wx.FlexGridSizer(cols=2, vgap=5, hgap=5)
        grid.AddMany([
            (theme_label), (theme_choice, 1, wx.EXPAND),
            (font_label), (font_spin, 1, wx.EXPAND),
            (timeout_label), (timeout_spin, 1, wx.EXPAND)
        ])
        
        btn_sizer = dlg.CreateButtonSizer(wx.OK|wx.CANCEL)
        sizer.Add(grid, 1, wx.EXPAND|wx.ALL, 10)
        sizer.Add(btn_sizer, 0, wx.EXPAND|wx.ALL, 10)
        dlg.SetSizer(sizer)
        
        if dlg.ShowModal() == wx.ID_OK:
            CONFIG['theme'] = theme_choice.GetStringSelection()
            CONFIG['font_size'] = font_spin.GetValue()
            CONFIG['session_timeout'] = timeout_spin.GetValue() * 60
            
            save_config(CONFIG)
            self.load_settings()
            
            # Apply changes to all tabs
            self.apply_theme(CONFIG['theme'])
            
            wx.MessageBox(
                "Settings saved. Some changes may require restart.", 
                "Info", 
                wx.OK|wx.ICON_INFORMATION
            )
        
        dlg.Destroy()

    def on_exit(self, event):
        self.Close()

    def on_copy(self, event):
        web = self.get_current_webview()
        if web:
            web.RunScript("document.execCommand('copy');")

    def on_paste(self, event):
        web = self.get_current_webview()
        if web:
            web.RunScript("document.execCommand('paste');")

    def on_clear(self, event):
        web = self.get_current_webview()
        if web:
            web.RunScript("document.getElementById('terminal').innerHTML = '';")

    def on_fullscreen(self, event):
        self.ShowFullScreen(self.mi_fullscreen.IsChecked())

    def on_zoom_in(self, event):
        web = self.get_current_webview()
        if web:
            web.SetZoom(web.GetZoom() + 0.1)

    def on_zoom_out(self, event):
        web = self.get_current_webview()
        if web:
            web.SetZoom(web.GetZoom() - 0.1)

    def on_reset_zoom(self, event):
        web = self.get_current_webview()
        if web:
            web.SetZoom(1.0)

    def on_help(self, event):
        webbrowser.open("https://github.com/blindtech/accessible-terminal/wiki")

    def on_about(self, event):
        info = wx.adv.AboutDialogInfo()
        info.SetName(APP_NAME)
        info.SetVersion(APP_VERSION)
        info.SetDescription("An accessible terminal emulator with enhanced features")
        info.SetCopyright("(C) 2023")
        info.SetWebSite("https://github.com/blindtech/accessible-terminal")
        
        wx.adv.AboutBox(info)

    def on_dev_info(self, event):
        info = """Developer Information:

Contact the developer:
Facebook: facebook.com/0mohammedbenantar/
Telegram: https://t.me/muhammedantar

GitHub Repository:
github.com/blindtech/accessible-terminal/
"""
        wx.MessageBox(info, "Developer Information", wx.OK|wx.ICON_INFORMATION)

    def on_loaded(self, event):
        web = event.GetEventObject()
        sid = SM.new_session()
        cwd = SM.get_cwd(sid)
        web.RunScript(f'py_createSession("{sid}", "{cwd}")')

    def on_navigate(self, event):
        url = event.GetURL()
        if url.startswith("app://"):
            event.Veto()
            import urllib.parse as up
            parsed = up.urlparse(url)
            action = parsed.netloc or parsed.path.lstrip('/')
            q = up.parse_qs(parsed.query)
            
            if action == 'newsession':
                sid = SM.new_session()
                cwd = SM.get_cwd(sid)
                self.run_js_in_current_tab(f'py_createSession("{sid}", "{cwd}")')
            
            elif action == 'run':
                sid = q.get('sid', [''])[0]
                cmd = q.get('cmd', [''])[0]
                cmd = up.unquote(cmd)
                SM.run_in_thread(self.handle_run, sid, cmd)
            
            elif action == 'connect_ssh':
                sid = q.get('sid', [''])[0]
                target = q.get('target', [''])[0]
                target = up.unquote(target)
                SM.run_in_thread(self.handle_connect_ssh, sid, target)
            
            elif action == 'disconnect_ssh':
                sid = q.get('sid', [''])[0]
                SM.run_in_thread(self.handle_disconnect_ssh, sid)
            
            elif action == 'connect_ftp':
                sid = q.get('sid', [''])[0]
                target = q.get('target', [''])[0]
                target = up.unquote(target)
                SM.run_in_thread(self.handle_connect_ftp, sid, target)
            
            elif action == 'disconnect_ftp':
                sid = q.get('sid', [''])[0]
                SM.run_in_thread(self.handle_disconnect_ftp, sid)
            
            elif action == 'list_ftp':
                sid = q.get('sid', [''])[0]
                path = q.get('path', ['.'])[0]
                path = up.unquote(path)
                SM.run_in_thread(self.handle_list_ftp, sid, path)
            
            elif action == 'download_ftp':
                sid = q.get('sid', [''])[0]
                remote = q.get('remote', [''])[0]
                remote = up.unquote(remote)
                local = q.get('local', [''])[0]
                local = up.unquote(local)
                SM.run_in_thread(self.handle_download_ftp, sid, remote, local)
            
            elif action == 'upload_ftp':
                sid = q.get('sid', [''])[0]
                local = q.get('local', [''])[0]
                local = up.unquote(local)
                remote = q.get('remote', [''])[0]
                remote = up.unquote(remote)
                SM.run_in_thread(self.handle_upload_ftp, sid, local, remote)
            
            elif action == 'get_keys':
                cfg = load_config()
                keys = cfg.get('private_keys', [])
                self.run_js_in_current_tab(f'py_receiveKeys({json.dumps(keys)})')
            
            elif action == 'get_history':
                sid = q.get('sid', [''])[0]
                count = int(q.get('count', ['10'])[0])
                history = SM.get_history(sid, count)
                self.run_js_in_current_tab(f'py_receiveHistory({json.dumps(history)})')
            
            else:
                log_error(f"Unknown action: {action}")

    def send_output_to_js(self, sid, text, out_type='success'):
        esc = json.dumps(text)
        script = f'py_appendOutput("{sid}", {esc}, "{out_type}")'
        self.run_js_in_current_tab(script)

    def handle_run(self, sid, cmd):
        if sid not in SM.sessions:
            self.send_output_to_js(sid, "Invalid session id", 'error')
            return
        
        session = SM.sessions[sid]
        cwd = session['cwd']
        cmd = cmd.strip()
        
        if cmd == '':
            return
        
        # Update last activity
        session['last_activity'] = time.time()
        
        # Handle special commands
        if cmd.startswith('cd '):
            target = cmd[3:].strip()
            target = os.path.expanduser(target)
            
            if not os.path.isabs(target):
                target = os.path.normpath(os.path.join(cwd, target))
            
            if os.path.isdir(target):
                SM.set_cwd(sid, target)
                self.send_output_to_js(sid, f'Changed directory to: {target}', 'success')
            else:
                self.send_output_to_js(sid, f'No such directory: {target}', 'error')
            return
        
        # Handle FTP commands if connected
        ftp_obj = SM.get_ftp(sid)
        if ftp_obj and ftp_obj.connected:
            if cmd.startswith('ftp '):
                ftp_cmd = cmd[4:].strip()
                if ftp_cmd.startswith('ls') or ftp_cmd.startswith('dir'):
                    path = ftp_cmd.split(' ', 1)[1] if ' ' in ftp_cmd else '.'
                    ok, out = ftp_obj.list_files(path)
                    typ = 'success' if ok else 'error'
                    self.send_output_to_js(sid, out if out else '(no output)', typ)
                elif ftp_cmd.startswith('get '):
                    remote = ftp_cmd.split(' ', 1)[1]
                    local = os.path.join(cwd, os.path.basename(remote))
                    ok, out = ftp_obj.download_file(remote, local)
                    typ = 'success' if ok else 'error'
                    self.send_output_to_js(sid, out, typ)
                elif ftp_cmd.startswith('put '):
                    local = ftp_cmd.split(' ', 1)[1]
                    remote = os.path.basename(local)
                    ok, out = ftp_obj.upload_file(local, remote)
                    typ = 'success' if ok else 'error'
                    self.send_output_to_js(sid, out, typ)
                else:
                    self.send_output_to_js(sid, 'Unknown FTP command. Use: ls, get, put', 'error')
                SM.add_history(sid, cmd)
                return
        
        # Handle SSH commands if connected
        ssh_obj = SM.get_ssh(sid)
        if ssh_obj and ssh_obj.connected:
            ok, out = ssh_obj.run_command(cmd)
            typ = 'success' if ok else 'error'
            self.send_output_to_js(sid, out if out else '(no output)', typ)
            SM.add_history(sid, cmd)
            return
        
        # Handle local commands
        try:
            # Use the session's environment
            env = session.get('env', os.environ.copy())
            
            completed = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=60,
                env=env
            )
            
            out = completed.stdout or completed.stderr or ''
            typ = 'success' if completed.returncode == 0 else 'error'
            self.send_output_to_js(sid, out if out.strip() else '(no output)', typ)
            SM.add_history(sid, cmd)
            
        except subprocess.TimeoutExpired:
            self.send_output_to_js(sid, 'Command timed out.', 'error')
        except Exception as e:
            self.send_output_to_js(sid, str(e), 'error')

    def handle_connect_ssh(self, sid, target):
        parts = shlex.split(target)
        userhost = None
        keyfile = None
        port = 22
        
        for i, tok in enumerate(parts):
            if tok == '-i' and i+1 < len(parts):
                keyfile = parts[i+1]
            elif tok == '-p' and i+1 < len(parts):
                try:
                    port = int(parts[i+1])
                except ValueError:
                    port = 22
            elif not userhost:
                userhost = tok
        
        if not userhost or '@' not in userhost:
            self.send_output_to_js(sid, 'Invalid ssh target. Use: user@host [-i /path] [-p port]', 'error')
            return
        
        username, hostpart = userhost.split('@', 1)
        if ':' in hostpart:
            host, prt = hostpart.split(':', 1)
            try:
                port = int(prt)
            except ValueError:
                pass
        else:
            host = hostpart
        
        if not keyfile:
            cfg = load_config()
            keys = cfg.get('private_keys', [])
            if keys:
                keyfile = keys[0]
        
        ssh = SSHSession()
        
        if keyfile and os.path.exists(keyfile):
            ok, msg = ssh.connect(
                hostname=host,
                username=username,
                key_filename=keyfile,
                port=port
            )
            self.send_output_to_js(sid, msg, 'success' if ok else 'error')
            if ok:
                SM.set_ssh(sid, ssh)
            return
        else:
            def ask_password():
                dlg = wx.PasswordEntryDialog(
                    self,
                    f"Password for {username}@{host}",
                    "SSH Password"
                )
                
                if dlg.ShowModal() == wx.ID_OK:
                    pwd = dlg.GetValue()
                else:
                    pwd = None
                
                dlg.Destroy()
                
                if not pwd:
                    self.send_output_to_js(sid, "SSH connection cancelled.", 'warning')
                    return
                
                ok, msg = ssh.connect(
                    hostname=host,
                    username=username,
                    password=pwd,
                    port=port
                )
                self.send_output_to_js(sid, msg, 'success' if ok else 'error')
                if ok:
                    SM.set_ssh(sid, ssh)
            
            wx.CallAfter(ask_password)

    def handle_disconnect_ssh(self, sid):
        ssh = SM.get_ssh(sid)
        if not ssh:
            self.send_output_to_js(sid, "No SSH session to disconnect.", 'warning')
            return
        
        ok, msg = ssh.disconnect()
        SM.set_ssh(sid, None)
        self.send_output_to_js(sid, msg, 'success' if ok else 'error')

    def handle_connect_ftp(self, sid, target):
        parts = shlex.split(target)
        userhost = None
        port = 21
        
        for i, tok in enumerate(parts):
            if tok == '-p' and i+1 < len(parts):
                try:
                    port = int(parts[i+1])
                except ValueError:
                    port = 21
            elif not userhost:
                userhost = tok
        
        if not userhost or '@' not in userhost:
            self.send_output_to_js(sid, 'Invalid FTP target. Use: user@host [-p port]', 'error')
            return
        
        username, host = userhost.split('@', 1)
        
        # Check for saved credentials
        cfg = load_config()
        cred_key = f"{username}@{host}:{port}"
        password = None
        
        if 'ftp_credentials' in cfg and cred_key in cfg['ftp_credentials']:
            creds = cfg['ftp_credentials'][cred_key].split(':', 1)
            if len(creds) == 2:
                password = creds[1]
        
        ftp = FTPSession()
        
        if password:
            ok, msg = ftp.connect(host, username, password, port)
            self.send_output_to_js(sid, msg, 'success' if ok else 'error')
            if ok:
                SM.set_ftp(sid, ftp)
            return
        else:
            def ask_password():
                dlg = wx.PasswordEntryDialog(
                    self,
                    f"Password for {username}@{host}",
                    "FTP Password"
                )
                
                if dlg.ShowModal() == wx.ID_OK:
                    pwd = dlg.GetValue()
                else:
                    pwd = None
                
                dlg.Destroy()
                
                if not pwd:
                    self.send_output_to_js(sid, "FTP connection cancelled.", 'warning')
                    return
                
                ok, msg = ftp.connect(host, username, pwd, port)
                self.send_output_to_js(sid, msg, 'success' if ok else 'error')
                if ok:
                    SM.set_ftp(sid, ftp)
            
            wx.CallAfter(ask_password)

    def handle_disconnect_ftp(self, sid):
        ftp = SM.get_ftp(sid)
        if not ftp:
            self.send_output_to_js(sid, "No FTP session to disconnect.", 'warning')
            return
        
        ok, msg = ftp.disconnect()
        SM.set_ftp(sid, None)
        self.send_output_to_js(sid, msg, 'success' if ok else 'error')

    def handle_list_ftp(self, sid, path):
        ftp = SM.get_ftp(sid)
        if not ftp:
            self.send_output_to_js(sid, "No active FTP connection.", 'error')
            return
        
        ok, out = ftp.list_files(path)
        typ = 'success' if ok else 'error'
        self.send_output_to_js(sid, out if out else '(no output)', typ)

    def handle_download_ftp(self, sid, remote_path, local_path):
        ftp = SM.get_ftp(sid)
        if not ftp:
            self.send_output_to_js(sid, "No active FTP connection.", 'error')
            return
        
        ok, out = ftp.download_file(remote_path, local_path)
        typ = 'success' if ok else 'error'
        self.send_output_to_js(sid, out, typ)

    def handle_upload_ftp(self, sid, local_path, remote_path):
        ftp = SM.get_ftp(sid)
        if not ftp:
            self.send_output_to_js(sid, "No active FTP connection.", 'error')
            return
        
        ok, out = ftp.upload_file(local_path, remote_path)
        typ = 'success' if ok else 'error'
        self.send_output_to_js(sid, out, typ)

if __name__ == '__main__':
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
