import os
import time
import hashlib
import psutil
import logging
import shutil
import socket
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

class AdvancedRansomwareDefender(FileSystemEventHandler):
    def __init__(self, watch_path, config_path='defender_config.ini'):
        # Configuration
        self.watch_path = os.path.abspath(watch_path)
        self.config = self._load_config(config_path)
        
        # Detection parameters
        self.suspicion_score = 0
        self.alert_threshold = self.config.getint('detection', 'alert_threshold', fallback=10)
        self.cooldown_period = timedelta(
            minutes=self.config.getint('detection', 'cooldown_minutes', fallback=5)
        )
        self.last_alert = None
        
        # ML Model
        self.model = None
        self.scaler = None
        self._load_ml_model()
        
        # System state tracking
        self.file_operations = []
        self.system_baseline = self._establish_baseline()
        
        # Initialize systems
        self._setup_logging()
        self._setup_notifications()
        print(f"[System] Monitoring initialized for {self.watch_path}")

    def _load_config(self, config_path):
        """Load configuration from file"""
        config = configparser.ConfigParser()
        config.read(config_path)
        
        # Set defaults if not specified
        if not config.has_section('detection'):
            config.add_section('detection')
            config.set('detection', 'alert_threshold', '10')
            config.set('detection', 'cooldown_minutes', '5')
        
        return config

    def _load_ml_model(self):
        """Load trained ML model for anomaly detection"""
        try:
            self.model = joblib.load('models/ransomware_model_latest.pkl')
            self.scaler = joblib.load('models/scaler_latest.pkl')
            if not isinstance(self.model, IsolationForest):
                raise ValueError("Invalid model type")
        except Exception as e:
            print(f"[Warning] ML model not loaded: {str(e)}")
            self.model = None

    def _establish_baseline(self):
        """Establish normal system behavior baseline"""
        print("[System] Establishing behavior baseline...")
        samples = []
        for _ in range(30):  # 30 samples over 30 seconds
            features = self._get_system_features()
            if features is not None:
                samples.append(features)
            time.sleep(1)
        
        if len(samples) < 20:
            return None
            
        return {
            'cpu_mean': np.mean([s[0] for s in samples]),
            'cpu_std': np.std([s[0] for s in samples]),
            'mem_mean': np.mean([s[1] for s in samples]),
            'mem_std': np.std([s[1] for s in samples])
        }

    def _setup_logging(self):
        """Configure comprehensive logging"""
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/defender.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('RansomwareDefender')

    def _setup_notifications(self):
        """Initialize notification system"""
        self.notification_queue = []
        self.admin_email = self.config.get('notifications', 'admin_email', fallback=None)

    def _get_system_features(self):
        """Collect current system metrics"""
        try:
            return [
                psutil.cpu_percent(interval=1),
                psutil.virtual_memory().percent,
                len(psutil.pids()),
                psutil.disk_usage('/').percent,
                psutil.net_io_counters().bytes_sent,
                psutil.net_io_counters().bytes_recv
            ]
        except Exception as e:
            self.logger.error(f"Failed to collect system features: {str(e)}")
            return None

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x)/len(data)
            if p_x > 0:
                entropy += -p_x * (p_x.bit_length() - 1)
        return entropy

    def _detect_encryption(self, filepath):
        """Check if file shows signs of encryption"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(8192)  # Read first 8KB for analysis
                
                # Check entropy
                entropy = self._calculate_entropy(data)
                if entropy > 7.0:  # High entropy suggests encryption
                    return True
                    
                # Check file headers (simple version)
                if not data.startswith(b'\x89PNG') and not data.startswith(b'\xFF\xD8') and not data.startswith(b'%PDF'):
                    return True
                    
        except Exception as e:
            self.logger.warning(f"Could not analyze {filepath}: {str(e)}")
            
        return False

    def _check_suspicious_activity(self, filepath):
        """Evaluate multiple detection indicators"""
        indicators = {
            'suspicious_extension': filepath.lower().endswith(('.encrypted', '.locked', '.crypt', '.ransom')),
            'high_entropy': self._detect_encryption(filepath),
            'mass_modification': len(self.file_operations) > 15 and 
                               (datetime.now() - self.file_operations[0]).seconds < 10,
            'ml_anomaly': False
        }
        
        # Check ML model if available
        if self.model:
            features = self._get_system_features()
            if features:
                scaled = self.scaler.transform([features])
                indicators['ml_anomaly'] = self.model.predict(scaled)[0] == -1
        
        return indicators

    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory or not event.src_path.startswith(self.watch_path):
            return
            
        filepath = event.src_path
        self.file_operations.append(datetime.now())
        
        # Keep only recent operations (last minute)
        self.file_operations = [op for op in self.file_operations 
                              if datetime.now() - op < timedelta(minutes=1)]
        
        # Check for suspicious activity
        indicators = self._check_suspicious_activity(filepath)
        if any(indicators.values()):
            score_increase = sum(2 if v else 0 for v in indicators.values())
            self.suspicion_score = min(self.suspicion_score + score_increase, 20)
            
            self.logger.warning(
                f"Suspicious activity detected on {os.path.basename(filepath)}. "
                f"Indicators: {[k for k,v in indicators.items() if v]}. "
                f"Score: {self.suspicion_score}/{self.alert_threshold}"
            )
            
            # Check if we need to take action
            current_time = datetime.now()
            if (self.suspicion_score >= self.alert_threshold and 
                (self.last_alert is None or 
                 (current_time - self.last_alert) > self.cooldown_period)):
                
                self._take_defensive_actions()
                self.last_alert = current_time
                self.suspicion_score = self.alert_threshold // 2  # Reduce but not reset

    def _take_defensive_actions(self):
        """Execute comprehensive defense strategy"""
        self.logger.critical("ACTIVATING DEFENSIVE MEASURES!")
        
        actions = []
        
        # 1. Process termination
        actions.append(self._terminate_suspicious_processes())
        
        # 2. File quarantine
        actions.append(self._quarantine_suspicious_files())
        
        # 3. Network isolation
        actions.append(self._isolate_network())
        
        # 4. System lockdown
        actions.append(self._lock_system())
        
        # 5. Notify administrator
        actions.append(self._notify_admin())
        
        self.logger.critical(f"Defensive actions taken: {actions}")

    def _terminate_suspicious_processes(self):
        """Kill processes with suspicious behavior"""
        terminated = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                if (info['cpu_percent'] > 70 or info['memory_percent'] > 30) and \
                   'system' not in info['name'].lower() and \
                   info['exe'] and self.watch_path.lower() in info['exe'].lower():
                    
                    psutil.Process(info['pid']).kill()
                    terminated.append(info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return f"Terminated {len(terminated)} processes"

    def _quarantine_suspicious_files(self):
        """Move suspicious files to quarantine"""
        quarantine_dir = os.path.join(self.watch_path, "QUARANTINE")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        quarantined = 0
        for item in os.listdir(self.watch_path):
            item_path = os.path.join(self.watch_path, item)
            if os.path.isfile(item_path) and self._detect_encryption(item_path):
                try:
                    target = os.path.join(
                        quarantine_dir,
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{item}"
                    )
                    shutil.move(item_path, target)
                    quarantined += 1
                except Exception as e:
                    self.logger.error(f"Failed to quarantine {item}: {str(e)}")
                    
        return f"Quarantined {quarantined} files"

    def _isolate_network(self):
        """Disconnect from network"""
        try:
            # Windows specific
            os.system("netsh interface set interface \"Wi-Fi\" admin=disable")
            os.system("netsh interface set interface \"Ethernet\" admin=disable")
            return "Network disabled"
        except Exception as e:
            self.logger.error(f"Network isolation failed: {str(e)}")
            return "Network isolation failed"

    def _lock_system(self):
        """Lock the workstation"""
        try:
            # Windows specific
            os.system("rundll32.exe user32.dll,LockWorkStation")
            return "System locked"
        except Exception as e:
            self.logger.error(f"System lock failed: {str(e)}")
            return "System lock failed"

    def _notify_admin(self):
        """Send alert to administrator"""
        if not self.admin_email:
            return "No admin email configured"
            
        try:
            msg = EmailMessage()
            msg.set_content(
                f"Ransomware attack detected on {socket.gethostname()}!\n"
                f"Path: {self.watch_path}\n"
                f"Time: {datetime.now()}\n"
                f"Please investigate immediately!"
            )
            msg['Subject'] = "URGENT: Ransomware Alert"
            msg['From'] = "ransomware_defender@yourdomain.com"
            msg['To'] = self.admin_email
            
            with smtplib.SMTP('localhost') as s:
                s.send_message(msg)
            return "Admin notified"
        except Exception as e:
            self.logger.error(f"Notification failed: {str(e)}")
            return "Notification failed"

def start_monitoring(path_to_watch):
    """Initialize and start the monitoring service"""
    if not os.path.exists(path_to_watch):
        print(f"Error: Watch path '{path_to_watch}' does not exist!")
        return

    print(f"\n=== Advanced Ransomware Defender ===")
    print(f"Monitoring: {path_to_watch}")
    print("Press Ctrl+C to stop\n")
    
    observer = Observer()
    event_handler = AdvancedRansomwareDefender(path_to_watch)
    observer.schedule(event_handler, path_to_watch, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nMonitoring stopped by user")
    observer.join()

if __name__ == "__main__":
    import configparser
    watch_path = "C:\\TestFiles"  # Change to your directory
    start_monitoring(watch_path)
    