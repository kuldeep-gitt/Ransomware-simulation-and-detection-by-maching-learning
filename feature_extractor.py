# feature_extractor.py
import psutil
import numpy as np

def get_system_features():
    """Capture 10 key features for ML model"""
    features = []
    
    # Process features (5 metrics)
    for proc in psutil.process_iter(['cpu_percent', 'memory_percent', 'num_handles']):
        features.extend([
            proc.info['cpu_percent'],
            proc.info['memory_percent'],
            proc.info['num_handles']
        ])
        if len(features) >= 5:  # Limit to top 5 processes
            break
    
    # System features (5 metrics)
    features.extend([
        psutil.cpu_percent(interval=1),
        psutil.virtual_memory().percent,
        len(psutil.net_connections()),
        len([f for f in psutil.disk_io_counters(perdisk=False)]),
        psutil.net_io_counters().bytes_sent
    ])
    
    return np.array(features[:10])  # Ensure 10 features