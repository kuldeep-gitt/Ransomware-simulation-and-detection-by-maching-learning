import os
import time
import random
import numpy as np
import pandas as pd
import psutil
from datetime import datetime, timedelta

def get_system_features():
    """Collect system metrics for training data"""
    try:
        return np.array([
            psutil.cpu_percent(interval=1),
            psutil.virtual_memory().percent,
            len(psutil.pids()),
            psutil.disk_usage('/').percent,
            psutil.net_io_counters().bytes_sent,
            psutil.net_io_counters().bytes_recv
        ])
    except Exception as e:
        print(f"Error collecting features: {e}")
        return None

def encrypt_files(target_path, num_files=10):
    """Simulate ransomware file encryption"""
    extensions = ['.docx', '.xlsx', '.pdf', '.jpg', '.png', '.txt']
    for i in range(num_files):
        try:
            filename = f"file_{i}{random.choice(extensions)}"
            filepath = os.path.join(target_path, filename)
            
            # Create original file if doesn't exist
            if not os.path.exists(filepath):
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(random.randint(1024, 10240)))
            
            # "Encrypt" by renaming
            encrypted_path = f"{filepath}.encrypted"
            os.rename(filepath, encrypted_path)
            print(f"Encrypted {filename}")
            
        except Exception as e:
            print(f"Error encrypting file: {e}")

def generate_training_data(target_path, output_file='data/training_data.csv'):
    """Generate training data by simulating normal and attack behavior"""
    os.makedirs('data', exist_ok=True)
    features = []
    
    print("Collecting normal behavior samples...")
    for i in range(100):  # Normal behavior
        feat = get_system_features()
        if feat is not None:
            features.append(np.append(feat, 0))  # Label 0 for normal
        time.sleep(0.5)
        print(f"Collected {i+1}/100 normal samples", end='\r')
    
    print("\nSimulating ransomware attack...")
    encrypt_files(target_path)
    
    print("Collecting attack behavior samples...")
    for i in range(100):  # Attack behavior
        feat = get_system_features()
        if feat is not None:
            features.append(np.append(feat, 1))  # Label 1 for attack
        time.sleep(0.5)
        print(f"Collected {i+1}/100 attack samples", end='\r')
    
    # Save to CSV
    columns = ['cpu', 'memory', 'processes', 'disk', 'net_out', 'net_in', 'label']
    pd.DataFrame(features, columns=columns).to_csv(output_file, index=False)
    print(f"\nTraining data saved to {output_file}")

def run_simulation(target_path, duration=300):
    """Run the ransomware simulation"""
    extensions = ['.docx', '.xlsx', '.pdf', '.jpg', '.png', '.txt']
    end_time = datetime.now() + timedelta(seconds=duration)
    
    print(f"Starting simulation in {target_path} for {duration} seconds")
    
    try:
        while datetime.now() < end_time:
            action = random.choice(['create', 'modify', 'encrypt'])
            filename = f"file_{random.randint(1,1000)}{random.choice(extensions)}"
            filepath = os.path.join(target_path, filename)
            
            if action == 'create':
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(random.randint(1024, 10240)))
                print(f"Created {filename}")
            
            elif action == 'modify' and os.path.exists(filepath):
                with open(filepath, 'ab') as f:
                    f.write(os.urandom(random.randint(512, 5120)))
                print(f"Modified {filename}")
            
            elif action == 'encrypt' and os.path.exists(filepath):
                encrypted_name = f"{filename}.encrypted"
                os.rename(filepath, os.path.join(target_path, encrypted_name))
                print(f"Encrypted {filename} -> {encrypted_name}")
            
            time.sleep(random.uniform(0.1, 1.0))
            
    except KeyboardInterrupt:
        print("\nSimulation stopped by user")
    finally:
        print("Simulation completed")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Simulation Tool")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Data generation command
    data_parser = subparsers.add_parser('generate-data', help='Generate training data')
    data_parser.add_argument('--path', default='.', help='Target directory path')
    data_parser.add_argument('--output', default='data/training_data.csv', 
                           help='Output CSV file path')
    
    # Simulation command
    sim_parser = subparsers.add_parser('simulate', help='Run ransomware simulation')
    sim_parser.add_argument('--path', default='.', help='Target directory path')
    sim_parser.add_argument('--duration', type=int, default=300, 
                          help='Simulation duration in seconds')
    
    args = parser.parse_args()
    
    if args.command == 'generate-data':
        generate_training_data(args.path, args.output)
    elif args.command == 'simulate':
        run_simulation(args.path, args.duration)