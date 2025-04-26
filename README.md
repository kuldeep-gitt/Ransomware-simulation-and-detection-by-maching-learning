📋 Table of Contents

1.Project Overview

2.Prerequisites

3.Setup Guide

4.Usage

5.Machine Learning Integration

6.Contributing

7.License

🌐 Project Overview

A safe environment to simulate ransomware behavior and build ML-powered detection systems. Perfect for cybersecurity research and education.

Key Features:

1.Safe ransomware simulation in isolated VM

2.Real-time anomaly detection using Isolation Forest

3.Automated defensive actions

4.Detailed logging and analysis

🛠️ Prerequisites

a.Hardware Requirements

1.4+ CPU cores

2.8GB+ RAM

3.100GB free storage

Software Requirements

1.VMware Workstation Player	 https://www.vmware.com/products/workstation-player.html

2.Windows 10/11 ISO	         https://www.microsoft.com/software-download

3.Python 3.8+	               https://www.python.org/downloads/

🚀 Setup Guide

1. Virtual Machine Setup

a. Create new VM in VMware:

   - Type: Microsoft Windows
   - Version: Windows 10/11
   - RAM: 4096MB
   - Disk: 50GB (Thin Provisioned)

b. Install Windows:

   - Use "Standard User" account
   - Disable automatic driver updates
   - Take snapshot after installation (label "Clean Install")

c. Critical VM Settings:
   
   - Network: Host-only adapter
   - Disable shared folders
   - Enable drag-and-drop (for file transfer)

2. Python Environment

a. Install required packages

  -: pip install -r requirements.txt

b.requirements.txt:

scikit-learn==1.0.2

pandas==1.4.0

numpy==1.22.0

psutil==5.9.0

watchdog==2.1.6

joblib==1.1.0

python-dotenv==0.20.0

3. Directory Structure

   /ransomware-detection
   
│

├── /data                  # Training datasets

├── /models                # ML models

├── /logs                  # Detection logs

├── /test_files            # Sample files for simulation

│

├── ransomware_simulator.py

├── ml_defender.py

├── feature_extractor.py

├── train_model.py

├── README.md

└── requirements.txt


🖥️ Usage

1.Running the Simulation

a.Generate training data (normal + attack behavior)
-: python ransomware_simulator.py --mode simulate --path "C:\TestFiles"

b.Monitor only mode
-: python ransomware_simulator.py --mode monitor --path "C:\TestFiles"

2.Starting the Defender
 -: python ml_defender.py --path "C:\TestFiles" --threshold 3

3.Command Line Options

a.--path = Directory to monitor

b.--threshold = Alerts before action

c.--log = Log file path

🤖 Machine Learning Integration

1.Feature Extraction

2.Model Training

🔍 Testing Procedure

1.Initial Test:

a.Terminal 1 - Start defender
-: python ml_defender.py --path "C:\TestFiles" --verbose

b.Terminal 2 - Create test files
-: 1..100 | % { New-Item -Path "C:\TestFiles\test_$_.txt" }

2.Simulation Test:

-: python ransomware_simulator.py --mode simulate --intensity high

📚 Resources

1.VMware Documentation-https://docs.vmware.com/

2.Scikit-learn Isolation Forest-https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

3.Windows Sysinternals for advanced monitoring-https://learn.microsoft.com/en-us/sysinternals/

🛡️ Safety Notice

1.Run simulations in isolated VMs

2.Use dummy data files

3.Keep network disabled during tests

4.Maintain regular snapshots

![Screenshot 2025-04-26 224250](https://github.com/user-attachments/assets/bcb1526a-c7f9-45e9-9745-6dd2346a87ca)
