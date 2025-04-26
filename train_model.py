import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from datetime import datetime

class RansomwareModelTrainer:
    def __init__(self, data_path='data/training_data.csv'):
        self.data_path = data_path
        self.features = [
            'cpu', 'memory', 'processes', 
            'disk', 'net_out', 'net_in'
        ]
        self.target = 'label'
        
    def load_data(self):
        """Load and validate training data"""
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Data file not found at {self.data_path}")
            
        data = pd.read_csv(self.data_path)
        
        # Validate data
        missing = set(self.features + [self.target]) - set(data.columns)
        if missing:
            raise ValueError(f"Missing columns: {missing}")
            
        if data.isnull().any().any():
            raise ValueError("Data contains missing values")
            
        return data[self.features], data[self.target]
    
    def train_model(self, X, y):
        """Train and evaluate the Isolation Forest model"""
        # Split data (stratified to maintain class ratio)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
            
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train Isolation Forest
        model = IsolationForest(
            n_estimators=150,
            contamination=0.05,  # Expected anomaly rate
            max_samples='auto',
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        model.fit(X_train_scaled)
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        y_pred = [1 if x == -1 else 0 for x in y_pred]  # Convert to binary labels
        
        print("\nModel Evaluation:")
        print(classification_report(y_test, y_pred))
        
        return model, scaler
    
    def save_model(self, model, scaler):
        """Save model artifacts with versioning"""
        os.makedirs('models', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        model_path = f"models/ransomware_model_{timestamp}.pkl"
        scaler_path = f"models/scaler_{timestamp}.pkl"
        
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
        
        # Create latest symlinks
        for src, dest in [
            (model_path, 'models/ransomware_model_latest.pkl'),
            (scaler_path, 'models/scaler_latest.pkl')
        ]:
            if os.path.exists(dest):
                os.remove(dest)
            try:
                os.symlink(os.path.basename(src), dest)
            except OSError:
                # Fallback for Windows if symlinks aren't supported
                import shutil
                shutil.copy(src, dest)
        
        print(f"\nModel saved to {model_path}")
        print(f"Scaler saved to {scaler_path}")

def train_and_save_model():
    """Main training workflow"""
    print("=== Ransomware Anomaly Detection Model Trainer ===")
    
    trainer = RansomwareModelTrainer()
    try:
        # Load and prepare data
        X, y = trainer.load_data()
        
        # Train model
        model, scaler = trainer.train_model(X, y)
        
        # Save artifacts
        trainer.save_model(model, scaler)
        print("\nTraining completed successfully!")
    except Exception as e:
        print(f"\n[ERROR] Training failed: {str(e)}")
        raise

if __name__ == "__main__":
    train_and_save_model()