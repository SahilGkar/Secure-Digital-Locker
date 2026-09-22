import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'locker.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    RSA_KEY_DIR = os.path.join(BASE_DIR, 'instance', 'keys')
    STORAGE_PATH = os.path.join(BASE_DIR, 'storage', 'blobs')
    
    # Enable tamper detection demo endpoint (set False in production)
    DEMO_MODE = True
    
    # Short-lived serve token expiry in seconds
    SERVE_TOKEN_EXPIRY = 30