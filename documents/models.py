import datetime
from auth.models import db

class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    document_type = db.Column(db.String(120), nullable=True)
    storage_path = db.Column(db.String(512), nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary(12), nullable=False)
    auth_tag = db.Column(db.LargeBinary(16), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f'<Document {self.original_filename}>'