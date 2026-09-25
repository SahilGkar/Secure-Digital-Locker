import os
from flask import Flask, redirect, url_for
from config import Config
from auth.models import db
from auth.routes import auth_bp
from documents.routes import documents_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    
    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))
    
    with app.app_context():
        from auth.models import User
        from documents.models import Document
        db.create_all()
        from crypto.rsa_engine import initialize_keys
        initialize_keys()
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )