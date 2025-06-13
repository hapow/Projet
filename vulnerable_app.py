#!/usr/bin/env python3
"""
Application de démonstration avec vulnérabilités de sécurité
ATTENTION : Code à des fins éducatives uniquement !
"""

import sqlite3
import hashlib
import requests
import smtplib
from email.mime.text import MIMEText

class VulnerableApp:
    def __init__(self):
        # VULNÉRABILITÉ 1: Mots de passe en clair dans le code
        self.admin_password = "admin123"
        self.database_password = "mySecretPass2024"
        
        # VULNÉRABILITÉ 2: Clés API exposées
        self.api_key = "sk-1234567890abcdef1234567890abcdef"
        self.secret_key = "super_secret_key_do_not_share"
        self.jwt_secret = "my_jwt_secret_2024"
        
        # VULNÉRABILITÉ 3: Informations de connexion base de données
        self.db_host = "prod-db.company.com"
        self.db_user = "root"
        self.db_pass = "RootPassword123!"
        
        # VULNÉRABILITÉ 4: Credentials email
        self.smtp_user = "admin@company.com"
        self.smtp_pass = "EmailPass2024!"
        
        # VULNÉRABILITÉ 5: Tokens d'accès
        self.github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        self.aws_access_key = "AKIAIOSFODNN7EXAMPLE"
        self.aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        
        print("🚨 Application vulnérable initialisée")
        print("⚠️  Credentials détectés dans le code source !")

    def authenticate_user(self, username, password):
        """Authentification utilisateur avec mot de passe hardcodé"""
        # VULNÉRABILITÉ 6: Comparaison de mot de passe non sécurisée
        if username == "admin" and password == self.admin_password:
            print(f"✅ Connexion réussie pour {username}")
            return True
        else:
            print("❌ Échec de l'authentification")
            return False

    def connect_database(self):
        """Connexion à la base de données avec credentials exposés"""
        try:
            # Simulation de connexion avec credentials en clair
            connection_string = f"mysql://{self.db_user}:{self.db_pass}@{self.db_host}/app_db"
            print(f"🔗 Tentative de connexion: {connection_string}")
            print("⚠️  Credentials de base de données exposés dans les logs !")
            return True
        except Exception as e:
            print(f"❌ Erreur de connexion: {e}")
            return False

    def make_api_call(self, endpoint):
        """Appel d'API avec clé exposée"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-API-Key": self.secret_key
        }
        
        print(f"🌐 Appel API vers: {endpoint}")
        print(f"🔑 Utilisation de la clé API: {self.api_key}")
        print("⚠️  Clé API exposée dans les logs !")
        
        # Simulation d'appel API
        return {"status": "success", "data": "API response"}

    def send_email(self, to_email, subject, body):
        """Envoi d'email avec credentials SMTP exposés"""
        try:
            print(f"📧 Envoi d'email à: {to_email}")
            print(f"🔐 Utilisation du compte: {self.smtp_user}")
            print(f"🔑 Mot de passe SMTP: {self.smtp_pass}")
            print("⚠️  Credentials SMTP exposés !")
            return True
        except Exception as e:
            print(f"❌ Erreur envoi email: {e}")
            return False

    def backup_to_cloud(self):
        """Sauvegarde cloud avec credentials AWS exposés"""
        print("☁️  Sauvegarde vers AWS S3...")
        print(f"🔑 Access Key: {self.aws_access_key}")
        print(f"🔐 Secret Key: {self.aws_secret_key}")
        print("⚠️  Credentials AWS exposés !")
        
        # Simulation de sauvegarde
        return {"backup_id": "backup_12345", "status": "completed"}

    def generate_jwt_token(self, user_id):
        """Génération de token JWT avec secret exposé"""
        import json
        import base64
        
        # Simulation de génération JWT
        payload = {"user_id": user_id, "role": "admin"}
        
        print(f"🎫 Génération token JWT pour utilisateur: {user_id}")
        print(f"🔑 Secret JWT utilisé: {self.jwt_secret}")
        print("⚠️  Secret JWT exposé dans le code !")
        
        # Token simulé
        token = base64.b64encode(json.dumps(payload).encode()).decode()
        return token

    def run_demo(self):
        """Démonstration des vulnérabilités"""
        print("\n" + "="*50)
        print("🎯 DÉMONSTRATION DES VULNÉRABILITÉS")
        print("="*50)
        
        # Test d'authentification
        print("\n1. Test d'authentification:")
        self.authenticate_user("admin", "admin123")
        
        # Test de connexion DB
        print("\n2. Connexion base de données:")
        self.connect_database()
        
        # Test d'API
        print("\n3. Appel d'API:")
        self.make_api_call("https://api.example.com/users")
        
        # Test d'email
        print("\n4. Envoi d'email:")
        self.send_email("user@example.com", "Test", "Message de test")
        
        # Test de sauvegarde cloud
        print("\n5. Sauvegarde cloud:")
        self.backup_to_cloud()
        
        # Test de génération JWT
        print("\n6. Génération token JWT:")
        token = self.generate_jwt_token("user123")
        print(f"Token généré: {token}")
        
        print("\n" + "="*50)
        print("⚠️  RÉSUMÉ DES VULNÉRABILITÉS DÉTECTÉES:")
        print("="*50)
        print("🔴 Mots de passe en clair dans le code")
        print("🔴 Clés API exposées")
        print("🔴 Credentials de base de données visibles")
        print("🔴 Informations SMTP en clair")
        print("🔴 Tokens d'accès cloud exposés")
        print("🔴 Secrets JWT hardcodés")
        print("🔴 Logs contenant des informations sensibles")
        print("\n💡 Utilisez des variables d'environnement ou des gestionnaires de secrets !")

if __name__ == "__main__":
    # VULNÉRABILITÉ 7: Configuration en dur
    DEBUG = True
    SECRET_TOKENS = {
        'payment_gateway': 'pk_live_1234567890abcdef',
        'social_media': 'fb_app_secret_abcdef123456',
        'analytics': 'ga_tracking_secret_xyz789'
    }
    
    print("🚨 ATTENTION: Application à des fins éducatives uniquement!")
    print("⚠️  Ne jamais utiliser en production!")
    
    app = VulnerableApp()
    app.run_demo()
