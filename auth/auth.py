import json
from google.cloud import storage
from flask_login import UserMixin


class User(UserMixin):
    """User class for Flask-Login."""
    def __init__(self, email: str, password: str):
        self.id = email.lower().strip()
        self.Password = password
        self.isFirstLogin = True

    @classmethod
    def get(cls, email: str):
        """Retrieves a user from GCS by email."""
        client = storage.Client()
        bucket = client.bucket("data_for_website")
        blob = bucket.blob(f"users/{email.lower().strip()}.json")

        if not blob.exists():
            return None

        data = json.loads(blob.download_as_text())
        return cls(
            emailID=data["email"],
            password=data["PasswordHash"],
        )
    
    def save(self):
        """Saves the user to GCS."""
        client = storage.Client()
        bucket = client.bucket("data_for_website")
        blob = bucket.blob(f"creators/{self.id}.json")
        blob.upload_from_string(json.dumps(self.__dict__), content_type="application/json")

