import json
from google.cloud import storage
from flask_login import UserMixin
import typing


class User(UserMixin):
    """User class for Flask-Login."""
    def __init__(self, email: str, password: str, isFirstLogin: bool):
        self.id = email.lower().strip()
        self.Password = password
        self.isFirstLogin = isFirstLogin

    @classmethod
    def get(cls, email: str) -> typing.Optional["User"]:
        """Retrieves a user from GCS by email."""
        client = storage.Client()
        bucket = client.bucket("qloo_hackathon_scepter_bucket")
        blob = bucket.blob(f"creators/{email.lower().strip()}/userInfo.json")

        if not blob.exists():
            return None

        data = json.loads(blob.download_as_text())
        return cls(
            email=data["id"],    
            password=data["Password"],
            isFirstLogin=data["isFirstLogin"]
        )
    
    def save(self):
        """Saves the user to GCS."""
        client = storage.Client()
        bucket = client.bucket("qloo_hackathon_scepter_bucket")
        blob = bucket.blob(f"creators/{self.id}/userInfo.json")
        blob.upload_from_string(json.dumps(self.__dict__), content_type="application/json")

    @classmethod
    def upload_json(cls, data, bucket_name, destination_blob_name):
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        blob.upload_from_string(json.dumps(data), content_type="application/json")
        return blob.public_url
