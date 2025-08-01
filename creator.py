import uuid 
import json
from google.cloud import storage

class Creator():

    def __init__(self, creator_id, email, password): 

        self.CreatorId = creator_id
        self.email = email 
        self.password = password
        self.ShopCatalog = {}
        self.youtubeData = {
            "channel_id": "<YOUTUBE_CHANNEL_ID>",
            "channel_title": "<CHANNEL_TITLE>",
            "description": "<CHANNEL_DESCRIPTION>",
            "statistics": {
                "subscriber_count": "<SUBSCRIBER_COUNT>",
                "view_count": "<TOTAL_VIEW_COUNT>",
                "video_count": "<TOTAL_VIDEO_COUNT>"
            },
            "top_videos": [
                {
                    "video_id": "<VIDEO_ID_1>",
                    "title": "<VIDEO_TITLE_1>",
                    "publish_date": "<YYYY-MM-DD>",
                    "transcript": "<FULL_TRANSCRIPT_TEXT_OR_UNAVAILABLE>"
                }
            ]
        }
        
        self.twitchData = {
            "user_id": "<TWITCH_USER_ID>",
            "login": "<TWITCH_LOGIN_NAME>",
            "display_name": "<TWITCH_DISPLAY_NAME>",
            "type": "<NORMAL_OR_BROADCASTER>",
            "broadcaster_type": "<AFFILIATE_OR_PARTNER_OR_EMPTY>",
            "description": "<CHANNEL_DESCRIPTION>",
            "profile_image_url": "<URL_TO_AVATAR>",
            "offline_image_url": "<URL_TO_OFFLINE_SCREENSHOT>",
            "view_count": "<TOTAL_VIEW_COUNT_ON_CHANNEL>"
        }
        self.threadsData = {}
        self.redditData = {}

    def save(self):
        """Saves the creator to GCS."""
        client = storage.Client()
        bucket = client.bucket("qloo_hackathon_scepter_bucket")
        blob = bucket.blob(f"creators/{self.CreatorId}.json")
        blob.upload_from_string(json.dumps(self.__dict__), content_type="application/json")



