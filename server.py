from google_auth_oauthlib.flow import Flow
from flask import redirect, url_for, session, request, current_app
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.oauth2.credentials import Credentials  
import json 
import os 
from flask import (
    Flask, abort, flash, jsonify, redirect, render_template,
    request, session, url_for, current_app
)
from flask_login import login_user, login_required, logout_user, current_user
from datetime import timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from auth import User
from google.cloud import storage
from creator import Creator
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = 'your-strong-random-secret'

def upload_json(data, bucket_name, destination_blob_name):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_string(json.dumps(data), content_type="application/json")
    return blob.public_url


@app.route("/", methods=["GET", "POST"])
def MainPage(): 
    return render_template("mainPage.html")

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard(): 
    user = User.get(current_user.id)
    if user is None:
        flash("User not found")
        return redirect(url_for('login'))
    
    if user.isFirstLogin:
        user.isFirstLogin = False
        user.save()

        return redirect(url_for('firstLogin'), user=user)
    
    return render_template("dashboard.html", user=user)

@app.route("/login", methods=["GET", "POST"])
def login(): 
    if request.method == "GET":
        return render_template("login.html")
    
    formEmail = request.form.get('email')
    formPassword = request.form.get('password')

    if not formEmail or not formPassword:
        flash("Please fill in all fields")
        return redirect(url_for('login'))
    
    user = User.get(formEmail)
    if user and check_password_hash(user.Password, formPassword):
        login_user(user, remember=True, duration=timedelta(days=365))
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid email or password")
        return redirect(url_for('login'))


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    formEmail = request.form.get('email')
    formPassword = request.form.get('password')
    formConfirmPassword = request.form.get('confirm_password')

    if formPassword != formConfirmPassword:
        flash("Passwords do not match")
        return redirect(url_for('signup'))

    if not formEmail or not formPassword or not formConfirmPassword:
        flash("Please fill in all fields")
        return redirect(url_for('signup'))
    
    if User.get(formEmail) is not None:
        flash("Email already exists")
        return redirect(url_for('signup'))

    user_data = {
        "email": formEmail,
        "PasswordHash": generate_password_hash(formPassword)
    }
    
    try:
        upload_json(
            data=user_data,
            bucket_name='data_for_website',
            destination_blob_name=f'creators/{formEmail.lower().strip()}.json'
        )

        flash("Account created! You can now log in.", "success")
        creator = Creator(formEmail, formPassword)
        creator.save()
        return redirect(url_for('login'))
    except Exception as e:
        current_app.logger.error(f"Failed to upload user blob: {e}")
        flash("Oops, something went wrong. Please try again.", "danger")
        return redirect(url_for('signup'))


@app.route("/connectYoutube", methods=["GET", "POST"])
@login_required
def connectYoutube():
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=[
            "https://www.googleapis.com/auth/youtube.readonly",
            "openid", "email"
        ],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)

@app.route("/oauth2callback")
@login_required
def oauth2callback():
    if 'error' in request.args:
        flash(f"Error: {request.args['error']}")
        return redirect(url_for('dashboard'))
    
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=[
            "https://www.googleapis.com/auth/youtube.readonly",
            "openid", "email"
        ],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['youtube_token'] = credentials.to_json()
    return redirect(url_for('dashboard'))

@app.route('/fetch_youtube_data')
def fetch_youtube_data():
    creds = Credentials.from_authorized_user_file(session['youtube_token'])
    youtube = build("youtube", "v3", credentials=creds)

    # Get channel info
    channel_response = youtube.channels().list(
        part="snippet,statistics",
        mine=True
    ).execute()
    
    channel = channel_response['items'][0]
    description = channel['snippet']['description']
    title = channel['snippet']['title']
    channel_id = channel['id']

    # Get top 5 videos
    top_videos = youtube.search().list(
        channelId=channel_id,
        part="snippet",
        order="viewCount",
        maxResults=5,
        type="video"
    ).execute()

    video_data = []
    for item in top_videos['items']:
        video_id = item['id']['videoId']
        video_title = item['snippet']['title']

        # Try to fetch transcript
        try:
            from youtube_transcript_api import YouTubeTranscriptApi
            transcript = YouTubeTranscriptApi.get_transcript(video_id)
            full_text = " ".join([t["text"] for t in transcript])
        except:
            full_text = "(Transcript unavailable)"

        video_data.append({
            'title': video_title,
            'id': video_id,
            'transcript': full_text
        })


    return render_template("creator_summary.html", channel_title=title,
                           description=description, videos=video_data)

@app.route('/connectTwitch', methods=["GET", "POST"])
@login_required
def connect_twitch():
    client_id = os.environ["TWITCH_CLIENT_ID"]
    redirect_uri = url_for("twitch_callback", _external=True)
    scopes = "user:read:email channel:read:subscriptions"
    auth_url = (
        f"https://id.twitch.tv/oauth2/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={scopes}"
        f"&state=xyz123"
    )
    return redirect(auth_url)

@app.route("/twitch/callback")
@login_required
def twitch_callback():
    code = request.args.get("code")
    if not code:
        flash("Twitch authorization failed.")
        return redirect(url_for("dashboard"))

    client_id = os.environ["TWITCH_CLIENT_ID"]
    client_secret = os.environ["TWITCH_CLIENT_SECRET"]
    redirect_uri = url_for("twitch_callback", _external=True)

    token_url = "https://id.twitch.tv/oauth2/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri
    }

    res = requests.post(token_url, data=payload)
    data = res.json()

    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # ✅ Save these securely tied to the current user
    save_twitch_token(current_user.id, access_token, refresh_token)

    flash("Twitch connected!")
    return redirect(url_for("dashboard"))

def refresh_twitch_token(refresh_token):
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": os.environ["TWITCH_CLIENT_ID"],
        "client_secret": os.environ["TWITCH_CLIENT_SECRET"]
    }

    res = requests.post("https://id.twitch.tv/oauth2/token", data=payload)
    return res.json()


def get_twitch_user_info(access_token):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Client-Id": os.environ["TWITCH_CLIENT_ID"]
    }
    res = requests.get("https://api.twitch.tv/helix/users", headers=headers)
    return res.json()


if __name__ == "__main__":
    app.run(debug=True)