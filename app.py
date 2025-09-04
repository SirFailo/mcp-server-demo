import os
import flask
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# --- APP CONFIGURATION ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.modify'] 

app = flask.Flask(__name__)
app.secret_key = 'a_super_random_secret_key_for_flask' 

# --- CORE LOGIC ("THE ENGINE" / TOOLS) ---

def get_gmail_service():
    """Builds and returns a Gmail service object from the user's session credentials."""
    if 'credentials' not in flask.session:
        return None
    
    stored_credentials = flask.session['credentials']
    credentials = google.oauth2.credentials.Credentials(**stored_credentials)
    
    return googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)

def get_unread_threads_tool(service, max_results=5):
    """Tool to find unread conversation threads."""
    threads_response = service.users().threads().list(
        userId='me', maxResults=max_results, q="is:unread in:inbox category:primary"
    ).execute()
    return threads_response.get('threads', [])

def read_thread_content_tool(service, thread_id):
    """Tool to read all messages within a specific conversation thread."""
    thread_details = service.users().threads().get(userId='me', id=thread_id).execute()
    return thread_details.get('messages', [])

# --- HELPER FUNCTIONS ---

def get_email_body(payload):
    """Helper function to parse and decode the email body."""
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                body_data = part['body'].get('data', '')
                return base64.urlsafe_b64decode(body_data.encode('ASCII')).decode('utf-8')
    elif 'body' in payload and 'data' in payload['body']:
        body_data = payload['body'].get('data', '')
        return base64.urlsafe_b64decode(body_data.encode('ASCII')).decode('utf-8')
    return "<i>(Body not found or not in plain text format)</i>"

# --- API ENDPOINTS (FOR AGENTS) ---

@app.route('/api/v1/unread_threads', methods=['GET'])
def api_get_unread_threads():
    # Here we would add security checks for CTRLN_API_KEY
    
    gmail_service = get_gmail_service()
    if not gmail_service:
        return flask.jsonify({"status": "error", "message": "User not authenticated"}), 401

    threads = get_unread_threads_tool(gmail_service)
    
    # Format the response for the AI agent
    formatted_threads = []
    for thread_info in threads:
        thread_id = thread_info['id']
        thread_details = gmail_service.users().threads().get(userId='me', id=thread_id, format='metadata').execute()
        subject = next((header['value'] for header in thread_details['messages'][0]['payload']['headers'] if header['name'] == 'Subject'), 'No Subject')
        formatted_threads.append({"id": thread_id, "subject": subject})

    return flask.jsonify({"status": "success", "threads": formatted_threads})

# --- DEMO UI ROUTES (OUR "DASHBOARD") ---
# Authentication routes remain the same

@app.route('/')
def index():
    if 'credentials' in flask.session:
        return flask.redirect(flask.url_for('profile'))
    return '<h1>Welcome!</h1><a href="/login"><button>Login with Google</button></a>'

@app.route('/login')
def login():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=flask.url_for('oauth2callback', _external=True))
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true')
    flask.session['state'] = state
    return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state,
        redirect_uri=flask.url_for('oauth2callback', _external=True))
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    flask.session['credentials'] = {
        'token': credentials.token, 'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri, 'client_id': credentials.client_id,
        'client_secret': credentials.client_secret, 'scopes': credentials.scopes}
    return flask.redirect(flask.url_for('profile'))

@app.route('/profile')
def profile():
    gmail_service = get_gmail_service()
    if not gmail_service:
        return flask.redirect(flask.url_for('index'))
    
    user_info = gmail_service.users().getProfile(userId='me').execute()
    email_address = user_info['emailAddress']
    
    # The UI route now calls our new "tool" function
    threads = get_unread_threads_tool(gmail_service)
    
    if not threads:
        return f"<h1>Profile for {email_address}</h1><p>No unread conversations found!</p><a href='/logout'><button>Logout</button></a>"
    
    conversations_html = "<ul>"
    for thread_info in threads:
        thread_id = thread_info['id']
        thread_details = gmail_service.users().threads().get(userId='me', id=thread_id, format='metadata').execute()
        subject = next((header['value'] for header in thread_details['messages'][0]['payload']['headers'] if header['name'] == 'Subject'), 'No Subject')
        conversations_html += f'<li><a href="/thread/{thread_id}">{subject}</a></li>'
    conversations_html += "</ul>"
    
    return f"""
        <h1>Profile for {email_address}</h1>
        <h2>Last 5 unread conversations:</h2>{conversations_html}<br>
        <a href="/logout"><button>Logout</button></a>"""

@app.route('/thread/<thread_id>')
def view_thread(thread_id):
    gmail_service = get_gmail_service()
    if not gmail_service:
        return flask.redirect(flask.url_for('index'))
    
    # The UI route now calls our new "tool" function
    messages = read_thread_content_tool(gmail_service, thread_id)
    
    html_output = "<h1>Conversation Details</h1><hr>"
    for message in messages:
        headers = message['payload']['headers']
        sender = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown')
        date = next((header['value'] for header in headers if header['name'] == 'Date'), 'Unknown')
        body = get_email_body(message['payload'])
        
        html_output += f"""
            <div><p><strong>From:</strong> {sender}</p><p><strong>Date:</strong> {date}</p>
            <div style="border: 1px solid #ccc; padding: 10px; white-space: pre-wrap;">{body}</div></div><hr>"""
            
    html_output += f"""
        <h2>Reply:</h2>
        <form action="/reply/{thread_id}" method="post">
            <textarea name="reply_body" rows="10" cols="80"></textarea><br><br>
            <button type="submit" name="action" value="reply">Send Reply</button>
            <button type="submit" name="action" value="draft">Create Draft</button>
        </form>
        <br><a href="/profile">Back to profile</a>"""
    return html_output

@app.route('/reply/<thread_id>', methods=['POST'])
def reply_to_thread(thread_id):
    gmail_service = get_gmail_service()
    if not gmail_service:
        return flask.redirect(flask.url_for('index'))

    reply_body = flask.request.form['reply_body']
    action = flask.request.form['action']

    thread_details = gmail_service.users().threads().get(userId='me', id=thread_id).execute()
    last_message = thread_details['messages'][-1]
    headers = last_message['payload']['headers']
    
    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
    to_address = next((h['value'] for h in headers if h['name'] == 'From'), '')
    original_message_id = next((h['value'] for h in headers if h['name'] == 'Message-ID'), '')
    references = next((h['value'] for h in headers if h['name'] == 'References'), '')

    message = MIMEMultipart()
    message['to'] = to_address
    message['subject'] = subject if subject.startswith('Re:') else 'Re: ' + subject
    message['In-Reply-To'] = original_message_id
    message['References'] = references + ' ' + original_message_id
    message.attach(MIMEText(reply_body, 'plain'))
    
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    body = {'raw': raw_message, 'threadId': thread_id}

    if action == 'reply':
        gmail.users().messages().send(userId='me', body=body).execute()
    elif action == 'draft':
        gmail.users().drafts().create(userId='me', body={'message': body}).execute()

    return flask.redirect(flask.url_for('view_thread', thread_id=thread_id))

@app.route('/logout')
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for('index'))

if __name__ == '__main__':
    app.run(port=5000, debug=True)