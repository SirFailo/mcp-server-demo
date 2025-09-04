#!/bin/bash

# This script creates the client_secret.json file from environment variables
# before starting the Gunicorn server.

echo "{
  \"web\": {
    \"client_id\": \"$GOOGLE_CLIENT_ID\",
    \"project_id\": \"mcp-server-demo-ctrln\",
    \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",
    \"token_uri\": \"https://oauth2.googleapis.com/token\",
    \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",
    \"client_secret\": \"$GOOGLE_CLIENT_SECRET\",
    \"redirect_uris\": [
      \"https://mcp-server-demo-uyvx.onrender.com/oauth2callback\"
    ]
  }
}" > client_secret.json

# Now, start the web server
gunicorn --bind 0.0.0.0:$PORT app:app