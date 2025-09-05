#!/bin/bash

echo "--- startup.sh: Script has started. ---"

# Verify that environment variables are set
if [ -z "$GOOGLE_CLIENT_ID" ] || [ -z "$GOOGLE_CLIENT_SECRET" ]; then
  echo "--- startup.sh: FATAL ERROR - Google credentials are not set in the environment. Exiting. ---"
  exit 1
fi

echo "--- startup.sh: Environment variables found. Creating client_secret.json... ---"

# Create the client_secret.json file
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

echo "--- startup.sh: client_secret.json created successfully. ---"
echo "--- startup.sh: Listing files to confirm: ---"
ls -l

echo "--- startup.sh: Starting Gunicorn server now. ---"
# Now, start the web server
gunicorn --bind 0.0.0.0:$PORT app:app