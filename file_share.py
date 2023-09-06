import os
import http.server
import json
from urllib.parse import parse_qs
from http.server import HTTPServer


from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.signature import SignatureVerifier


slack_signing_secret = os.environ["SLACK_SIGNING_SECRET"]
slack_bot_token = os.environ["SLACK_BOT_TOKEN"]

# Initialize the Slack WebClient
slack_client = WebClient(token=slack_bot_token)
signature_verifier = SignatureVerifier(slack_signing_secret)

class SlackRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(200)
            self.end_headers()
            return
        
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)

        # Verify the incoming request's signature
        if not signature_verifier.is_valid_request(post_data, self.headers):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        # Parse the request body as JSON
        data = json.loads(post_data.decode("utf-8"))

        # Check if the event is a file upload event
        if data["type"] == "file_shared":
            file_id = data["file_id"]
            channel = data["channel_id"]
            user = data["user_id"]

            # Respond with a message containing additional options
            message = f"Hey <@{user}>, thanks for sharing the file! What would you like to do with it?"
            actions = [
                {
                    "name": "share",
                    "text": "Share File",
                    "type": "button",
                    "value": "share_file",
                },
                {
                    "name": "download",
                    "text": "Download File",
                    "type": "button",
                    "value": "download_file",
                },
                # Add more custom actions here
            ]

            try:
                response = slack_client.chat_postMessage(
                    channel=channel,
                    text=message,
                    attachments=[{"text": "Choose an option:", "fallback": "Options", "callback_id": file_id, "actions": actions}],
                )
            except SlackApiError as e:
                print(f"Error posting message: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
                return


        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

def run(server_class=HTTPServer, handler_class=SlackRequestHandler, port=3000):
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
