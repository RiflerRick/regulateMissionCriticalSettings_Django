"""
Status:
0 : All okay
1 : failed, something went wrong in code
2 : failed, request is not json
-1 : pending
"""
from django.conf import settings
import requests
import os, json

PAT_TOKEN = settings.TOKEN


# TODO: exception handling for errors on status update
def send(status, repo_login, repo_name, head_sha_hash, stat_string):
    headers = {
        "Authorization" : "token " + PAT_TOKEN
    }

    payload = {
        "state" : "success",
        "description" : "Tests for change in mission critical settings",
        "context" : "Github RMCS Test"
    }

    if status == 0:
        # alls well
        payload["description"] = "Alerts intimated"

    elif status == 1:
        payload["state"] = "failure"
        payload["description"] = "Something went wrong, check in code"

    elif status == 2:
        payload["state"] = "failure"
        payload["description"] = "request was not json"
    
    else:
        payload["state"] = "pending"
        payload["description"] = "Still processing"
        
    url = os.path.join("https://api.github.com/repos", repo_login, repo_name, "statuses",\
                       head_sha_hash)
    r = requests.post(url, headers=headers, data=json.dumps(payload))