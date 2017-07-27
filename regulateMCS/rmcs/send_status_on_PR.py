"""
Status:
0 : All okay
1 : failed, something went wrong in code
2 : failed, request is not json
-1 : pending
"""
import requests
import pat_token
import os
import json
PAT_TOKEN = pat_token.TOKEN


def send(status, repo_login, repo_name, head_sha_hash, stat_string):
    headers = {
        "Authorization" : "token " + PAT_TOKEN
    }

    payload = {
        "state" : "success"
    }

    if status == 0:
        # alls well
        payload["description"] = "Alerts intimated"

    elif status == 1:
        
        payload["state"] = "failure"
        payload["description"] = "Something went wrong, check in code"
        # print the stack trace
        print stat_string

    elif status == 2:
        
        payload["state"] = "failure"
        payload["description"] = "request was not json"
        print stat_string
    
    else:
        
        payload["state"] = "pending"
        payload["descirption"] = "Still processing"
        
    url = os.path.join("https://api.github.com/repos", repo_login, repo_name, "statuses",\
                       head_sha_hash)
    r = requests.post(url, headers=headers, data=json.dumps(payload))
    # printing the json response is not really required
    # print json.dumps(r.json(), indent=4, separators=(',', ': '))