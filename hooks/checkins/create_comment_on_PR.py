"""
creates a comment on PR page
"""
from django.conf import settings

import requests
import os, json
PAT_TOKEN = settings.TOKEN

def create(repo_name, repo_login, repo_owner, pr_number, author, committer, commit_id, filepath, comment_position, owners, collaborators):
    """
    sends request for PR page comment to github api
    """
    pr_number = str(pr_number)
     
    url = os.path.join("https://api.github.com/repos", repo_login, repo_name, "pulls", pr_number, "comments",)
    headers = {
        "Authorization" : "token " + PAT_TOKEN
    }
    if owners != "":
        msg = committer + " committed on a restricted directory: " + filepath + " in the repository: " + repo_name + "belonging to " + repo_owner + "(" + repo_login + ")" + " authored by " + "@" + author + " in the file " + filepath + "\nCollaborators: " + collaborators
    else:
        msg = committer + " committed on a restricted directory: " + filepath + "in the repository: " + repo_name + " belonging to " + repo_owner + "(" + repo_login + ")" + " authored by " + "@" + author + " in the file " + filepath + "\nCollaborators: " + collaborators

    payload = {
        "body" : msg,
        "commit_id" : commit_id,
        "path" : filepath,
        "position" : comment_position
    }
    r = requests.post(url, headers= headers, data=json.dumps(payload))
    response = r.json()
    if response.has_key("message") == False:
        pass
    else:
        f = open("comment_api_response.log", "w+")
        f.write(json.dumps(r.json(), indent=4, separators=(',', ': ')))
        f.close()
        raise Exception("commenting failed: " + str(response.get("errors")))

    f = open("comment_api_response.log", "w+")
    f.write(json.dumps(r.json(), indent=4, separators=(',', ': ')))
    f.close()
