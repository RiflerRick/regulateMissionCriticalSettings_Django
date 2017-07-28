"""
creates a comment on PR page
"""
import pat_token
import requests
import os
import json
PAT_TOKEN = pat_token.TOKEN

def create(repo_name, repo_login, repo_owner, pr_number, author, committer, commit_id, filepath, comment_position, owners, collaborators):
    """
    sends request for PR page comment to github api
    """

    # DEBUG statements
    # print "repo owner: "+repo_owner
    # print "repo name: "+repo_name
    # print "pr_number:" +pr_number
    # print "committer: "+committer
    # print "repo_login:" +repo_login
    # print "filepath: "+filepath
    # print "comment_position: "+str(comment_position)
    pr_number = str(pr_number)
     
    url = os.path.join("https://api.github.com/repos", repo_login, repo_name, "pulls", pr_number, "comments",)
    headers = {
        "Authorization" : "token " + PAT_TOKEN
    }
    if owners != "":
        msg = committer + " committed on a restricted directory: " + filepath + " in the repository: " + repo_name + "belonging to " + repo_owner + "(" + repo_login + ")" + " authored by " + "@" + author + " in the file " + filepath + "\nOwners: " + "@" + owners + "\nCollaborators: " + collaborators
    else:
        msg = committer + " committed on a restricted directory: " + filepath + "in the repository: " + repo_name + " belonging to " + repo_owner + "(" + repo_login + ")" + " authored by " + "@" + author + " in the file " + filepath + "\nOwners: no owner file found\n Collaborators: " + collaborators

    payload = {
        "body" : msg,
        "commit_id" : commit_id,
        "path" : filepath,
        "position" : comment_position
    }
    print "url: " + url
    print "payload: "
    print payload
    r = requests.post(url, headers= headers, data=json.dumps(payload))
    response = r.json()
    if response.has_key("message") == False:
        pass
    else:
        f = open("comment_api_response.log", "w+")
        f.write(json.dumps(r.json(), indent=4, separators=(',', ': ')))
        f.close()
        raise Exception("commenting failed: " + str(response.get("errors")))
    # print json.dumps(r.json(), indent=4, separators=(',', ': '))
    f = open("comment_api_response.log", "w+")
    f.write(json.dumps(r.json(), indent=4, separators=(',', ': ')))
    f.close()
