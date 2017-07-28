#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Acronyms:
    - mcs : mission critical settings

WARNINGS:
    - If the file name edited in a commit has the same name as a restricted directory, that
    commit will be commented.
    - If a webhook is redelivered from the admin, duplicate comments are created
    on the PR page.
    - If an owners.txt file is added, that file should be included in the top level directory.

Comment on PR page must contain the following details:
    - Who created the PR
    - Where in the file changes were made
"""
# TODO: extend support for regex on filepaths
from django.http import HttpResponse
# from django.http import HttpRequest
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

import sys, os
import thread
import traceback
import requests
import hashlib, hmac
import json
import base64


import create_comment_on_PR as createComment
import send_status_on_PR as sendStatus

# ------------------------------------configs and secrets--------------------------------
import mcs_config
import webhook_secret
import pat_token

# RETURN_MSG = "Meliora cogito #DBL"
PAT_TOKEN = pat_token.TOKEN
RETURN_MSG = "auf weidersehen"
DIR_ITEM_SET = set(mcs_config.DIRS)
OWNER_FILE_NAME = "CODEOWNERS"
# WARNING: the regex matching portion of the method to check for code owners is buggy. Please
# review and edit it before toggling INTIMATE_OWNERS
INTIMATE_OWNERS = False


def index(request):
    return HttpResponse("Hi, welcome to the PR_Regulation. If you were looking for something here,"
                        " i am  afraid there is nothing...")


def attempt_to_get_owner_file(repo_login, repo_name, filepath, branch):
    """
    attempt to find the CODEOWNERS file from the top level directory. assuming that the top level
    directory is the directory to where we are required to check for owner.txt

    - WARNING: Note that the contents of the file are encoded in base64 format so it is essential
    to decode it. If the format of encoding is something else then it will raise an error

    :param filepath: filepath to the edited file in a corresponding commit
    :return:
    """
    import re
    owner_filepath = ""
    reviewers = ""

    owner_filepath = os.path.join(OWNER_FILE_NAME)

    parameters = "?ref=" + branch
    url = os.path.join("https://api.github.com", "repos", repo_login, repo_name, "contents", owner_filepath)
    url += parameters
    r = requests.get(url)
    response = r.json()
    try:
        if response["message"] == "Not Found":
            return -1
    except KeyError:
        if response["encoding"] != "base64":
            raise Exception("encoding in response was not base64")

        content = response["content"]
        decoded_content = base64.b64decode(content)
        decoded_content = decoded_content.split('\n')
        for line in decoded_content:
            if line[0] == "#":
                continue
            line = line.split('\t')
            filepath_regex = line[0]
            if re.match(filepath_regex, filepath): # this line is buggy
                reviewers_list = line[1]
                reviewers = reviewers_list.replace(' ', ',')

        return reviewers


def get_collabortors(payload):
    """
    gets the collaborators of the base repository

    :param payload:
    :return:
    """
    collaborators = ""
    collaborator_url = os.path.join(payload["pull_request"]["base"]["repo"]["url"],
                                    "collaborators")
    headers = {
        "Authorization": "token " + PAT_TOKEN
    }
    r = requests.get(collaborator_url, headers = headers)
    response  = r.json()
    for collaborator in response:
        print collaborator
        collaborators += '@'+ collaborator["login"] + ", "
    return collaborators



def get_base_branch(payload):
    """
    gets the ref of the base branch.

    :param payload: payload from webhook
    :return:
    """
    return payload["pull_request"]["base"]["ref"]


def get_author(commit):
    """
    gets the author name of the commit

    :param commit: the commmit in the form of a dict
    :return: author name
    """
    return commit["commit"]["author"]["name"]


def get_committer(commit):
    """
    gets username of committer

    :param commit: commit dict
    :return: username of committer
    """
    return commit["commit"]["committer"]["name"]


def get_head_branch(payload):
    """
    gets the branch where the head is

    :param payload: payload from webhook
    :return: return the branch
    """
    return payload["pull_request"]["head"]["ref"]


def get_repo_owner(payload):
    """
    gets the repo owner

    :param payload: payload from webhook
    :return: return tuple of login and name of repo owner
    """
    r = requests.get(payload["repository"]["owner"]["url"])
    # print r.json()
    return r.json()["login"], r.json()["name"]


def get_repo_name(payload):
    """
    gets the repo name

    :param payload: payload from webhook
    :return: repo owner
    """
    return payload["repository"]["name"]


def get_PR_number(payload):
    """
    get the PR number. The pull request number is one of the keys payload dictionary itself

    :param payload: payload from the webhook
    :return: repo owner
    """
    return payload["number"]


def get_commits(payload):
    """
    gets all commits for a particular pull request

    :param payload: payload from the webhook
    :return:list of all commits for that particular PR
    """
    r = requests.get(payload["pull_request"]["commits_url"])
    # r.json() will be a list of all commits
    commits = r.json()
    return commits


def get_commit_id(commit):
    """
    Gets the commit ids of the PR

    :param commit: payload from the webhook
    :return: commit hash list
    """
    return commit["sha"]


def get_files_changed(commit):
    """
    Gets the files changed for a commit

    :param commit: commit
    :return: list of files changed
    """
    r = requests.get(commit["url"])
    files_changed = r.json()["files"]
    return files_changed


def get_file_path(file):
    """
    gets the file path for a given file

    :param file: dictionary of file details
    :return: file path
    """
    return file["filename"]


def get_position_to_comment(file):
    """
    gets line number to comment. Note that here we are only interested in getting the post image
    line number of the git diff.

    :param file: payload from the webhook
    :return: line number
        """
    patch = file["patch"]
    patch = patch.split('@@')
    patch = patch[1].split(' ')
    preimage = patch[1]
    postimage = patch[2]
    # preimage_start_line = preimage.split(',')[0]
    postimage_start_line = postimage.split(',')[0]
    num_of_lines = 0
    if len(postimage.split(',')) == 1:
        # it means that number of lines edited is not on the diff
        return int(postimage_start_line)
    else:
        num_of_lines = int(postimage.split(',')[1])
        print num_of_lines

    return int(postimage_start_line) + num_of_lines - 1


def get_head_sha_hash(payload):
    """
    gets the head sha hash

    :param payload: payload from webhook
    :return: line number
    """
    return payload["pull_request"]["head"]["sha"]


def process_payload(thread_name, parsed_json, logging_file):
    """
    process the json payload

    :param thread_name: dummy
    :param parsed_json:
    :return:
    """
    # DEBUG: logging
    logging_file.write(str(parsed_json))

    # initializations
    owners = ""
    owners_in_dir = []
    repo_name = ""
    repo_login = ""
    pr_head_branch = ""
    repo_owner = ""
    head_sha_hash = ""
    try:
        repo_name = get_repo_name(parsed_json)

        if repo_name not in mcs_config.REPO_NAMES:
            return RETURN_MSG

        pr_head_branch = get_head_branch(parsed_json)
        pr_base_branch = get_base_branch(parsed_json)

        if pr_head_branch not in mcs_config.BRANCHES:
            return RETURN_MSG

        repo_login, repo_owner = get_repo_owner(parsed_json)
        head_sha_hash = get_head_sha_hash(parsed_json)
        # intimating that a check is already on the way
        sendStatus.send(-1, repo_login=repo_login, repo_name=repo_name,
                        head_sha_hash=head_sha_hash, stat_string="pending")

        pr_number = get_PR_number(parsed_json)
        collaborators = get_collabortors(parsed_json)

        # print head_sha_hash + "," + repo_login + "," + repo_owner + "," + pr_number
        # now there will be a check on the commits in and if in any commit a file
        # change is found that is in the list of possible file changes then comment on
        # those changes

        commits = get_commits(parsed_json)
        for commit in commits:
            # print "current_commit: "+commit
            committer = get_committer(commit)
            author = get_author(commit)
            commit_id = get_commit_id(commit)
            files = get_files_changed(commit)
            for file in files:



                filepath = get_file_path(file)

                print filepath

                dir_items = set(filepath.split('/'))

                print dir_items.intersection(DIR_ITEM_SET)

                if dir_items.intersection(DIR_ITEM_SET):
                    # this is the crucial check to confirm that we are checking in the
                    # same directory that is configured

                    # WARNING: fails if the directory name is also a file name that is edited
                    if INTIMATE_OWNERS == True and dir_items not in owners_in_dir:
                        # optimization to prevent api calls to get contents of
                        # owners file for each and every filepath
                        owners_in_dir.append(dir_items)
                        r = attempt_to_get_owner_file(repo_login, repo_name, filepath,
                                                      pr_base_branch)
                        if r == -1:
                            # it means the filepath has only one file or the owners.txt file
                            # does not exist
                            pass
                        else:
                            owners = r

                    comment_position = get_position_to_comment(file)
                    createComment.create(
                        repo_name, repo_login, repo_owner, pr_number, author, committer,\
                        commit_id, filepath, comment_position, owners, collaborators)

        sendStatus.send(0, repo_login, repo_name, head_sha_hash, "success")
        logging_file.close()
        print "success"

    except Exception:
        # sending non-zero exit code for failure
        exc_type, exc_val, exc_tb = sys.exc_info()
        sendStatus.send(1, repo_login, repo_name, head_sha_hash, traceback.print_exception(exc_type, exc_val, exc_tb))


def authenticate(body, hash):
    # print "{} and {}".format(body, hash)
    secret = webhook_secret.SECRET
    # github uses both the secret and the payload to authenticate
    h = hmac.new(secret, body, hashlib.sha1)
    password = h.hexdigest()
    password = "sha1=" + password
    if password == hash:
        return True
    else:
        return False


@csrf_exempt
def github_webhook_handler(request):
    if request.method != "POST":
        return HttpResponse("Go to hell!!!")

    headers = request.META

    if request.content_type == "application/json":
        print "request is json"
        parsed_json = json.loads(request.body)
        # print "json_parsed"
        # print "headers: {}".format(headers)
        try:
            if not authenticate(str(request.body), headers.get("HTTP_X_HUB_SIGNATURE")):
                return HttpResponse("Go to hell!!!")
            if headers.get("HTTP_X_GITHUB_EVENT") != "pull_request":
                return HttpResponse("Not a pr")
        except Exception:
            exc_type, exc_val, exc_tb = sys.exc_info()
            traceback.print_exception(exc_type, exc_val, exc_tb)
            return HttpResponse("Secret not defined...")
        # start a new thread for processing json so that webhook does not timeout.
        f = open("payload_log.log", "w+")
        thread.start_new_thread(process_payload, ("payload_thread", parsed_json, f))
    else:
        print "request is not json"
        return HttpResponse("request was not json, please configure the payload as json")

    return HttpResponse(RETURN_MSG)

