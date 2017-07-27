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

Comment on PR page must contain the following details:
    - Who created the PR
    - Where in the file changes were made
"""
# TODO: extend support for regex on filepaths
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods


import sys
import thread
import traceback
import requests
import hashlib, hmac


import create_comment_on_PR as createComment
import send_status_on_PR as sendStatus

# ------------------------------------configs and secrets--------------------------
import mcs_config
import webhook_secret

# RETURN_MSG = "Meliora cogito #DBL"
RETURN_MSG = "auf weidersehen"
DIR_ITEM_SET = set(mcs_config.DIRS)


@require_http_methods(["GET"])
def index(request):
    return HttpResponse("Hi, welcome to the PR_Regulation. If you were looking for something here,"
                        " i am  afraid there is nothing...")



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
    return (r.json()["login"], r.json()["name"])


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

    :param payload: payload from the webhook
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

    :param payload: payload from the webhook
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

    return int(postimage_start_line) + num_of_lines


def get_head_sha_hash(payload):
    """
    gets the head sha hash

    :param payload: payload from webhook
    :return: line number
    """
    return payload["pull_request"]["head"]["sha"]


def process_payload(thread_name, parsed_json):
    """
    process the json payload

    :param thread_name: dummy
    :param parsed_json:
    :return:
    """

    try:
        repo_name = get_repo_name(parsed_json)

        if repo_name not in mcs_config.REPO_NAMES:
            return RETURN_MSG

        pr_head_branch = get_head_branch(parsed_json)

        if pr_head_branch not in mcs_config.BRANCHES:
            return RETURN_MSG

        repo_login, repo_owner = get_repo_owner(parsed_json)
        head_sha_hash = get_head_sha_hash(parsed_json)
        # intimating that a check is already on the way
        sendStatus.send(-1, repo_login=repo_login, repo_name=repo_name, \
                        head_sha_hash=head_sha_hash, stat_string="pending")

        pr_number = get_PR_number(parsed_json)

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

                dir_items = set(filepath.split('/'))

                if dir_items.intersection(DIR_ITEM_SET):
                    # this is the crucial check to confirm that we are checking in the
                    # same directory that is configured

                    # WARNING: fails if the directory name is also a file name that is edited

                    comment_position = get_position_to_comment(file)
                    createComment.create(
                        repo_name, repo_login, repo_owner, pr_number, author, committer,\
                        commit_id, filepath, comment_position)

        sendStatus.send(0, repo_login, repo_name, head_sha_hash, "success")

    except Exception:
        # sending non-zero exit code for failure
        exc_type, exc_val, exc_tb = sys.exc_info()
        sendStatus.send(1, repo_login, repo_name, head_sha_hash, traceback.print_exception(exc_type, exc_val, exc_tb))


def authenticate(body, hash):
    secret = webhook_secret.SECRET
    # github uses both the secret and the payload to authenticate
    h = hmac.new(secret, body, hashlib.sha1)
    password = h.hexdigest()
    password = "sha1=" + password
    if password == hash:
        return True
    else:
        return False


@require_http_methods(["POST"])
def github_webhook_handler(request):

    if request.is_json:
        print "request is json"
        parsed_json = request.json
        try:
            if not authenticate(request.data, request.headers.get("X-Hub-Signature")):
                return "Go to hell!!!"
            if request.headers["X-Github-Event"] != "pull_request":
                return "Not a pr"
        except Exception:
            return "Secret not defined..."
        # start a new thread for processing json so that webhook does not timeout.
        thread.start_new_thread(process_payload, ("payload_thread", parsed_json))

    else:
        print "request is not json"
        return "request was not json, please configure the payload as json"

    return RETURN_MSG

