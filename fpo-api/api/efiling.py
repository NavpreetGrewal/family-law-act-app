import logging
from pathlib import Path
import json
import base64
from io import BytesIO
import requests
from requests.auth import HTTPBasicAuth
from django.conf import settings
LOGGER = logging.getLogger(__name__)


def get_efiling_auth_token() -> {}:
    client_id = settings.EFILING_CLIENT_ID
    client_secret = settings.EFILING_CLIENT_SECRET
    url = settings.EFILING_AUTH_URL
    if not client_id:
        LOGGER.error("eFiling service client id is not configured")
        return
    if not client_secret:
        LOGGER.error("eFiling service client secret is not configured")
        return
    if not url:
        LOGGER.error("eFiling authentication url is not configured")
        return
    payload = {"grant_type": "client_credentials"}
    header = {"content-type": "application/x-www-form-urlencoded"}
    try:
        token_rs = requests.post(url, data=payload, auth=HTTPBasicAuth(client_id, client_secret), headers=header, verify=True)
        if not token_rs.status_code == 200:
            LOGGER.error("Error: Unexpected response %s", token_rs.text.encode('utf8'))
            return
        json_obj = token_rs.json()
        return json_obj
    except requests.exceptions.RequestException as e:
        LOGGER.error("Error: {}".format(e))
        return


def upload_documents(files: any, user_id: str, transaction_id: str) -> {}:
    base_url = settings.EFILING_BASE_URL

    if not base_url:
        LOGGER.error("eFiling base url not configured")
        return

    # Get the keycloak token and check if it's not empty
    token = get_efiling_auth_token()
    if not token or 'access_token' not in token:
        LOGGER.error("No efiling auth token provided %s", token)
        return
    auth_token = token['access_token']

    url = base_url + "documents"

    headers = {"Authorization": 'Bearer ' + auth_token,
               "contect-type": "multipart/form-data",
               "X-Transaction-Id": transaction_id,
               "X-User-Id": user_id}
    try:
        response = requests.post(url, data={}, headers=headers, files=files, verify=True)
        if not response.status_code // 100 == 2:
            LOGGER.error("Error: Document upload failed! %s", response.text.encode('utf8'))
            return

        upload_res = response.json()
        LOGGER.debug("Document upload complete! %s", upload_res)
        return upload_res
    except requests.exceptions.RequestException as e:
        LOGGER.error("Error: {}".format(e))
        return


def generate_efiling_url(data: any, user_id: str, transaction_id: str, submission_id: str) -> {}:
    base_url = settings.EFILING_BASE_URL

    if not base_url:
        LOGGER.error("eFiling base url not configured")
        return
    if not submission_id:
        LOGGER.error("Submission Id not provided")
        return
    if not user_id:
        LOGGER.error("User Id not provided")
        return
    if not transaction_id:
        LOGGER.error("Transaction Id not provided")
        return

    # Get the keycloak token and check if it's not empty
    token = get_efiling_auth_token()
    if not token or 'access_token' not in token:
        LOGGER.error("No efiling auth token provided %s", token)
        return
    auth_token = token['access_token']

    url = base_url + submission_id + "/generateUrl"
    headers = {"Authorization": 'Bearer ' + auth_token,
               "Content-Type": "application/json",
               "X-Transaction-Id": transaction_id,
               "X-User-Id": user_id
               }
    try:
        response = requests.post(url, data=json.dumps(data), headers=headers, verify=True)
        if not response.status_code // 100 == 2:
            LOGGER.error("Error: Generation of efilingURL failed! %s", response.text.encode('utf8'))
            return

        gene_res = response.json()
        LOGGER.debug("Efiling URL recieved! %s", gene_res)
        return gene_res
    except requests.exceptions.RequestException as e:
        LOGGER.error("Error: {}".format(e))
        return
      