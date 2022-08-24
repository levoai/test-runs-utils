#
#  Copyright ©2022. Levo.ai Inc. All Rights Reserved.
#  You may not copy, reproduce, distribute, publish, display, perform, modify, create derivative works, transmit,
#  or in any way exploit any such software/code, nor may you distribute any part of this software/code over any network,
#  including a local area network, sell or offer it for commercial purposes.
#

import os
import sys

import requests

DAF_AUDIENCE = os.getenv("LEVO_DAF_AUDIENCE", "https://api.levo.ai")
DAF_DOMAIN = os.getenv("LEVO_DAF_DOMAIN", "https://levoai.us.auth0.com")
DAF_CLIENT_ID = os.getenv("LEVO_DAF_CLIENT_ID", "aa9hJp2bddyhZeEXjAsura6bWIdSEr5s")


def _refresh_get_access_token(refresh_token: str) -> dict:
    """Refresh the API access token with the given refresh token."""
    headers = {"content-type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "refresh_token",
        "client_id": DAF_CLIENT_ID,
        "refresh_token": refresh_token,
        "audience": DAF_AUDIENCE,
    }

    response = requests.post(
        DAF_DOMAIN + "/oauth/token", headers=headers, data=data
    )
    response.raise_for_status()
    resp_json = response.json()

    if (response.status_code != 200) or not len(resp_json):
        print(f"Failed to retrieve token with status {response.status_code}")

    return dict(resp_json)["access_token"]


if __name__ == "__main__":
    org_refresh_token = sys.argv[1]
    if org_refresh_token:
        auth_token = _refresh_get_access_token(org_refresh_token)
        print(f"{auth_token}")
