import logging
from datetime import timedelta

import requests
from django.utils import timezone

logger = logging.getLogger('commands')


class Credentials:
    def __init__(self, client_id, client_secret, refresh_token, access_token, token_expiry):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.token_expiry = token_expiry

    @property
    def valid(self):
        """
        Check if a token is still valid using datetime comparison

        Note: this function only uses the time comparison to check if a token is valid. Revoked tokens are not checked
        in this function, as this is unlikely to happen on a regular bases
        :return: Boolean with token state
        """
        if self.token_expiry is None:
            return False

        if self.access_token is None:
            return False

        return self.token_expiry > timezone.now()

    def refresh(self):
        """
        Refresh access token
        :rtype: bool
        :return:
        """
        if self.client_id is None or self.client_secret is None or self.refresh_token is None:
            raise InvalidCredentialsError()

        params = {'client_id': self.client_id,
                  'client_secret': self.client_secret,
                  'refresh_token': self.refresh_token,
                  'grant_type': 'refresh_token'}

        r = requests.post('https://www.googleapis.com/oauth2/v4/token', params)

        data = r.json()

        if 'error' in data:
            if data['error'] == 'invalid_grant':
                raise InvalidTokenError(data['error_description'])
            if data['error'] == 'invalid_client':
                raise InvalidClientError(data['error_description'])
            raise RefreshError("Error when refreshing token")

        self.access_token = data['access_token']
        # Expire the token a little early as to avoid conflicts
        self.token_expiry = timezone.now() + timedelta(seconds=data['expires_in'] - 60)
        return


def execute_file_search(credentials, query, order_by=None, fields=None):
    """
    Execute file search

    Note: This function doesn't implement the specified "nextPageToken", it isn't needed for this project as
    100 files limit is well within reason

    :param credentials: credentials
    :param query: query
    :param order_by: how to order the files incoming
    :param fields: what fields to select
    :return: list of files, or None on failure
    """
    if not credentials.valid:
        credentials.refresh()

    # headers = {'Authorization': f'Bearer {credentials.access_token}'}
    headers = {'Authorization': f'Bearer {credentials.access_token}'}

    # Name Checking is oke for a first release, but ideally users would be able to change the name.
    # Not completely sure how to fix this at the moment, without also introducing several other issues
    # The google drive API isn't that clear on how to find files by ID, and it isn't a super important issue ATM
    params = {'q': query}

    if order_by is not None:
        params['orderBy'] = order_by
    if fields is not None:
        params['fields'] = fields

    r = requests.get(F'https://www.googleapis.com/drive/v3/files', headers=headers, params=params)

    data = r.json()

    if 'error' in data:
        logger.error('Error while checking file')
        raise FileError('Error while checking file')

    files = data['files']
    return files


class CredentialsError(Exception):
    pass


class InvalidCredentialsError(CredentialsError):
    pass


class InvalidTokenError(CredentialsError):
    pass


class InvalidClientError(CredentialsError):
    pass


class RefreshError(CredentialsError):
    pass


class FileError(Exception):
    pass
