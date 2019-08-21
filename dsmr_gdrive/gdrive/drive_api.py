import json
import logging
import os
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


class DriveService:
    def __init__(self, credentials):
        self.credentials = credentials

    def execute_file_search(self, query, order_by=None, fields=None):
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
        credentials = self.credentials

        if not credentials.valid:
            credentials.refresh()

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

    def get_file_meta(self, file_path, drive_root_id):
        credentials = self.credentials
        folders, file = split_path_into_file_and_folders(file_path)

        parent_id = drive_root_id
        for folder in folders:
            parent_id = check_if_folder_exists(folder, parent_id)
            if parent_id is None:
                return None

        query = f'name = \'{file}\' and trashed = false and \'{parent_id}\' in parents'
        order_by = 'modifiedTime desc'
        fields = 'files(md5Checksum,originalFilename,id)'

        files = execute_file_search(query, order_by, fields)

        if len(files) > 0:
            return files[0]
        return None

    def check_if_folder_exists(self, name, parent_id=None):
        credentials = self.credentials
        name = name.replace('_', '-')

        if parent_id is not None:
            query = f'name = \'{name}\' and trashed = false and mimeType = \'application/vnd.google-apps.folder\' ' \
                    f'and \'{parent_id}\' in parents'
        else:
            query = f'name = \'{name}\' and trashed = false and mimeType = \'application/vnd.google-apps.folder\''

        order_by = "modifiedTime desc"
        files = self.execute_file_search(credentials, query, order_by)

        if len(files) > 0:
            return files[0]['id']
        return None

    def create_remote_folder(self, directory_name, parent_id=None):
        credentials = self.credentials

        directory_name = directory_name.replace('_', '-')
        dir_id = self.check_if_folder_exists(credentials, directory_name)
        if dir_id is not None:
            logger.debug(f'Dir already exists ({dir_id})')
            return dir_id

        if not credentials.valid:
            credentials.refresh()

        # Thanks to https://stackoverflow.com/questions/54176209/create-new-folder-in-google-drive-with-rest-api
        headers = {'Authorization': f'Bearer {credentials.access_token}',
                   'Content-Type': 'application/json'}
        metadata = {'name': directory_name,
                    'mimeType': 'application/vnd.google-apps.folder'}

        if parent_id is not None:
            metadata['parents'] = [parent_id]

        r = requests.post('https://www.googleapis.com/drive/v3/files', headers=headers, data=json.dumps(metadata))
        data = r.json()

        if 'error' in data:
            return None
        return data['id']

    def create_remote_path(self, file_path, parent_id=None):
        folders, file = split_path_into_file_and_folders(file_path)

        for folder in folders:
            parent_id = self.create_remote_folder(folder, parent_id)
            if parent_id is None:
                return None

        return parent_id

    def init_resumable_upload_session_existing_file(self, abs_file_path, file_id):
        credentials = self.credentials

        if not credentials.valid:
            credentials.refresh()

        file_name = os.path.basename(abs_file_path)
        file_size = os.path.getsize(abs_file_path)

        headers = {'Authorization': f'Bearer {credentials.access_token}',
                   'Content-Type': 'application/json; charset=UTF-8',
                   'X-Upload-Content-Type': 'plain/txt',
                   'X-Upload-Content-Length': f'{file_size}'}

        params = {'name': file_name}
        url = f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=resumable"
        r = requests.patch(url, headers=headers, data=json.dumps(params))

        response_headers = r.headers
        if 'Location' not in response_headers:
            return None
        location = response_headers['Location']
        return location

    def init_resumable_upload_session(self, abs_file_path, remote_file_path, drive_root_id):
        credentials = self.credentials
        if not credentials.valid:
            credentials.refresh()

        folder_id = self.create_remote_path(remote_file_path, drive_root_id)
        if folder_id is None:
            return None

        file_name = os.path.basename(abs_file_path)
        file_size = os.path.getsize(abs_file_path)

        headers = {'Authorization': f'Bearer {credentials.access_token}',
                   'Content-Type': 'application/json; charset=UTF-8',
                   'X-Upload-Content-Type': 'plain/txt',
                   'X-Upload-Content-Length': f'{file_size}'}

        params = {'name': file_name, "parents": [folder_id]}
        url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable"
        r = requests.post(url, headers=headers, data=json.dumps(params))

        response_headers = r.headers
        if 'Location' not in response_headers:
            return None
        location = response_headers['Location']
        return location

    @staticmethod
    def upload_file(abs_file_path, location):
        file_size = os.path.getsize(abs_file_path)

        # chunk size should a multiple of 256 * 1024 (min chunk size is 256 * 1024 + 1)
        chunk_size = 256 * 1024 * 8
        bytes_confirmed_send = 0

        while bytes_confirmed_send != file_size:
            bytes_remaining = file_size - bytes_confirmed_send
            if bytes_remaining >= chunk_size:
                part_size = chunk_size
            else:
                part_size = bytes_remaining

            if os.path.exists(abs_file_path):
                with open(abs_file_path, 'rb') as f:
                    f.seek(bytes_confirmed_send)
                    data = f.read(part_size)
            else:
                logger.debug("File does not exist")
                raise UploadError("File does not exist")

            headers = {'Content-Length': f'{part_size}',
                       'Content-Range': f'bytes {bytes_confirmed_send}-{bytes_confirmed_send + part_size - 1}/{file_size}'}

            r = requests.put(location, headers=headers, data=data)

            response_headers = r.headers
            status_code = r.status_code

            if status_code == 308:
                if 'Range' in response_headers:
                    c_range = response_headers['Range']
                    c_range = c_range.split('-')[1]
                    bytes_confirmed_send = int(c_range)
                    logger.debug(f'{(bytes_confirmed_send/file_size)*100}% {abs_file_path}')
                else:
                    raise UploadError("No Range header found in response")
                pass
            elif status_code == 201 or status_code == 200:
                bytes_confirmed_send = file_size
                logger.debug(f'{(bytes_confirmed_send / file_size) * 100}% {abs_file_path}')
            else:
                raise UploadError("Error when uploading")

        return True

    @staticmethod
    def split_path_into_file_and_folders(file_path):
        path, file = os.path.split(file_path)

        folders = []
        while True:
            path, folder = os.path.split(path)
            if folder != "":
                folders.append(folder)
            else:
                break

        folders.reverse()
        return folders, file


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


class UploadError(Exception):
    pass
