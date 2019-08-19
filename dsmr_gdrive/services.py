import json
import logging
import os
import time
from datetime import timedelta
import hashlib

import requests
from django.utils import timezone


from django.utils.translation import ugettext_lazy as gettext

import dsmr_backup.services.backup
from dsmr_backup.models.settings import GoogleDriveSettings
from dsmr_frontend.models.message import Notification
from dsmr_gdrive.gdrive.Credentials import Credentials, CredentialsError, execute_file_search, FileError
from dsmrreader import settings

logger = logging.getLogger('commands')


def sync():
    gdrive_settings = GoogleDriveSettings.get_solo()

    if not gdrive_settings.client_id or not gdrive_settings.client_secret:
        # If drive settings does have a state but no client_id then reset state so other credentials can entered
        if gdrive_settings.state != 0:
            GoogleDriveSettings.objects.update(
                state=0
            )
        return

    if gdrive_settings.next_sync and gdrive_settings.next_sync > timezone.now():
        return

    if gdrive_settings.state == 0:
        make_request(gdrive_settings)

    elif gdrive_settings.state == 1:
        poll_server(gdrive_settings)

    elif gdrive_settings.state == 2:
        setup_directory(gdrive_settings)

    elif gdrive_settings.state == 3:
        gdrive_sync()
        print(calculate_content_hash("tests/small_file.txt"))
        creds = create_credentials(gdrive_settings)
        print(get_file_meta_data(creds, "small_file.txt", gdrive_settings.folder_id))


def should_sync_file(abs_file_path):
    """ Checks whether we should include this file for sync. """
    file_stat = os.stat(abs_file_path)

    # Ignore empty files.
    if file_stat.st_size == 0:
        logger.debug('Ignoring file: Zero Bytes: %s', abs_file_path)
        return False

    # Ignore file that haven't been updated in a while.
    seconds_since_last_modification = int(time.time() - file_stat.st_mtime)

    if seconds_since_last_modification > settings.DSMRREADER_GDRIVE_MAX_FILE_MODIFICATION_TIME:
        logger.debug(
            'Ignoring file: Time since last modification too high (%s secs): %s',
            seconds_since_last_modification,
            abs_file_path
        )
        return False

    return True


def gdrive_sync():
    backup_directory = dsmr_backup.services.backup.get_backup_directory()

    # Sync each file, recursively.
    for (root, _, filenames) in os.walk(backup_directory):
        for current_file in filenames:
            abs_file_path = os.path.abspath(os.path.join(root, current_file))

            if not should_sync_file(abs_file_path):
                continue

            # sync file

    # Try again in a while.
    GoogleDriveSettings.objects.update(
        latest_sync=timezone.now(),
        next_sync=timezone.now() + timezone.timedelta(
            hours=settings.DSMRREADER_GDRIVE_SYNC_INTERVAL
        )
    )
    pass


def sync_file(ab_file_path):

    pass


def calculate_content_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if len(chunk) == 0:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


# region Drive Access
def make_request(gdrive_settings):
    logger.debug("Making request to google oauth servers")
    scopes = ['https://www.googleapis.com/auth/drive.file']

    params = {'client_id': gdrive_settings.client_id,
              'scope': scopes}

    r = requests.post('https://accounts.google.com/o/oauth2/device/code', params, timeout=10)

    data = r.json()

    if r.status_code == 200:
        GoogleDriveSettings.objects.update(
            device_code=data['device_code'],
            user_code=data['user_code'],
            interval=data['interval'],
            authorization_url=data['verification_url'],
            next_sync=timezone.now() + timedelta(seconds=data['interval']),
            state=1
        )
    else:
        logger.error("Error when making request: " + data)
        Notification.objects.create(message=gettext(
            "[{}] Invalid credentials for google drive service. Credentials have been reset".format(
                timezone.now()
            )
        ))
        GoogleDriveSettings.objects.update(
            client_id=None,
            client_secret=None,
            state=0
        )
    return


def poll_server(gdrive_settings):
    params = {'client_id': gdrive_settings.client_id,
              'client_secret': gdrive_settings.client_secret,
              'code': gdrive_settings.device_code,
              'grant_type': 'http://oauth.net/grant_type/device/1.0'}

    r = requests.post('https://www.googleapis.com/oauth2/v4/token', params)

    data = r.json()
    status_code = r.status_code

    if status_code == 200:
        GoogleDriveSettings.objects.update(
            access_token=data['access_token'],
            refresh_token=data['refresh_token'],
            token_expiry=timezone.now() + timedelta(seconds=data['expires_in']),
            authorization_url="",
            user_code=None,
            state=2
        )
        return
    else:
        if 'error' in data:
            if data['error'] == 'authorization_pending':
                GoogleDriveSettings.objects.update(
                    next_sync=timezone.now() + timedelta(seconds=gdrive_settings.interval),
                )
                return
        logger.error(data)
        Notification.objects.create(message=gettext(
            "[{}] Error when polling google authorization servers. Error: {}. Credentials have been reset".format(
                timezone.now(),
                data['error_description']
            )
        ))
        GoogleDriveSettings.objects.update(
            client_id=None,
            authorization_url=None,
            user_code=None,
            state=0
        )
        return
# endregion


# region Drive File functions
def check_if_folder_exists(credentials, name):
    name = name.replace('_', '-')

    # Name Checking is oke for a first release, but ideally users would be able to change the name.
    # Not completely sure how to fix this at the moment, without also introducing several other issues
    # The google drive API isn't that clear on how to find files by ID, and it isn't a super important issue ATM
    query = f'name = \'{name}\' and trashed = false and mimeType = \'application/vnd.google-apps.folder\''
    order_by = "modifiedTime desc"
    files = execute_file_search(credentials, query, order_by)

    if len(files) > 0:
        return files[0]['id']
    return None


# def get_file_id(credentials, file_name, parent_id):
#     query = f'name = \'{file_name}\' and trashed = false and \'{parent_id}\' in parents'
#     order_by = 'modifiedTime desc'
#     files = execute_file_search(credentials, query, order_by)
#     if len(files) > 0:
#         return files[0]['id']
#     return None


def get_file_meta_data(credentials, file_name, parent_id):
    query = f'name = \'{file_name}\' and trashed = false and \'{parent_id}\' in parents'
    order_by = 'modifiedTime desc'
    fields = 'files(md5Checksum,originalFilename,id)'
    files = execute_file_search(credentials, query, order_by, fields)
    if len(files) > 0:
        return files[0]
    return None


def create_remote_dsmr_dir(credentials, directory_name):
    directory_name = directory_name.replace('_', '-')
    dir_id = check_if_folder_exists(credentials, directory_name)
    if dir_id is not None:
        logger.debug(f'Dir already exists ({dir_id})')
        return dir_id

    if not credentials.valid:
        credentials.refresh()

    # Thanks to https://stackoverflow.com/questions/40999982/create-folders-in-google-drive-with-rest-api-interface-and-
    # python-requests
    headers = {'Authorization': f'Bearer {credentials.access_token}',
               'Content-Type': 'application/json'}
    metadata = {'name': directory_name,
                'mimeType': 'application/vnd.google-apps.folder'}

    r = requests.post('https://www.googleapis.com/drive/v3/files', headers=headers, data=json.dumps(metadata))
    data = r.json()

    if 'error' in data:
        return None
    return data['id']
# endregion


def create_credentials(gdrive_settings):
    credentials = Credentials(gdrive_settings.client_id, gdrive_settings.client_secret, gdrive_settings.refresh_token,
                              gdrive_settings.access_token, gdrive_settings.token_expiry)
    return credentials


# region Drive Setup
def setup_directory(gdrive_settings):
    credentials = create_credentials(gdrive_settings)
    try:
        dir_id = create_remote_dsmr_dir(credentials, gdrive_settings.folder_name)

        GoogleDriveSettings.objects.update(
            folder_id=dir_id,
            state=3
        )

    except (CredentialsError, FileError) as err:
        Notification.objects.create(message=gettext(
            "[{}] Unable to create remote folder due to {}".format(
                timezone.now(),
                str(err)
            )
        ))
        GoogleDriveSettings.objects.update(
            client_id=None,
            state=0
        )
        return

    pass
# endregion

