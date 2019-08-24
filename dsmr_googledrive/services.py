import hashlib
import logging
import os
import time
from datetime import timedelta

import requests
from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as gettext

import dsmr_backup.services.backup
from dsmr_backup.models.settings import GoogleDriveSettings
from dsmr_frontend.models.message import Notification
from dsmr_googledrive.googledrive.drive_api import Credentials, DriveService, CredentialsError, UploadError, FileError
from dsmrreader import settings

logger = logging.getLogger('commands')


def sync():
    gdrive_settings = GoogleDriveSettings.get_solo()

    if not gdrive_settings.client_id or not gdrive_settings.client_secret:
        # If drive settings does have a state but no client_id then reset state so other credentials can entered
        if gdrive_settings.state != settings.DSMRREADER_GDRIVE_MAKE_ACCESS_REQUEST:
            GoogleDriveSettings.objects.update(
                state=settings.DSMRREADER_GDRIVE_MAKE_ACCESS_REQUEST
            )
        return

    if gdrive_settings.next_sync and gdrive_settings.next_sync > timezone.now():
        return

    credentials = Credentials(gdrive_settings.client_id, gdrive_settings.client_secret, gdrive_settings.refresh_token,
                              gdrive_settings.access_token, gdrive_settings.token_expiry)

    service = DriveService(credentials)

    if gdrive_settings.state == settings.DSMRREADER_GDRIVE_MAKE_ACCESS_REQUEST:
        make_request(gdrive_settings)

    elif gdrive_settings.state == settings.DSMRREADER_GDRIVE_POLL_SERVER:
        poll_server(gdrive_settings)

    elif gdrive_settings.state == settings.DSMRREADER_GDRIVE_SETUP_FOLDERS:
        setup_directory(service, gdrive_settings)

    elif gdrive_settings.state == settings.DSMRREADER_GDRIVE_SYNC_FILES:
        gdrive_sync(service, gdrive_settings)

    if credentials.access_token is not None and credentials.token_expiry is not None:
        GoogleDriveSettings.objects.update(
            access_token=credentials.access_token,
            token_expiry=credentials.token_expiry
        )

    # Try again in a while.
    GoogleDriveSettings.objects.update(
        latest_sync=timezone.now(),
        next_sync=timezone.now() + timezone.timedelta(
            hours=settings.DSMRREADER_GDRIVE_SYNC_INTERVAL
        )
    )


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


def gdrive_sync(service, gdrive_settings):
    backup_directory = dsmr_backup.services.backup.get_backup_directory()

    # Sync each file, recursively.
    for (root, _, filenames) in os.walk(backup_directory):
        for current_file in filenames:
            abs_file_path = os.path.abspath(os.path.join(root, current_file))

            if not should_sync_file(abs_file_path):
                continue
            try:
                sync_file(gdrive_settings, service, backup_directory, abs_file_path)
            except CredentialsError:
                Notification.objects.create(message=gettext(
                    "[{}] Invalid Credentials for Google Drive. Removing credentials...".format(
                        timezone.now(),
                    )
                ))
                GoogleDriveSettings.objects.update(
                    latest_sync=timezone.now(),
                    next_sync=None,
                    client_id=None,
                    state=settings.DSMRREADER_GDRIVE_MAKE_ACCESS_REQUEST
                )


def sync_file(gdrive_settings, service, local_root_dir, abs_file_path):
    relative_file_path = abs_file_path.replace(local_root_dir, '')
    drive_root_id = gdrive_settings.folder_id

    gdrive_file_meta = service.get_file_meta(relative_file_path, drive_root_id)

    if gdrive_file_meta and calculate_content_hash(abs_file_path) == gdrive_file_meta['md5Checksum']:
        return logger.debug(' - Google Drive content hash is the same, skipping: %s', relative_file_path)

    # Upload
    if gdrive_file_meta is not None:
        location = service.init_resumable_upload_session_existing_file(abs_file_path, gdrive_file_meta['id'])
    else:
        location = service.init_resumable_upload_session(abs_file_path, relative_file_path, drive_root_id)

    error = False
    try:
        if location is not None:
            service.upload_file(abs_file_path, location)
        else:
            error = True
    except UploadError:
        error = True

    if error:
        Notification.objects.create(message=gettext(
            "[{}] Unable to upload files to Google Drive. "
            "Ignoring new files for the next {} hours...".format(
                timezone.now(),
                settings.DSMRREADER_GDRIVE_ERROR_INTERVAL
            )
        ))
        GoogleDriveSettings.objects.update(
            latest_sync=timezone.now(),
            next_sync=timezone.now() + timezone.timedelta(hours=settings.DSMRREADER_GDRIVE_ERROR_INTERVAL)
        )


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
            state=settings.DSMRREADER_GDRIVE_POLL_SERVER
        )
    else:
        logger.error("Error when making request")
        Notification.objects.create(message=gettext(
            "[{}] Invalid credentials for google drive service. Credentials have been reset".format(
                timezone.now()
            )
        ))
        GoogleDriveSettings.objects.update(
            client_id=None,
            state=settings.DSMRREADER_GDRIVE_MAKE_ACCESS_REQUEST
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
            state=settings.DSMRREADER_GDRIVE_SETUP_FOLDERS
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
            "[{}] Error when polling google authorization servers. Credentials have been reset".format(
                timezone.now(),
            )
        ))
        GoogleDriveSettings.objects.update(
            client_id=None,
            authorization_url=None,
            user_code=None,
            state=settings.DSMRREADER_GDRIVE_MAKE_ACCESS_REQUEST
        )
        return


# endregion


# region Drive Setup
def setup_directory(service, gdrive_settings):
    try:
        dir_id = service.create_remote_folder(gdrive_settings.folder_name)

        GoogleDriveSettings.objects.update(
            folder_id=dir_id,
            state=settings.DSMRREADER_GDRIVE_SYNC_FILES
        )

    except (CredentialsError, FileError) as err:
        Notification.objects.create(message=gettext(
            "[{}] Unable to create remote folder due to {}. Removing Credentials".format(
                timezone.now(),
                str(err)
            )
        ))
        GoogleDriveSettings.objects.update(
            latest_sync=timezone.now(),
            next_sync=None,
            client_id=None,
            state=settings.DSMRREADER_GDRIVE_MAKE_ACCESS_REQUEST
        )
        return
# endregion
