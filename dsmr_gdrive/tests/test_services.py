import tempfile
import os

from datetime import timedelta
from unittest import mock
from unittest.mock import Mock

from django.test import TestCase, override_settings
from django.utils import timezone

import dsmr_gdrive.services
from dsmr_backend.tests.mixins import InterceptStdoutMixin
from dsmr_backup.models.settings import GoogleDriveSettings
from dsmr_frontend.models.message import Notification
from dsmr_gdrive.gdrive.drive_api import CredentialsError, UploadError


class TestServices(InterceptStdoutMixin, TestCase):
    def setUp(self):
        GoogleDriveSettings.get_solo()
        GoogleDriveSettings.objects.all().update(client_id="FAKE")

    @mock.patch('dsmr_gdrive.gdrive.drive_api.Credentials')
    def test_sync_disabled(self, credentials_mock):
        GoogleDriveSettings.objects.all().update(client_id=None)

        self.assertFalse(credentials_mock.called)
        dsmr_gdrive.services.sync()
        self.assertFalse(credentials_mock.called)

    @mock.patch('dsmr_gdrive.services.make_request')
    @mock.patch('django.utils.timezone.now')
    def test_sync_init_setup(self, now_mock, make_request_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=0, next_sync=None)

        self.assertFalse(make_request_mock.called)
        dsmr_gdrive.services.sync()
        self.assertTrue(make_request_mock.called)

    @mock.patch('dsmr_gdrive.services.poll_server')
    @mock.patch('django.utils.timezone.now')
    def test_sync_init_polling(self, now_mock, poll_server_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=1, next_sync=None)
        self.assertFalse(poll_server_mock.called)
        dsmr_gdrive.services.sync()
        self.assertTrue(poll_server_mock.called)

    @mock.patch('dsmr_gdrive.services.setup_directory')
    @mock.patch('django.utils.timezone.now')
    def test_sync_init_directory_setup(self, now_mock, setup_directory_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=2, next_sync=None)
        self.assertFalse(setup_directory_mock.called)
        dsmr_gdrive.services.sync()
        self.assertTrue(setup_directory_mock.called)

    @mock.patch('dsmr_gdrive.services.gdrive_sync')
    @mock.patch('django.utils.timezone.now')
    def test_sync_gdrive_sync(self, now_mock, gdrive_sync_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)
        self.assertFalse(gdrive_sync_mock.called)
        dsmr_gdrive.services.sync()
        self.assertTrue(gdrive_sync_mock.called)

    @mock.patch('dsmr_gdrive.services.sync_file')
    @mock.patch('dsmr_gdrive.services.should_sync_file', return_value=True)
    @mock.patch('django.utils.timezone.now')
    def test_sync_should_sync(self, now_mock, should_sync_file_mock, sync_file_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)
        self.assertFalse(should_sync_file_mock.called)
        self.assertFalse(sync_file_mock.called)

        dsmr_gdrive.services.sync()
        should_sync_file_mock.return_value = True
        self.assertTrue(should_sync_file_mock.called)
        self.assertTrue(sync_file_mock.called)

    @mock.patch('dsmr_gdrive.services.sync_file')
    @mock.patch('dsmr_gdrive.services.should_sync_file', return_value=False)
    @mock.patch('django.utils.timezone.now')
    def test_sync_should_not_sync(self, now_mock, should_sync_file_mock, sync_file_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)
        self.assertFalse(should_sync_file_mock.called)
        self.assertFalse(sync_file_mock.called)

        dsmr_gdrive.services.sync()
        self.assertTrue(should_sync_file_mock.called)
        self.assertFalse(sync_file_mock.called)

    @mock.patch('dsmr_gdrive.services.sync_file')
    @mock.patch('dsmr_gdrive.services.should_sync_file', return_value=True)
    @mock.patch('django.utils.timezone.now')
    def test_sync_file_invalid_creds(self, now_mock, should_sync_file_mock, sync_file_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        sync_file_mock.side_effect = CredentialsError("An Error")

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)
        self.assertFalse(should_sync_file_mock.called)
        self.assertFalse(sync_file_mock.called)
        self.assertIsNotNone(GoogleDriveSettings.get_solo().client_id)

        dsmr_gdrive.services.sync()
        self.assertTrue(should_sync_file_mock.called)
        self.assertTrue(sync_file_mock.called)
        self.assertIsNone(GoogleDriveSettings.get_solo().client_id)

    @mock.patch('requests.post')
    @mock.patch('django.utils.timezone.now')
    def test_make_request(self, now_mock, request_post_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=0, next_sync=None, device_code=None)
        request_post_mock.return_value = Mock(status_code=200,
                                              json=lambda: {'device_code': 'TEST_DEVICE_CODE',
                                                            'user_code': 'TEST_USER_CODE',
                                                            'interval': 101,
                                                            'verification_url': 'TEST_VER_URL'})

        dsmr_gdrive.services.sync()

        self.assertEqual("TEST_DEVICE_CODE", GoogleDriveSettings.get_solo().device_code)
        self.assertEqual("TEST_USER_CODE", GoogleDriveSettings.get_solo().user_code)
        self.assertEqual(101, GoogleDriveSettings.get_solo().interval)
        self.assertEqual("TEST_VER_URL", GoogleDriveSettings.get_solo().authorization_url)

    @mock.patch('requests.post')
    @mock.patch('django.utils.timezone.now')
    def test_make_request_invalid(self, now_mock, request_post_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=0, next_sync=None,
                                                 device_code=None)
        request_post_mock.return_value = Mock(status_code=400,
                                              json=lambda: {'error': 'TEST_ERROR'})

        dsmr_gdrive.services.sync()

        self.assertEqual(0, GoogleDriveSettings.get_solo().state)
        self.assertEqual(None, GoogleDriveSettings.get_solo().client_id)

    @mock.patch('requests.post')
    @mock.patch('django.utils.timezone.now')
    def test_poll_server_pending(self, now_mock, request_post_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=1, next_sync=None)
        request_post_mock.return_value = Mock(status_code=400,
                                              json=lambda: {'error': 'authorization_pending'})
        dsmr_gdrive.services.sync()

        self.assertIsNotNone(GoogleDriveSettings.get_solo().client_id)

    @mock.patch('requests.post')
    @mock.patch('django.utils.timezone.now')
    def test_poll_server_error(self, now_mock, request_post_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=1, next_sync=None)
        request_post_mock.return_value = Mock(status_code=400,
                                              json=lambda: {'error': 'invalid_grant', 'error_description':'TEST_ERROR'})
        dsmr_gdrive.services.sync()

        self.assertIsNone(GoogleDriveSettings.get_solo().client_id)

    @mock.patch('requests.post')
    @mock.patch('django.utils.timezone.now')
    def test_poll_server_success(self, now_mock, request_post_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=1, next_sync=None)
        request_post_mock.return_value = Mock(status_code=200,
                                              json=lambda: {'access_token': 'ACCESS_TOKEN',
                                                            'refresh_token': 'REFRESH_TOKEN',
                                                            'expires_in': 5000})
        dsmr_gdrive.services.sync()

        self.assertIsNotNone(GoogleDriveSettings.get_solo().client_id)
        self.assertEqual('REFRESH_TOKEN', GoogleDriveSettings.get_solo().refresh_token)
        self.assertEqual('ACCESS_TOKEN', GoogleDriveSettings.get_solo().access_token)

    @mock.patch('requests.post')
    @mock.patch('django.utils.timezone.now')
    def test_poll_server_invalid_response(self, now_mock, request_post_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=1, next_sync=None)
        request_post_mock.return_value = Mock(status_code=400,
                                              json=lambda: {'TEST': 'invalid_grant',
                                                            'TESTER': 'TEST_SOMETHING'})
        dsmr_gdrive.services.sync()

        self.assertIsNone(GoogleDriveSettings.get_solo().client_id)



    def test_calculate_content_hash(self):
        result = dsmr_gdrive.services.calculate_content_hash(
            os.path.join(os.path.dirname(__file__), 'dummy.txt')
        )
        self.assertEqual(result, '2f5d040efe7a42620a617ee7a7feb6b9')
        pass

    @override_settings(DSMRREADER_GDRIVE_MAX_FILE_MODIFICATION_TIME=60)
    @mock.patch('time.time')
    @mock.patch('os.stat')
    def test_should_sync_file(self, stat_mock, time_mock):
        time_mock.return_value = 1500000100
        FILE = '/var/tmp/fake'

        # Skip empty file.
        stat_result = mock.MagicMock()
        stat_result.st_size = 0
        stat_result.st_mtime = 1500000000  # Start with 100s diff.
        stat_mock.return_value = stat_result

        self.assertFalse(dsmr_gdrive.services.should_sync_file(FILE))
        # Skip stale file.
        stat_result = mock.MagicMock()
        stat_result.st_size = 12345  # Not empty
        stat_result.st_mtime = 1500000000
        stat_mock.return_value = stat_result

        self.assertFalse(dsmr_gdrive.services.should_sync_file(FILE))

        # OK path.
        stat_result = mock.MagicMock()
        stat_result.st_size = 12345
        stat_result.st_mtime = 1500000090  # Within settings range (10s diff, 60s allowed)
        stat_mock.return_value = stat_result

        self.assertTrue(dsmr_gdrive.services.should_sync_file(FILE))

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.create_remote_folder')
    @mock.patch('django.utils.timezone.now')
    def test_setup_directory(self, now_mock, create_remote_folder_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=2, next_sync=None)
        create_remote_folder_mock.return_value = "SOME_ID"
        dsmr_gdrive.services.sync()

        self.assertEqual(3, GoogleDriveSettings.get_solo().state)
        self.assertEqual('SOME_ID', GoogleDriveSettings.get_solo().folder_id)
        self.assertIsNotNone(GoogleDriveSettings.get_solo().client_id)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.create_remote_folder')
    @mock.patch('django.utils.timezone.now')
    def test_setup_directory_invalid_creds(self, now_mock, create_remote_folder_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=2, next_sync=None)
        create_remote_folder_mock.side_effect = CredentialsError("An Error")
        dsmr_gdrive.services.sync()

        self.assertIsNone(GoogleDriveSettings.get_solo().client_id)
        self.assertEqual(0, GoogleDriveSettings.get_solo().state)

    def test_reset_state(self):
        GoogleDriveSettings.objects.all().update(client_id=None, client_secret="FAKE", state=2, next_sync=None)
        self.assertEqual(2, GoogleDriveSettings.get_solo().state)
        dsmr_gdrive.services.sync()
        self.assertEqual(0, GoogleDriveSettings.get_solo().state)

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret=None, state=2, next_sync=None)
        self.assertEqual(2, GoogleDriveSettings.get_solo().state)
        dsmr_gdrive.services.sync()
        self.assertEqual(0, GoogleDriveSettings.get_solo().state)

    def test_late_sync(self):
        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=2,
                                                 next_sync=timezone.now() + timedelta(hours=10))

        sync = GoogleDriveSettings.get_solo().latest_sync
        dsmr_gdrive.services.sync()
        self.assertEqual(sync, GoogleDriveSettings.get_solo().latest_sync)

    @mock.patch('django.utils.timezone.now')
    def test_update_credentials(self, now_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))
        tm = timezone.now()
        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=500,
                                                 access_token="TESTTEST", token_expiry=tm)

        dsmr_gdrive.services.sync()

        self.assertEqual('TESTTEST', GoogleDriveSettings.get_solo().access_token)
        self.assertEqual(tm, GoogleDriveSettings.get_solo().token_expiry)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.upload_file')
    @mock.patch('dsmr_gdrive.services.calculate_content_hash')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session_existing_file')
    @mock.patch('dsmr_backup.services.backup.get_backup_directory')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.get_file_meta')
    @mock.patch('django.utils.timezone.now')
    def test_sync_file_existing(self, now_mock, get_file_meta_mock, get_backup_directory_mock,
                                init_resumable_existing_mock, init_resumable_mock, calculate_content_hash_mock,
                                upload_file_mock
                                ):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)

        get_file_meta_mock.return_value = {'id': 'test_file_id', 'md5Checksum': 'SOME_HASH'}

        calculate_content_hash_mock.return_value = 'OTHER_HASH'
        init_resumable_existing_mock.return_value = "NOT NONE"
        init_resumable_mock.return_value = "NOT NONE"

        with tempfile.TemporaryDirectory() as temp_dir:
            get_backup_directory_mock.return_value = temp_dir
            temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, delete=False)
            temp_file.write(b'Meh.')
            temp_file.flush()

            self.assertFalse(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertFalse(upload_file_mock.called)

            dsmr_gdrive.services.sync()

            self.assertFalse(init_resumable_mock.called)
            self.assertTrue(init_resumable_existing_mock.called)
            self.assertTrue(upload_file_mock.called)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.upload_file')
    @mock.patch('dsmr_gdrive.services.calculate_content_hash')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session_existing_file')
    @mock.patch('dsmr_backup.services.backup.get_backup_directory')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.get_file_meta')
    @mock.patch('django.utils.timezone.now')
    def test_sync_file_new(self, now_mock, get_file_meta_mock, get_backup_directory_mock,
                                init_resumable_existing_mock, init_resumable_mock, calculate_content_hash_mock,
                                upload_file_mock
                                ):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)

        get_file_meta_mock.return_value = None

        calculate_content_hash_mock.return_value = 'OTHER_HASH'
        init_resumable_existing_mock.return_value = "NOT NONE"
        init_resumable_mock.return_value = "NOT NONE"

        with tempfile.TemporaryDirectory() as temp_dir:
            get_backup_directory_mock.return_value = temp_dir
            temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, delete=False)
            temp_file.write(b'Meh.')
            temp_file.flush()

            self.assertFalse(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertFalse(upload_file_mock.called)

            dsmr_gdrive.services.sync()

            self.assertTrue(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertTrue(upload_file_mock.called)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.upload_file')
    @mock.patch('dsmr_gdrive.services.calculate_content_hash')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session_existing_file')
    @mock.patch('dsmr_backup.services.backup.get_backup_directory')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.get_file_meta')
    @mock.patch('django.utils.timezone.now')
    def test_sync_file_failed_location(self, now_mock, get_file_meta_mock, get_backup_directory_mock,
                                       init_resumable_existing_mock, init_resumable_mock, calculate_content_hash_mock,
                                       upload_file_mock):

        Notification.objects.all().delete()
        self.assertEqual(Notification.objects.count(), 0)

        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))

        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)

        get_file_meta_mock.return_value = None

        calculate_content_hash_mock.return_value = None
        init_resumable_existing_mock.return_value = None
        init_resumable_mock.return_value = None

        with tempfile.TemporaryDirectory() as temp_dir:
            get_backup_directory_mock.return_value = temp_dir
            temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, delete=False)
            temp_file.write(b'Meh.')
            temp_file.flush()

            self.assertFalse(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertFalse(upload_file_mock.called)

            dsmr_gdrive.services.sync()

            self.assertTrue(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertFalse(upload_file_mock.called)
            self.assertEqual(Notification.objects.count(), 1)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.upload_file')
    @mock.patch('dsmr_gdrive.services.calculate_content_hash')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session_existing_file')
    @mock.patch('dsmr_backup.services.backup.get_backup_directory')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.get_file_meta')
    @mock.patch('django.utils.timezone.now')
    def test_sync_file_failed_upload_error(self, now_mock, get_file_meta_mock, get_backup_directory_mock,
                                       init_resumable_existing_mock, init_resumable_mock, calculate_content_hash_mock,
                                       upload_file_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))
        Notification.objects.all().delete()
        self.assertEqual(Notification.objects.count(), 0)
        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)

        get_file_meta_mock.return_value = None

        calculate_content_hash_mock.return_value = None
        init_resumable_existing_mock.return_value = 'SOME_LOCATION'
        init_resumable_mock.return_value = 'SOME_LOCATION'
        upload_file_mock.side_effect = UploadError("Some Error")

        with tempfile.TemporaryDirectory() as temp_dir:
            get_backup_directory_mock.return_value = temp_dir
            temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, delete=False)
            temp_file.write(b'Meh.')
            temp_file.flush()

            self.assertFalse(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertFalse(upload_file_mock.called)

            dsmr_gdrive.services.sync()

            self.assertTrue(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertTrue(upload_file_mock.called)
            self.assertEqual(Notification.objects.count(), 1)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.upload_file')
    @mock.patch('dsmr_gdrive.services.calculate_content_hash')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.init_resumable_upload_session_existing_file')
    @mock.patch('dsmr_backup.services.backup.get_backup_directory')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.get_file_meta')
    @mock.patch('django.utils.timezone.now')
    def test_sync_content_not_modified(self, now_mock, get_file_meta_mock, get_backup_directory_mock,
                                           init_resumable_existing_mock, init_resumable_mock,
                                           calculate_content_hash_mock,
                                           upload_file_mock):
        now_mock.return_value = timezone.make_aware(timezone.datetime(2016, 1, 1))
        GoogleDriveSettings.objects.all().update(client_id="FAKE", client_secret="FAKE", state=3, next_sync=None)

        get_file_meta_mock.return_value = {'id': 'test_file_id', 'md5Checksum': 'SOME_HASH'}

        calculate_content_hash_mock.return_value = "SOME_HASH"
        init_resumable_existing_mock.return_value = 'SOME_LOCATION'
        init_resumable_mock.return_value = 'SOME_LOCATION'
        upload_file_mock.side_effect = UploadError("Some Error")

        with tempfile.TemporaryDirectory() as temp_dir:
            get_backup_directory_mock.return_value = temp_dir
            temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, delete=False)
            temp_file.write(b'Meh.')
            temp_file.flush()

            self.assertFalse(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertFalse(upload_file_mock.called)

            dsmr_gdrive.services.sync()

            self.assertFalse(init_resumable_mock.called)
            self.assertFalse(init_resumable_existing_mock.called)
            self.assertFalse(upload_file_mock.called)

