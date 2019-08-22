import os
import tempfile
from datetime import timedelta
from unittest import mock
from unittest.mock import Mock

from django.test import TestCase
from django.utils import timezone

from dsmr_backend.tests.mixins import InterceptStdoutMixin
from dsmr_gdrive.gdrive.drive_api import DriveService, FileError, Credentials, InvalidCredentialsError, \
    InvalidClientError, InvalidTokenError, RefreshError, UploadError


class TestDriveAPI(InterceptStdoutMixin, TestCase):
    def setUp(self):
        pass

    def test_credentials_valid_no_expiry(self):
        credentials = Credentials('ID', 'SECRET', 'REFRESH', 'ACCESS_TOKEN', None)
        self.assertFalse(credentials.valid)

    def test_credentials_valid_no_token(self):
        credentials = Credentials('ID', 'SECRET', 'REFRESH', None, 150)
        self.assertFalse(credentials.valid)

    def test_credentials_valid(self):
        credentials = Credentials('ID', 'SECRET', 'REFRESH', 'ACCESS_TOKEN', timezone.now() + timedelta(hours=1))
        self.assertTrue(credentials.valid)

    def test_credentials_invalid(self):
        credentials = Credentials('ID', 'SECRET', 'REFRESH', 'ACCESS_TOKEN', timezone.now() - timedelta(hours=1))
        self.assertFalse(credentials.valid)

    @mock.patch('requests.post')
    def test_credentials_refresh(self, request_mock):
        credentials = Credentials('CLIENT_ID', 'SECRET', 'REFRESH', 'ACCESS_TOKEN', 150)
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'access_token': 'SOME_NEW_TOKEN', 'expires_in': 0})

        credentials.refresh()
        self.assertEqual('SOME_NEW_TOKEN', credentials.access_token)

    def test_credentials_missing_data(self):
        credentials = Credentials(None, 'SECRET', 'REFRESH', 'ACCESS_TOKEN', 150)
        with self.assertRaises(InvalidCredentialsError):
            credentials.refresh()

        credentials = Credentials('CLIENT_ID', None, 'REFRESH', 'ACCESS_TOKEN', 150)
        with self.assertRaises(InvalidCredentialsError):
            credentials.refresh()

        credentials = Credentials('CLIENT_ID', 'SECRET', None, 'ACCESS_TOKEN', 150)
        with self.assertRaises(InvalidCredentialsError):
            credentials.refresh()
        pass

    @mock.patch('requests.post')
    def test_credentials_invalid_client(self, request_mock):
        credentials = Credentials('CLIENT_ID', 'SECRET', 'REFRESH', 'ACCESS_TOKEN', 150)
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'error': 'invalid_client', 'error_description': 'test'})

        with self.assertRaises(InvalidClientError):
            credentials.refresh()

    @mock.patch('requests.post')
    def test_credentials_invalid_grant(self, request_mock):
        credentials = Credentials('CLIENT_ID', 'SECRET', 'REFRESH', 'ACCESS_TOKEN', 150)
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'error': 'invalid_grant', 'error_description': 'test'})

        with self.assertRaises(InvalidTokenError):
            credentials.refresh()

    @mock.patch('requests.post')
    def test_credentials_error(self, request_mock):
        credentials = Credentials('CLIENT_ID', 'SECRET', 'REFRESH', 'ACCESS_TOKEN', 150)
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'error': 'some_other_error', 'error_description': 'test'})

        with self.assertRaises(RefreshError):
            credentials.refresh()

    @mock.patch('requests.get')
    def test_execute_file_search(self, request_get_mock):
        request_get_mock.return_value = Mock(status_code=200,
                                             json=lambda: {'files': 'TEST_RESPONSE'})
        credentials_mock = Mock(valid=True, refresh='TEST')
        service = DriveService(credentials_mock)
        result = service.execute_file_search('name = \'TEST\'')
        self.assertEqual('TEST_RESPONSE', result)

    @mock.patch('requests.get')
    def test_execute_file_search_refresh_creds(self, request_get_mock):
        request_get_mock.return_value = Mock(status_code=200,
                                             json=lambda: {'files': 'TEST_RESPONSE'})
        credentials_mock = Mock(valid=False)
        service = DriveService(credentials_mock)
        self.assertFalse(credentials_mock.refresh.called)
        service.execute_file_search('name = \'TEST\'')
        self.assertTrue(credentials_mock.refresh.called)

    @mock.patch('requests.get')
    def test_execute_file_search_extra_field(self, request_get_mock):
        request_get_mock.return_value = Mock(status_code=200,
                                             json=lambda: {'files': 'TEST_RESPONSE'})
        credentials_mock = Mock(valid=True, access_token='TEST')
        service = DriveService(credentials_mock)
        result = service.execute_file_search('q', 'order_by', 'fields')
        request_get_mock.assert_called_with('https://www.googleapis.com/drive/v3/files',
                                            headers={'Authorization': "Bearer TEST"},
                                            params={'q': 'q', 'orderBy': 'order_by', 'fields': 'fields'})

    @mock.patch('requests.get')
    def test_execute_file_error(self, request_get_mock):
        request_get_mock.return_value = Mock(status_code=200,
                                             json=lambda: {'error': 'Some Error'})
        credentials_mock = Mock(valid=True)
        service = DriveService(credentials_mock)

        with self.assertRaises(FileError):
            service.execute_file_search('name = \'TEST\'')

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.execute_file_search')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.split_path_into_file_and_folders')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.check_if_folder_exists')
    def test_get_file_meta(self, check_if_folder_exists_mock, split_path_mock, execute_file_search_mock):
        credentials_mock = Mock(valid=True)
        split_path_mock.return_value = (['one', 'two', 'three'], 'file.txt')
        check_if_folder_exists_mock.return_value = 'value_id'

        service = DriveService(credentials_mock)
        service.get_file_meta('', 12345)

        self.assertEqual(check_if_folder_exists_mock.call_count, 3)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.execute_file_search')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.split_path_into_file_and_folders')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.check_if_folder_exists')
    def test_get_file_meta_parent_none(self, check_if_folder_exists_mock, split_path_mock, execute_file_search_mock):
        credentials_mock = Mock(valid=True)
        split_path_mock.return_value = (['one', 'two', 'three'], 'file.txt')
        check_if_folder_exists_mock.return_value = None
        service = DriveService(credentials_mock)
        value = service.get_file_meta('', 12345)

        self.assertEqual(check_if_folder_exists_mock.call_count, 1)
        self.assertIsNone(value)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.execute_file_search')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.split_path_into_file_and_folders')
    def test_get_file_meta_multiple_files(self, split_path_mock, execute_file_search_mock):
        credentials_mock = Mock(valid=True)
        split_path_mock.return_value = (['one', 'two', 'three'], 'file.txt')
        service = DriveService(credentials_mock)
        execute_file_search_mock.return_value = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
        value = service.get_file_meta('', 12345)
        self.assertEqual('1', value['id'])

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.execute_file_search')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.split_path_into_file_and_folders')
    def test_get_file_meta_no_files(self, split_path_mock, execute_file_search_mock):
        credentials_mock = Mock(valid=True)
        split_path_mock.return_value = (['one', 'two', 'three'], 'file.txt')
        service = DriveService(credentials_mock)
        execute_file_search_mock.return_value = []
        value = service.get_file_meta('', 12345)
        self.assertIsNone(value)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.execute_file_search')
    def test_check_folder_exists(self, execute_file_mock):
        credentials_mock = Mock(valid=True)
        execute_file_mock.return_value = []
        service = DriveService(credentials_mock)
        service.check_if_folder_exists('TEST_NAME')
        self.assertTrue('parents' not in str(execute_file_mock.call_args))
        self.assertTrue('TEST_NAME' in str(execute_file_mock.call_args))

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.execute_file_search')
    def test_check_folder_exists_with_parent(self, execute_file_mock):
        credentials_mock = Mock(valid=True)
        execute_file_mock.return_value = []
        service = DriveService(credentials_mock)
        service.check_if_folder_exists('TEST_NAME', 123456)
        self.assertTrue('parents' in str(execute_file_mock.call_args))
        self.assertTrue('123456' in str(execute_file_mock.call_args))
        self.assertTrue('TEST_NAME' in str(execute_file_mock.call_args))

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.execute_file_search')
    def test_check_folder_exist_return(self, execute_file_mock):
        credentials_mock = Mock(valid=True)
        service = DriveService(credentials_mock)
        execute_file_mock.return_value = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
        value = service.check_if_folder_exists('TEST_NAME')

        self.assertEqual(value, '1')

    @mock.patch('requests.post')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.check_if_folder_exists')
    def test_create_remote_folder(self, check_folder_mock, request_mock):
        credentials_mock = Mock(valid=True, access_token='TEST-TOKEN')
        service = DriveService(credentials_mock)
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'id': 'SOME_ID'})

        self.assertFalse(check_folder_mock.called)
        self.assertFalse(request_mock.called)
        check_folder_mock.return_value = None
        value = service.create_remote_folder('FOLDER-NAME')
        self.assertTrue(check_folder_mock.called)
        self.assertTrue(request_mock.called)
        self.assertEqual('SOME_ID', value)

    @mock.patch('requests.post')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.check_if_folder_exists')
    def test_create_remote_folder_already_exists(self, check_folder_mock, request_mock):
        credentials_mock = Mock(valid=True, access_token='TEST-TOKEN')
        service = DriveService(credentials_mock)
        request_mock.return_value = Mock(status_code=200)

        self.assertFalse(check_folder_mock.called)
        self.assertFalse(request_mock.called)
        check_folder_mock.return_value = 'EXISTING_ID'
        value = service.create_remote_folder('FOLDER-NAME')
        self.assertTrue(check_folder_mock.called)
        self.assertFalse(request_mock.called)
        self.assertEqual('EXISTING_ID', value)

    @mock.patch('requests.post')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.check_if_folder_exists')
    def test_create_remote_folder_refresh_creds(self, check_folder_mock, request_mock):
        credentials_mock = Mock(valid=False, access_token='TEST-TOKEN')
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'id': 'SOME_ID'})
        check_folder_mock.return_value = None
        service = DriveService(credentials_mock)
        self.assertFalse(credentials_mock.refresh.called)
        service.create_remote_folder('FOLDERNAME')
        self.assertTrue(credentials_mock.refresh.called)

    @mock.patch('requests.post')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.check_if_folder_exists')
    def test_create_remote_folder_error_returned(self, check_folder_mock, request_mock):
        credentials_mock = Mock(valid=False, access_token='TEST-TOKEN')
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'error': 'SOME_ID'})
        check_folder_mock.return_value = None
        service = DriveService(credentials_mock)
        value = service.create_remote_folder('FOLDERNAME')
        self.assertIsNone(value)

    @mock.patch('requests.post')
    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.check_if_folder_exists')
    def test_create_remote_folder_in_parent(self, check_folder_mock, request_mock):
        credentials_mock = Mock(valid=False, access_token='TEST-TOKEN')
        request_mock.return_value = Mock(status_code=200,
                                         json=lambda: {'error': 'SOME_ID'})
        check_folder_mock.return_value = None
        service = DriveService(credentials_mock)
        value = service.create_remote_folder('FOLDERNAME', 'PARENT_ID')
        self.assertTrue('PARENT_ID' in str(request_mock.call_args))
        self.assertIsNone(value)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.create_remote_folder')
    def test_create_remote_path(self, create_remote_folder_mock):
        credentials_mock = Mock(valid=False)
        service = DriveService(credentials_mock)
        self.assertFalse(create_remote_folder_mock.called)
        create_remote_folder_mock.return_value = 'VALUE'
        value = service.create_remote_path('/one/two/three/file.txt')
        self.assertEqual(3, create_remote_folder_mock.call_count)
        self.assertEqual('VALUE', value)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.create_remote_folder')
    def test_create_remote_path_none(self, create_remote_folder_mock):
        credentials_mock = Mock(valid=False)
        service = DriveService(credentials_mock)
        self.assertFalse(create_remote_folder_mock.called)
        create_remote_folder_mock.return_value = None
        value = service.create_remote_path('/one/two/three/file.txt')
        self.assertEqual(1, create_remote_folder_mock.call_count)
        self.assertIsNone(value)

    @mock.patch('os.path.basename')
    @mock.patch('os.path.getsize')
    @mock.patch('requests.patch')
    def test_init_upload_existing_invalid_creds(self, request_patch, getsize, basename):
        credentials_mock = Mock(valid=False)

        request_patch.return_value = Mock(status_code=200,
                                          headers={'Location': 'SOME_ID'})
        getsize.return_value = 5000
        basename.return_value = 200
        service = DriveService(credentials_mock)
        self.assertFalse(credentials_mock.refresh.called)
        value = service.init_resumable_upload_session_existing_file('FOLDERNAME', 'ID')
        self.assertTrue(credentials_mock.refresh.called)
        self.assertEqual('SOME_ID', value)

    @mock.patch('os.path.basename')
    @mock.patch('os.path.getsize')
    @mock.patch('requests.patch')
    def test_init_uploading_existing_no_location(self, request_patch, getsize, basename):
        credentials_mock = Mock(valid=True)

        request_patch.return_value = Mock(status_code=200,
                                          headers={'TEST': 'SOME_ID'})
        getsize.return_value = 5000
        basename.return_value = 200
        service = DriveService(credentials_mock)
        value = service.init_resumable_upload_session_existing_file('FOLDERNAME', 'ID')
        self.assertIsNone(value)

    @mock.patch('os.path.basename')
    @mock.patch('os.path.getsize')
    @mock.patch('requests.patch')
    def test_init_uploading_existing(self, request_patch, getsize, basename):
        credentials_mock = Mock(valid=True)

        request_patch.return_value = Mock(status_code=200,
                                          headers={'Location': 'SOME_ID'})
        getsize.return_value = 5000
        basename.return_value = 200
        service = DriveService(credentials_mock)
        value = service.init_resumable_upload_session_existing_file('FOLDERNAME', 'ID')
        self.assertEqual('SOME_ID', value)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.create_remote_path')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.getsize')
    @mock.patch('requests.patch')
    def test_init_uploading_invalid_creds(self, request_patch, getsize, basename, create_remote_path_mock):
        credentials_mock = Mock(valid=False)

        request_patch.return_value = Mock(status_code=200,
                                          headers={'Location': 'SOME_ID'})
        getsize.return_value = 5000
        basename.return_value = 200
        service = DriveService(credentials_mock)
        self.assertFalse(credentials_mock.refresh.called)
        create_remote_path_mock.return_value = None
        value = service.init_resumable_upload_session('FILE', 'REMOTE', 'ID')
        self.assertTrue(credentials_mock.refresh.called)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.create_remote_path')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.getsize')
    @mock.patch('requests.patch')
    def test_init_uploading_no_location(self, request_patch, getsize, basename, create_remote_path_mock):
        credentials_mock = Mock(valid=True)

        request_patch.return_value = Mock(status_code=200,
                                          headers={'TEST': 'SOME_ID'})
        getsize.return_value = 5000
        basename.return_value = 200
        create_remote_path_mock.return_value = 'SOMETHING'
        service = DriveService(credentials_mock)
        value = service.init_resumable_upload_session('path', 'path', 'id')
        self.assertIsNone(value)

    @mock.patch('dsmr_gdrive.gdrive.drive_api.DriveService.create_remote_path')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.getsize')
    @mock.patch('requests.post')
    def test_init_uploading(self, request_post, getsize, basename, create_remote_path_mock):
        credentials_mock = Mock(valid=True)

        request_post.return_value = Mock(status_code=200,
                                         headers={'Location': 'SOME_ID'})
        getsize.return_value = 5000
        basename.return_value = 200
        create_remote_path_mock.return_value = 'SOMETHING'
        service = DriveService(credentials_mock)
        value = service.init_resumable_upload_session('path', 'path', 'id')
        self.assertEqual('SOME_ID', value)

    def test_split_path(self):
        path_1 = '/one/file.txt'
        path_2 = '/one/two/file_2.txt'
        path_3 = '/one/two/three/file_3.txt'

        service = DriveService(None)
        r_folders, r_files = service.split_path_into_file_and_folders(path_1)
        self.assertEqual(r_folders, ['one'])
        self.assertEqual(r_files, 'file.txt')

        r_folders, r_files = service.split_path_into_file_and_folders(path_2)
        self.assertEqual(r_folders, ['one', 'two'])
        self.assertEqual(r_files, 'file_2.txt')

        r_folders, r_files = service.split_path_into_file_and_folders(path_3)
        self.assertEqual(r_folders, ['one', 'two', 'three'])
        self.assertEqual(r_files, 'file_3.txt')

    @mock.patch('requests.put')
    def test_upload(self, request_mock):
        service = DriveService(None)
        request_mock.return_value = Mock(status_code=200)
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'just a couple of words to test')
            temp_file.flush()
            value = service.upload_file(temp_file.name, 'LOCATION')
            self.assertTrue(value)

    def test_upload_no_file(self):
        service = DriveService(None)
        with self.assertRaises(UploadError):
            value = service.upload_file('LALALA', 'SOME_LOCATION')

    @mock.patch('requests.put')
    def test_upload_all_send(self, request_mock):
        service = DriveService(None)

        with tempfile.NamedTemporaryFile() as temp_file:

            temp_file.write(b'just a couple of words to test')
            temp_file.flush()
            file_size = os.path.getsize(temp_file.name)
            request_mock.return_value = Mock(status_code=308, headers={'Range': f'SOMETHING-{file_size}'})
            value = service.upload_file(temp_file.name, 'LOCATION')
            self.assertTrue(value)

    @mock.patch('requests.put')
    def test_upload_no_range(self, request_mock):
        service = DriveService(None)

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'just a couple of words to test')
            temp_file.flush()
            file_size = os.path.getsize(temp_file.name)
            request_mock.return_value = Mock(status_code=308, headers={'NOTRANGE': f'SOMETHING-{file_size}'})
            with self.assertRaises(UploadError):
                value = service.upload_file(temp_file.name, 'SOME_LOCATION')

    @mock.patch('requests.put')
    def test_upload_unknown_response(self, request_mock):
        service = DriveService(None)

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'just a couple of words to test')
            temp_file.flush()
            file_size = os.path.getsize(temp_file.name)
            request_mock.return_value = Mock(status_code=404, headers={'NOTRANGE': f'SOMETHING-{file_size}'})
            with self.assertRaises(UploadError):
                value = service.upload_file(temp_file.name, 'SOME_LOCATION')

    @mock.patch('requests.put')
    def test_upload_large_file(self, request_mock):
        service = DriveService(None)
        with tempfile.NamedTemporaryFile() as temp_file:
            file_size = os.path.getsize(temp_file.name)
            while file_size < service.CHUNK_SIZE:
                file_size = os.path.getsize(temp_file.name)
                temp_file.write(b'just a couple of words to test')
                temp_file.flush()

            request_mock.return_value = Mock(status_code=200)
            value = service.upload_file(temp_file.name, 'LOCATION')
            self.assertTrue(value)






