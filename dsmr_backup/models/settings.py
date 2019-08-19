from datetime import time

from django.db import models
from django.utils.html import format_html
from django.utils.translation import ugettext_lazy as _
from solo.models import SingletonModel


class BackupSettings(SingletonModel):
    """ Generic backup settings. """
    daily_backup = models.BooleanField(
        default=True,
        verbose_name=_('Backup daily'),
        help_text=_('Create a backup of your data daily. Stored locally, but can be exported using Dropbox.')
    )
    backup_time = models.TimeField(
        default=time(hour=2),
        verbose_name=_('Backup timestamp'),
        help_text=_(
            'Daily moment of creating the backup. You should prefer a nightly timestamp, as it '
            'might freeze or lock the application shortly during backup creation.'
        )
    )
    folder = models.CharField(
        max_length=512,
        default='backups/',
        verbose_name=_('Backup storage folder'),
        help_text=_(
            'The folder to store the backups in. The default location is "backups/". '
            'Please make sure that the "dsmr" user both has read and write access to the folder.'
        ),
    )
    latest_backup = models.DateTimeField(
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Latest backup'),
        help_text=_(
            'Timestamp of latest backup created. Automatically updated by application. Please note '
            'that the application will ignore the "backup_time" setting the first time used.'
        )
    )

    def __str__(self):
        return self._meta.verbose_name.title()

    class Meta:
        default_permissions = tuple()
        verbose_name = _('Backup configuration')


class DropboxSettings(SingletonModel):
    """ Dropbox backup upload settings. """
    access_token = models.CharField(
        max_length=128,
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Dropbox access token'),
    )
    latest_sync = models.DateTimeField(
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Latest sync'),
        help_text=_('Timestamp of latest sync with Dropbox. Automatically updated by application.')
    )
    next_sync = models.DateTimeField(
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Next sync'),
        help_text=_('Timestamp of next sync with Dropbox. Automatically updated by application.')
    )

    def __str__(self):
        return self._meta.verbose_name.title()

    class Meta:
        default_permissions = tuple()
        verbose_name = _('Dropbox configuration')


class GoogleDriveSettings(SingletonModel):
    """ Google Drive backup  settings. """
    client_id = models.CharField(
        max_length=128,
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Client ID'),
    )
    client_secret = models.CharField(
        max_length=128,
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Client Secret'),
    )
    # Read-Only Fields
    authorization_url = models.CharField(
        max_length=128,
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Authorization URL'),
    )
    user_code = models.CharField(
        max_length=24,
        default=None,
        null=True,
        blank=True,
        verbose_name=_('User Code'),
    )
    latest_sync = models.DateTimeField(
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Latest sync'),
        help_text=_('Timestamp of latest sync with Google Drive. Automatically updated by application.')
    )
    next_sync = models.DateTimeField(
        default=None,
        null=True,
        blank=True,
        verbose_name=_('Next sync'),
        help_text=_('Timestamp of next sync with Google Drive. Automatically updated by application.')
    )

    # None visible fields
    folder_name = models.CharField(  # In later release should be user changeable
        max_length=24,
        default="dsmr-backup",
        null=True,
        blank=True,
        verbose_name=_('Google Drive Folder Name'),
    )
    folder_id = models.CharField(
        max_length=128,
        default=None,
        null=True,
        blank=True,
    )
    interval = models.IntegerField(default=5)
    access_token = models.CharField(
        max_length=256,
        default=None,
        null=True,
        blank=True,
    )
    refresh_token = models.CharField(
        max_length=128,
        default=None,
        null=True,
        blank=True,
    )
    device_code = models.CharField(
        max_length=128,
        default=None,
        null=True,
        blank=True,
    )
    token_expiry = models.DateTimeField()
    state = models.IntegerField(default=0)

    def authorization_url_view(self):
        return format_html("<a href=\"{}\" target=\"_blank\">{}</a>".format(self.authorization_url,
                                                                            self.authorization_url))

    def __str__(self):
        return self._meta.verbose_name.title()

    class Meta:
        default_permissions = tuple()
        verbose_name = _('Google Drive configuration')


class EmailBackupSettings(SingletonModel):
    """ Backup by email settings. """
    INTERVAL_NONE = None
    INTERVAL_DAILY = 1
    INTERVAL_WEEKLY = 7
    INTERVAL_BIWEEKLY = 14
    INTERVAL_MONTHLY = 28

    INTERVAL_CHOICES = (
        (INTERVAL_NONE, _('--- Disabled ---')),
        (INTERVAL_DAILY, _('Daily')),
        (INTERVAL_WEEKLY, _('Weekly')),
        (INTERVAL_BIWEEKLY, _('Every two weeks')),
        (INTERVAL_MONTHLY, _('Every four weeks')),
    )
    interval = models.IntegerField(
        null=True,
        blank=True,
        default=INTERVAL_NONE,
        choices=INTERVAL_CHOICES,
        help_text=_('The frequency of sending backups per email')
    )

    def __str__(self):
        return self._meta.verbose_name.title()

    class Meta:
        default_permissions = tuple()
        verbose_name = _('Email backup configuration')
