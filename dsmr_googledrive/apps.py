from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class GoogleDriveAppConfig(AppConfig):
    name = 'dsmr_googledrive'
    verbose_name = _('Google Drive')
