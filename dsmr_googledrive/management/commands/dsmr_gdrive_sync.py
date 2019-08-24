from django.core.management.base import BaseCommand
from django.utils.translation import ugettext as _
from django.utils import timezone

import dsmr_googledrive.services


class Command(BaseCommand):
    help = _('Forces Google Drive sync.')

    def handle(self, **options):
        dsmr_googledrive.services.sync()
        pass
