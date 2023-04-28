import os.path

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
from requests import session
from requests.auth import HTTPDigestAuth
import re
from urllib.parse import urljoin,urlparse

class POC(POCBase):

    def _verify(self):
