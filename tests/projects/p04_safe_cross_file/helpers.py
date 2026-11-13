# expect: none
import os

from werkzeug.utils import secure_filename


def safe_path(name):
    return os.path.join("/srv/files", secure_filename(name))
