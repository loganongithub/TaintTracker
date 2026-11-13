# expect: path-traversal line 8, path-traversal line 13
import os

UPLOADS = "/srv/uploads"


def read_upload(name):
    with open(os.path.join(UPLOADS, name)) as f:
        return f.read()


def delete_upload(name):
    os.remove(os.path.join(UPLOADS, name))
