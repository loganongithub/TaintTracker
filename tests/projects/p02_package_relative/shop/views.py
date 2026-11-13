# expect: none
from flask import Blueprint, request

from . import storage
from .storage import delete_upload

bp = Blueprint("shop", __name__)


@bp.route("/uploads/<path:name>")
def show(name):
    return storage.read_upload(name)


@bp.route("/uploads/delete", methods=["POST"])
def delete():
    delete_upload(request.form["name"])
    return "deleted"
