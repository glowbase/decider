import logging
import json
import os
from app.models import technique_platform_map, tactic_technique_map, tactic_ds_map, technique_ds_map
from app.routes.auth import disabled_in_kiosk

from app.routes.utils import ErrorDuringAJAXRoute, wrap_exceptions_as

from flask import Blueprint, request, current_app, jsonify, g, url_for

from flask_login import current_user
from sqlalchemy import asc, func, distinct, and_, or_, literal_column
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm.util import aliased

from app.domain.mitigations_service import MitigationsService

logger = logging.getLogger(__name__)

mitigations_ = Blueprint("mitigations_", __name__)

@mitigations_.route("/api/mappings", methods=["GET"])
@wrap_exceptions_as(ErrorDuringAJAXRoute)
def get_mappings():
    return get_mitigations()

@mitigations_.route("/api/mitigations", methods=["GET"])
@wrap_exceptions_as(ErrorDuringAJAXRoute)
def get_mitigations():
    """Returns a list of custom mapping data stored in JSON file (JSON response)"""
    g.route_title = "Get Custom Mappings"
    technique = request.args.get("technique")
    if (technique is None):
        logger.error("request failed - technique field missing")
        return jsonify(message="'technique' field missing"), 400
    logger.info("querying custom mappings")
    ms = MitigationsService()
    return_value = ms.get_mitigations(technique)
    return jsonify(return_value), 200


