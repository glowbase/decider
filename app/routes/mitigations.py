import logging
import json
import os
from app.models import technique_platform_map, tactic_technique_map, tactic_ds_map, technique_ds_map
from app.routes.auth import disabled_in_kiosk

from app.routes.utils import (
    build_url,
    is_attack_version,
    is_base_tech_id,
    is_tact_id,
    is_tech_id,
    outgoing_markdown,
    trim_keys,
    DictValidator,
)

from app.routes.utils import ErrorDuringAJAXRoute, wrap_exceptions_as

from flask import Blueprint, request, current_app, jsonify, g, url_for

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

    version = request.args.get("version")
    technique = request.args.get("technique")

    # validate request arguments
    if (version is None) or (not is_attack_version(version)):
        version = "v15.1"
        # logger.error("request failed - ATT&CK version field missing / malformed")
        # return jsonify(message="'version' field missing / malformed"), 400

    if (technique is None):
        logger.error("request failed - technique field missing")
        return jsonify(message="'technique' field missing"), 400

    logger.info("querying custom mappings")

    ms = MitigationsService()
    return_value = ms.get_mitigations(technique, version)
    return jsonify(return_value), 200


