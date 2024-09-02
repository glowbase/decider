# Crumbs
# -----------------------------------------------------------------------------------
# start
# start / Mitigation Source (ID)
# start / Mitigation Source (ID) / Mitigation (ID)

from operator import and_
from flask import Blueprint, render_template, g, url_for
from app.models import (
    db,
    Technique,
    MitigationSource,
    Mitigation,
)
from app.models import (
    technique_mitigation_map,
)
from sqlalchemy import func, distinct
from sqlalchemy.dialects.postgresql import array

import app.utils.db.read as db_read

import logging.config

import re

from app.routes.utils_db import VersionPicker
from app.routes.utils import (
    build_mitigation_url,
    is_attack_version,
    outgoing_markdown
)
from app.routes.utils import ErrorDuringHTMLRoute, wrap_exceptions_as

logger = logging.getLogger(__name__)
mitigations_ = Blueprint("mitigations_", __name__, template_folder="templates")


def crumb_bar(ids, version_context):
    """Builds the navigation crumb bar and checks that each crumb exists

    ids: list[str] of IDs describing the requested location in the question tree
    possible forms for ids:
    - mitigation source             : mitigation source
    - mitigation source, mitigation : mitigation source -> mitigation

    version_context: str of ATT&CK version to pull content from

    returns None if any node is missing
    returns {"breadcrumbs": crumbs} on success
    - crumbs is a list of dicts, each having keys "name", "url"
    """

    # invalid range check
    if not (1 <= len(ids) <= 4):
        logger.error("Crumb Bar: failed - request had too little or too many crumbs (invalid format)")
        return None

    # start always present
    crumbs = []

    logger.debug(f"Crumb Bar: querying Source by ID {ids[0]} ({version_context})")
    mitigation_src = db_read.mitigation.mit_src(ids[0])

    if mitigation_src is None:
        logger.error("Crumb Bar: Mitigation Source does not exist")
        return None
    logger.debug("Crumb Bar: Tactic exists")

    crumbs.append(
        {
            "name": f"{mitigation_src.display_name}",
            "url": build_mitigation_url(None, mitigation_src, version_context),
        }
    )

    # techs if present
    if len(ids) > 1:
        logger.debug(f"Crumb Bar: querying Mitigations by IDs {ids[1:]} ({version_context})")
        mitigations = (
            db.session.query(Mitigation).filter(
                Mitigation.mit_id.in_(ids[1:])
            )
        ).all()

        if len(mitigations) != len(ids[1:]):
            logger.error("Crumb Bar: 1+ Mitigation do not exist")
            return None
        logger.debug("Crumb Bar: All Techniques exist")

        mitigations.sort(key=lambda t: ids[1:].index(t.mit_id))
        for mit in mitigations:
            crumbs.append(
                {
                    "name": f"{mit.name} ({mit.mit_id})",
                    "url": build_mitigation_url(mit, mitigation_src, version_context),
                }
            )

    logger.info("Crumb Bar: successfully built")
    return {"breadcrumbs": crumbs}


# ---------------------------------------------------------------------------------------------------------------------
# Mitigation Page & Helpers

def success_page_vars(mit_id, version_context):
    """Generates variables needed for the Jinja success page template

    index: str of MitID that the success page is for

    version_context: str of the ATT&CK version to pull content from
    """

    # get mitigations and its Mitigation Techniques Use
    logger.debug(f"querying Techniques and Uses of Mitigation {mit_id}")
    mitigation, mitigation_src, technique_mitigation_uses = (
        db.session.query(
            Mitigation,  # 0
            func.array_agg(distinct(array([MitigationSource.source, MitigationSource.description, MitigationSource.display_name, MitigationSource.url]))),  # 1
            func.array_agg(distinct(array([Technique.tech_id, Technique.full_tech_name, Technique.attack_version, Technique.tech_description, Technique.tech_url, technique_mitigation_map.c.use]))),  # 2
        )
        .filter(
            Mitigation.mit_id == mit_id
        )
        .outerjoin(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .outerjoin(technique_mitigation_map, Mitigation.uid == technique_mitigation_map.c.mitigation)
        .outerjoin(Technique, technique_mitigation_map.c.technique == Technique.uid)
        .filter(Technique.attack_version == version_context)
        .group_by(Mitigation.uid)
    ).first()

    logger.debug(f"got {len(technique_mitigation_uses)} Uses for Mitigation {mitigation.mit_id}")

    mitigations_uses = []
    if(not technique_mitigation_uses is None or len(technique_mitigation_uses) > 0):
        for tech in technique_mitigation_uses:
            if(tech[0] is not None and len(tech[0]) > 0):
                mitigations_uses.append(
                {
                    "tech_id": tech[0],
                    "full_tech_name": tech[1],
                    "attack_version": tech[2],
                    "tech_description": outgoing_markdown(tech[3]) if tech[3] is not None else "",
                    "tech_url": tech[4],
                    "internal_url": url_for(
                        "question_.notactic_success", version=tech[2], subpath=tech[0].replace(".", "/")
                    ),
                    "use": outgoing_markdown(tech[5]) if tech[5] is not None else "",
                })

    # create jinja vars
    return {
        "success": {
            "id": mit_id,
            "name": mitigation.name,
            "description": outgoing_markdown(mitigation.description),
            "url": "/mitigations/" + mitigation_src[0][0] + "/" + mit_id,
            "techniques": mitigations_uses,
            "mitigation_src": mitigation_src[0]
        }
    }

@mitigations_.route("/mitigations/<version>/<source>", methods=["GET"])
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def mitigation_src_success(version, source: str):
    """Route of Mitigation Source success page (HTML response)

    The utility of a source success page is in linking to all the mitigations.

    version: str of ATT&CK version to pull content from
    """
    g.route_title = "Mitigation Source Success Page"
    mitigation_context = db_read.mitigation.mit_src(source)

    if not is_attack_version(version):
        logger.error("failed - request contained a malformed ATT&CK version")
        return render_template("status_codes/404.html"), 404

    logger.debug(f"querying existence of version {version}")
    version_pick = VersionPicker(version=version)
    if not version_pick.set_vars():
        logger.error("requested ATT&CK version does not exists")
        return render_template("status_codes/404.html"), 404
    logger.debug("requested ATT&CK version exists")

    if not mitigation_context:
        logger.error("failed - request contained a malformed Mitigation Source")
        return render_template("status_codes/404.html"), 404

    logger.debug(f"{source} exists")

    mitigations = []
    mits = db.session.query(Mitigation).filter(Mitigation.mitigation_source == mitigation_context.uid).all()
    for mit in mits:
        mitigations.append(
            {
                "uid":mit.uid,
                "mit_id": mit.mit_id,
                "name": mit.name,
                "description": outgoing_markdown(mit.description),
                "internal_url": url_for("mitigations_.mitigation_success", version=version, source=source, mit_id=mit.mit_id),
            }
        )

    success = {
        "success": {
            "id": mitigation_context.uid,
            "src_display_name": mitigation_context.display_name,
            "description": outgoing_markdown(mitigation_context.description),
            "url": mitigation_context.url,
            "mitigations": mitigations,
        }
    }

    crumbs = crumb_bar([mitigation_context.source], version)
    logger.info("serving page")
    return render_template("mitigation_source_success.html", **success, **crumbs)


@mitigations_.route("/mitigations/<version>/<source>/<path:mit_id>", methods=["GET"])
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def mitigation_success(version, source, mit_id):
    """Route of Mitigation success page (HTML response)

    The utility of a Mitigation success page is in seeing all related Techniques and Uses
    for the mitigation.

    version: str of ATT&CK version to pull content from

    source: str of Mitigation Source that the Mitigation belongs to
    path: str path describing resource being accessed. This validated against the Regex of the Mitigation Source
    """
    g.route_title = "Mitigation Success Page"
    mitigation_src_context = db_read.mitigation.mit_src(source)

    if not is_attack_version(version):
        logger.error("failed - request contained a malformed ATT&CK version")
        return render_template("status_codes/404.html"), 404

    logger.debug(f"querying existence of version {version}")
    version_pick = VersionPicker(version=version)
    if not version_pick.set_vars():
        logger.error("requested ATT&CK version does not exists")
        return render_template("status_codes/404.html"), 404
    logger.debug("requested ATT&CK version exists")

    version_context = version_pick.cur_version

    if not mitigation_src_context:
        logger.error("failed - request contained a malformed Mitigation Source")
        return render_template("status_codes/404.html"), 404

    if not re.fullmatch(mitigation_src_context.id_regex, mit_id):
        logger.error("failed - request had a malformed Mitigation ID")
        return render_template("status_codes/404.html"), 404

    success = success_page_vars(mit_id, version_context)

    crumbs = crumb_bar([mitigation_src_context.source, mit_id], version)
    logger.info("serving page")
    return render_template("mitigation_success.html", **success, **crumbs)
