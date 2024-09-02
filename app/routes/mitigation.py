# Crumbs
# -----------------------------------------------------------------------------------
# start
# start / Mitigation Source (ID)
# start / Mitigation Source (ID) / Mitigation (ID)

from operator import and_
from flask import Blueprint, redirect, render_template, current_app, g, url_for
from app.models import (
    AttackVersion,
    db,
    Tactic,
    Technique,
    MitigationSource,
    Mitigation,
)
from app.models import (
    technique_mitigation_map,
)
from sqlalchemy import asc, func, distinct
from sqlalchemy.orm import aliased
from sqlalchemy.dialects.postgresql import array

import app.utils.db.read as db_read

import logging.config

import re

from app.routes.utils import (
    build_mitigation_url,
    is_tech_id,
    outgoing_markdown,
    checkbox_filters_component,
    remove_html_tag
)
from app.routes.utils import ErrorDuringHTMLRoute, wrap_exceptions_as

logger = logging.getLogger(__name__)
mitigations_ = Blueprint("mitigations_", __name__, template_folder="templates")


def crumb_bar(ids, version_context):
    """Builds the navigation crumb bar and checks that each crumb exists

    ids: list[str] of IDs describing the requested location in the question tree
    possible forms for ids:
    - start                    : start     -> tactic       question page
    - start, tactic            : tactic    -> technique    question page
    - start, tactic, tech      : technique -> subtechnique question page (if tech has subs), else tech success page
    - start, tactic, tech, sub : ----------------------------------------------------------,   subtech success page

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
# Question Page & Helpers - Normal Navigation & Tactic-less Success Page

def success_page_vars(mit_id):
    """Generates variables needed for the Jinja success page template

    index: str of MitId that the success page is for

    version_context: str of the ATT&CK version to pull content from
    """

    # get technique and its mitigation uses
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
    """Route of (Sub/)Technique success page without a tactic context (HTML response)

    The utility of a success page without a Tactic context is in search results.
    A user searching for a certain keyword / behavior can land on a (Sub/)Technique page.
    However, the goal the adversary had was not yet considered.
    The user can select what Tactic (goal) applies on this page to allow adding it to their cart.

    version: str of ATT&CK version to pull content from
    """
    g.route_title = "Mitigation Success Page"
    mitigation_context = db_read.mitigation.mit_src(source)

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
    """Route of (Sub/)Technique success page without a tactic context (HTML response)

    The utility of a success page without a Tactic context is in search results.
    A user searching for a certain keyword / behavior can land on a (Sub/)Technique page.
    However, the goal the adversary had was not yet considered.
    The user can select what Tactic (goal) applies on this page to allow adding it to their cart.

    version: str of ATT&CK version to pull content from

    subpath: str path describing resource being accessed
    subpath formats and their meaning:
    - T[0-9]{4}/         : Technique no-tactic success page
    - T[0-9]{4}/[0-9]{3} : SubTechnique no-tactic success page
    """
    g.route_title = "Mitigation Success Page"
    mitigation_src_context = db_read.mitigation.mit_src(source)

    if not mitigation_src_context:
        logger.error("failed - request contained a malformed Mitigation Source")
        return render_template("status_codes/404.html"), 404

    if not re.fullmatch(mitigation_src_context.id_regex, mit_id):
        logger.error("failed - request had a malformed Mitigation ID")
        return render_template("status_codes/404.html"), 404

    success = success_page_vars(mit_id)

    crumbs = crumb_bar([mitigation_src_context.source, mit_id], version)
    logger.info("serving page")
    return render_template("mitigation_success.html", **success, **crumbs)
