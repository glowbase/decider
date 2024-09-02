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
    crumbs = [{
        "name": "start",
        "url": url_for("question_.question_start_page", version=version_context),
    }]

    # tactic if present
    if len(ids) > 1:
        logger.debug(f"Crumb Bar: querying Tactic by ID {ids[1]} ({version_context})")
        tactic = db.session.query(Tactic).filter_by(tact_id=ids[1], attack_version=version_context).first()

        if tactic is None:
            logger.error("Crumb Bar: Tactic does not exist")
            return None
        logger.debug("Crumb Bar: Tactic exists")

        crumbs.append(
            {
                "name": f"{tactic.tact_name} ({tactic.tact_id})",
                "url": build_mitigation_url(None, tactic.tact_id, version_context),
            }
        )

    # techs if present
    if len(ids) > 2:
        if not all(is_tech_id(t) for t in ids[2:]):
            logger.error("Crumb Bar: failed - request had one or more malformed Techniques")
            return None

        logger.debug(f"Crumb Bar: querying Techs by IDs {ids[2:]} ({version_context})")
        techniques = (
            db.session.query(Technique).filter(
                and_(
                    Technique.tech_id.in_(ids[2:]),
                    Technique.attack_version == version_context,
                )
            )
        ).all()

        if len(techniques) != len(ids[2:]):
            logger.error("Crumb Bar: 1+ Techniques do not exist")
            return None
        logger.debug("Crumb Bar: All Techniques exist")

        techniques.sort(key=lambda t: ids[2:].index(t.tech_id))
        for technique in techniques:
            crumbs.append(
                {
                    "name": f"{technique.tech_name} ({technique.tech_id})",
                    "url": build_mitigation_url(technique, tactic.tact_id, version_context),
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
    for tech in technique_mitigation_uses:
        mitigations_uses.append(
            {
                "tech_id": tech[0],
                "full_tech_name": tech[1],
                "attack_version": tech[2],
                "tech_description": outgoing_markdown(tech[3]) if tech[3] is not None else "",
                "tech_url": tech[4],
                "use": outgoing_markdown(tech[5]) if tech[5] is not None else "",
            }
        )

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

@mitigations_.route("/mitigations/<source>", methods=["GET"])
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def mitigation_src_success(source: str):
    """Route of (Sub/)Technique success page without a tactic context (HTML response)

    The utility of a success page without a Tactic context is in search results.
    A user searching for a certain keyword / behavior can land on a (Sub/)Technique page.
    However, the goal the adversary had was not yet considered.
    The user can select what Tactic (goal) applies on this page to allow adding it to their cart.

    version: str of ATT&CK version to pull content from
    """
    g.route_title = "Mitigation Success Page"
    mitigation_source = db_read.mitigation.mit_src(source)

    if not mitigation_source:
        logger.error("failed - request contained a malformed Mitigation Source")
        return render_template("status_codes/404.html"), 404


    logger.debug(f"{source} exists")

    mitigations = []
    mits = db.session.query(Mitigation).filter(Mitigation.mitigation_source == mitigation_source.uid).all()
    for mit in mits:
        mitigations.append(
            {
                "uid":mit.uid,
                "mit_id": mit.mit_id,
                "name": mit.name,
                "description": outgoing_markdown(mit.description)
            }
        )

    success = {
        "success": {
            "id": mitigation_source.uid,
            "src_display_name": mitigation_source.display_name,
            "description": outgoing_markdown(mitigation_source.description),
            "url": mitigation_source.url,
            "mitigations": mitigations,
        }
    }

    logger.info("serving page")
    return render_template("mitigation_source_success.html", **success)


@mitigations_.route("/mitigations/<source>/<path:mit_id>", methods=["GET"])
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def mitigation_success(source, mit_id=""):
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
    mitigation_context = db_read.mitigation.mit_src(source)
    path = mit_id.strip().strip("/").split("/")

    if not mitigation_context:
        logger.error("failed - request contained a malformed Mitigation Source")
        return render_template("status_codes/404.html"), 404

    if not re.fullmatch(mitigation_context.id_regex, mit_id):
        logger.error("failed - request had a malformed Mitigation ID")
        return render_template("status_codes/404.html"), 404

    success = success_page_vars(mit_id)

    logger.info("serving page")
    return render_template("mitigation_success.html", **success)
