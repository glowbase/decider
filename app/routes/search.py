import bleach
import logging
import markdown
import re

from flask import Blueprint, request, render_template, jsonify, g, make_response, url_for

from sqlalchemy.sql.expression import distinct
from sqlalchemy.sql.functions import func
from sqlalchemy import REAL, literal_column, String, or_, and_
from sqlalchemy.orm.util import aliased

from app.models import (
    db,
    Tactic,
    Technique,
    Aka,
    Blurb,
    DataSource,
    Platform,
    Mitigation,
    MitigationSource
)

from app.domain import PSQLTxt
from app.domain.search_service import technique_search_args_are_valid, parse_search_str, tsqry_rep, plain_rep
from app.models import (
    technique_aka_map,
    technique_platform_map,
    tactic_technique_map,
    technique_ds_map,
    technique_mitigation_map
)
from app.routes.utils_db import VersionPicker
from app.routes.utils import (
    is_attack_version,
    checkbox_filters_component,
    is_base_tech_id,
    is_tact_id,
)
from app.routes.utils import ErrorDuringHTMLRoute, ErrorDuringAJAXRoute, wrap_exceptions_as

logger = logging.getLogger(__name__)
search_ = Blueprint("search_", __name__, template_folder="templates")

@search_.route("/search/mini/<version>", methods=["POST"])
@wrap_exceptions_as(ErrorDuringAJAXRoute)
def mini_search(version):
    """Route for Mini-Search in top right (quick jump to a Technique by name / ID)

    URL -> version: str of ATT&CK version to pull content from
    JSON request -> search: search string user typed

    JSON response
    - list[dict]
    - each dict represents a Technique result using keys "tech_name", "tech_id", "url"
    - results are ordered closest-match first
    """
    g.route_title = "Mini-Search"

    if not is_attack_version(version):
        logger.error("failed - request had a malformed ATT&CK version")
        return jsonify(message="Malformed ATT&CK version requested"), 400

    try:
        phrase = request.json.get("search").strip()
    except Exception:
        logger.exception("failed - malformed request/fields")
        return jsonify(message="Search form fields malformed"), 400

    # Matches T1234 | 1234 | T1234.123 | 1234.123 | .123 - with partial progress allowed left to right
    contains_tech_id = re.search(r"[Tt]?[0-9]{4}\.[0-9]{0,3}|[Tt]?[0-9]{1,4}|\.[0-9]{1,3}", phrase)
    if contains_tech_id:
        phrase = contains_tech_id.group(0)

        logger.debug(f"querying Techniques by ID under ATT&CK {version}")
        techniques = (
            db.session.query(
                Technique.full_tech_name,
                Technique.tech_id,
            )
            .filter(Technique.attack_version == version)
            .filter(Technique.tech_id.ilike(f"%{phrase}%"))
            .order_by(Technique.tech_id)
        ).all()

    # No match - return results by similarity descending of phrase likeness to Technique Name
    else:
        phrase = String("").literal_processor(dialect=db.session.get_bind().dialect)(value=phrase.lower())

        logger.debug(f"querying Techniques by name under ATT&CK {version}")
        subq = (
            db.session.query(
                Technique.full_tech_name,
                Technique.tech_id,
                literal_column(f"WORD_SIMILARITY({phrase}, technique.full_tech_name)", type_=REAL).label("sml"),
            ).filter(Technique.attack_version == version)
        ).subquery()
        techniques = (
            db.session.query(subq).filter(subq.c.sml > 0.25).order_by(subq.c.sml.desc(), subq.c.full_tech_name)
        ).all()

    logger.debug(f"got {len(techniques)} Techniques")

    # Make response from entries
    dictified = []
    for tech_name, tech_id, *_ in techniques:
        app_url = url_for("question_.notactic_success", version=version, subpath=tech_id.replace(".", "/"))
        dictified.append({"tech_name": tech_name, "tech_id": tech_id, "url": app_url})

    logger.info("sending search results to user")
    return jsonify(dictified), 200

@search_.route("/search/page", methods=["GET"])
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def search_page():
    """Route for the full Technique search page (HTML response)

    URL parameters are checked on request before sending response
    - the full search page updates the URL params as filtering / search are updated
    - these params allow sharing full search links and also allow the Back / Forward browser buttons to work

    The page's content is populated with search results from a separate GET request
    """
    g.route_title = "Full-Search Page"

    # get and validate parameters
    version = request.args.get("version")
    search_str = request.args.get("search")
    tactics = request.args.getlist("tactics")
    options = request.args.getlist("options")
    mitigation_sources = request.args.getlist("mitigation_sources")
    platforms = request.args.getlist("platforms")
    data_sources = request.args.getlist("data_sources")
    if not technique_search_args_are_valid(version, search_str, tactics, mitigation_sources, platforms, data_sources):
        # technique_search_args_are_valid has the error log action - this just shows a 404 will be sent
        logger.debug("request malformed - serving them a 404 page")
        return (
            render_template(
                "status_codes/404.html",
                **{
                    "reason_for_404": "The search request made was invalid - "
                    "did you visit a pasted URL that got cut-off?"
                },
            ),
            404,
        )

    # get version picked
    version_pick = VersionPicker(version=version)
    version_pick.set_vars()
    ver_model = version_pick.cur_version_model
    ver_name = ver_model.version

    # populate tactic / platform / data source checkbox options for picked version
    logger.debug(f"querying Tactics in ATT&CK {ver_name} for filters")
    tactic_names = [t.tact_name for t in ver_model.tactics]

    logger.debug(f"querying Platforms in ATT&CK {ver_name} for filters")
    platform_names = [p.readable_name for p in ver_model.platforms]

    logger.debug(f"querying Data Sources in ATT&CK {ver_name} for filters")
    data_source_names = [d.readable_name for d in ver_model.data_sources]

    logger.debug(f"querying Mitigation Sources in ATT&CK {ver_name} for filters")
    mitigation_source_names = db.session.query(MitigationSource.source).all()

    options_names = ["Techniques", "Usage Examples",
                     "Mitigations","Mitigation Uses"]

    options_filters = checkbox_filters_component(
        "options_fs",
        options_names,
        "searchClearOptions()",
        "searchUpdateOptions(this)",
        different_name="Options",
    )

    tactic_filters = checkbox_filters_component(
        "tactic_fs",
        tactic_names,
        "searchClearTactics()",
        "searchUpdateTactics(this)",
        different_name="Tactic",
    )
    platform_filters = checkbox_filters_component(
        "platform_fs",
        platform_names,
        "searchClearPlatforms()",
        "searchUpdatePlatforms(this)",
        different_name="Platform",
    )
    data_source_filters = checkbox_filters_component(
        "data_source_fs",
        data_source_names,
        "searchClearDataSources()",
        "searchUpdateDataSources(this)",
        different_name="Data Source",
    )
    mitigation_source_filters = checkbox_filters_component(
        "mitigation_source_fs",
        [x[0] for x in mitigation_source_names],
        "searchClearMitigationSources()",
        "searchUpdateMitigationSources(this)",
        different_name="Mitigation Source",
    )

    response = make_response(
        render_template("search.html", **options_filters, **tactic_filters, **platform_filters, **data_source_filters, **mitigation_source_filters)
    )

    logger.info("serving page")
    return response

def technique_search(search_tsqry, tactics, version, platforms, data_sources):
    results = []
    """Performs a full Technique search and returns highlighted & ranked results

    URL Params
    ----------
    version      : (str)     ATT&CK version to search for content in
    search_str   : (str)     user-entered boolean search expression
    tactics      : list[str] only show results with any of these Tactics      *
    platforms    : list[str] only show results with any of these Platforms    *
    data_sources : list[str] only show results with any of these Data Sources *

    * If this list is empty, no filtering is done on this aspect

    Output
    ------
    - list[dict] is returned
    - each dict is a Technique result from the search
    - results are ordered first by strength of match, and secondly by TechniqueID as a tie-breaker
    - each dict has these keys:
      - tech_id         : (str)     match-highlighted Tech ID
      - tech_id_plain   : (str)     raw Tech ID
      - tech_name       : (str)     match-highlighted Full Tech Name
      - tech_name_plain : (str)     raw Full Tech Name
      - description     : (str)     match-highlighted Tech Description (just text near highlights; or just start if none)
      - attack_url      : (str)     link to MITRE ATT&CK page for this Tech
      - internal_url    : (str)     link to Decider no_tactic success page for this Tech
      - akas            : list[str] match-highlighted list of tags associated with Tech

    Search Technology TL;DR
    -----------------------
    1. User search string is parsed into a boolean expression and then transformed into a ts_query
    3. Search space is reduced by filtering Techniques by tactic, platform, and data_source selection(s)
    4. This query is ran against a ts_vector representing each Technique
       Filter by tsvec @@ tsqry, then rank by ts_rank()
       Highest-to-Lowest ts_vector weights are as follows:
       A. Technique ID, in the forms "Twxyz abc" and "wxyz abc"
       B. Technique name (including parent name beforehand if a sub-Technique)
       C. Technique AKAs / keyword tags
       D. Technique description
    5. Highlights and description highlight snippets are generated for the results
    6. Results are ordered and sent out
    """
    
    tsvec = PSQLTxt.multiline_cleanup(
        """
        technique.tech_ts || setweight(
            to_tsvector(
                'english_nostop',
                regexp_replace(array_to_string(array_agg(distinct(aka.term)), ' ', ''), '[^a-z0-9 ]', ' ', 'gi')
            ),
            'C'
        )
    """
    )

    # filter techniques by platform / tactics / data source filters, then generate tsvecs for remaining
    logger.debug("querying Techniques filtered by Platform/Tactic/Data Source selections and ranked by relevance")
    tech_subq = (
        db.session.query(
            Technique.tech_id,  # 0
            literal_column(tsvec).label("tsvec"),  # 1
            literal_column(search_tsqry).label("tsqry"),  # 2
        )
        .filter(Technique.attack_version == version)
        .group_by(Technique.uid)
        # filter on tactics if specified
        .join(tactic_technique_map, Technique.uid == tactic_technique_map.c.technique)
        .join(Tactic, Tactic.uid == tactic_technique_map.c.tactic)
        .filter(or_(not tactics, func.lower(func.replace(Tactic.tact_name, " ", "_")).in_(tactics)))
        # filter on platforms if specified
        .join(technique_platform_map, Technique.uid == technique_platform_map.c.technique)
        .join(Platform, Platform.uid == technique_platform_map.c.platform)
        .filter(or_(not platforms, func.lower(func.replace(Platform.readable_name, " ", "_")).in_(platforms)))
        # filter on data sources if defined
        .outerjoin(technique_ds_map, Technique.uid == technique_ds_map.c.technique)
        .outerjoin(DataSource, DataSource.uid == technique_ds_map.c.data_source)
        .filter(or_(not data_sources, func.lower(func.replace(DataSource.readable_name, " ", "_")).in_(data_sources)))
        # add AKAs if defined for tech
        .outerjoin(technique_aka_map, Technique.uid == technique_aka_map.c.technique)
        .outerjoin(Aka, Aka.uid == technique_aka_map.c.aka)
    ).subquery()
    

    # get techniques matching search tsquery
    generate_existing = (db.session.query(tech_subq, literal_column("tsvec @@ tsqry").label("exists"))).subquery()

    # filter non-matching and get scores - returns IDs and their scores, pull into dict
    filter_and_scoreq = (
        db.session.query(
            generate_existing.c.tech_id,
            literal_column("ts_rank(tsvec, tsqry)").label("score"),
        ).filter(generate_existing.c.exists)
    )

    filter_and_score = filter_and_scoreq.all()

    logger.debug(f"got {len(filter_and_score)} matching Techniques")
    tech_to_score = {tech: score for tech, score in filter_and_score}

    # fetch details of matching techniques
    logger.debug("querying details for the earlier-matched Techniques")
    result_subq = (
        db.session.query(
            Technique.tech_id,  # 0
            Technique.full_tech_name,  # 1
            Technique.tech_description,  # 2
            Technique.tech_url,  # 3
            func.array_agg(distinct(Tactic.tact_id)),  # 4
            literal_column("replace(array_to_string(array_agg(distinct(aka.term)), '    ', ''), '\\\\', '\\')").label(
                "akas_str"
            ),  # 5
            literal_column(search_tsqry).label("tsqry"),  # 6
        )
        .filter(Technique.attack_version == version)
        .filter(Technique.tech_id.in_(list(tech_to_score.keys())))
        .group_by(Technique.uid)
        .join(tactic_technique_map, Technique.uid == tactic_technique_map.c.technique)
        .join(Tactic, Tactic.uid == tactic_technique_map.c.tactic)
        .outerjoin(technique_aka_map, Technique.uid == technique_aka_map.c.technique)
        .outerjoin(Aka, Aka.uid == technique_aka_map.c.aka)
    ).subquery()

    # generate highlights for ID, Name, Description, and AKAs

    # processing tech desc for ts_headline is easier to read as multiple stages
    s0 = PSQLTxt.unaccent("tech_description")
    s1 = PSQLTxt.no_html(s0)
    s2 = PSQLTxt.no_citation_nums(s1)
    s3 = PSQLTxt.no_md_urls(s2)
    s4 = PSQLTxt.newlines_as_space(s3)
    tech_desc_processed = PSQLTxt.zwspace_pad_special(s4)

    tech_desc_headline = PSQLTxt.multiline_cleanup(
        f"""
        ts_headline(
            'english_nostop',
            {tech_desc_processed},
            tsqry,
            '
                HighlightAll=false,
                MinWords=1,
                MaxWords=16,
                MaxFragments=4,
                FragmentDelimiter=<red>...</red><br>,
                StartSel=<mark>,
                StopSel=</mark>
            '
        )
    """
    )

    result_q = (
        db.session.query(
            result_subq,
            # 7, 8, 9, 10
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("tech_id"), "tsqry")).label("hl_id"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.unaccent("full_tech_name"), "tsqry")).label("hl_name"),
            literal_column(tech_desc_headline).label("hl_desc"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("akas_str"), "tsqry")).label("hl_akas"),
        )
    ).all()
    logger.debug("query finished")

    # build response
    for (
        tech_id,
        tech_name,
        tech_desc,
        tech_url,
        _,  # tactic_ids
        _,  # akas
        _,  # tsqry
        hl_id,
        hl_name,
        hl_desc,
        hl_akas,
    ) in result_q:
        # for ts_headlined descriptions - finish off any ... between snippets
        if len(hl_desc) > 50:
            tdesc = hl_desc.replace("<red>", '<span class="redtext">').replace("</red>", "</span>")

        # if no terms are matched in the description - get the first 250 chars, cut to last space, and add ... in red
        else:
            cleaned_desc = bleach.clean(markdown.markdown(tech_desc), tags=[], strip=True)[:250]
            cleaned_desc = cleaned_desc[: cleaned_desc.rfind(" ")]
            tdesc = f'{cleaned_desc}<span class="redtext">...</span>'

        results.append(
            {
                "technique": True,
                "tech_id": hl_id,
                "card_id_plain": tech_id,
                "tech_name": hl_name,
                "tech_name_plain": tech_name,
                "description": tdesc,
                "attack_url": tech_url,
                "internal_url": url_for(
                    "question_.notactic_success", version=version, subpath=tech_id.replace(".", "/")
                ),
                "akas": hl_akas.split("    ") if hl_akas else [],
                "score": tech_to_score[tech_id],
            }
        )

    return results

def mitigation_search(search_tsqry, mitigation_sources, version):
    results = []
    
    tsvec = PSQLTxt.multiline_cleanup(
        """
        mitigation.mit_ts 
    """
    )

    # filter Mitigations by Mitigation Source filters, then generate tsvecs for remaining
    logger.debug("querying Mitigations filtered by Mitigation Source selections and ranked by relevance")
    
    mit_subq = (
        db.session.query(
            Mitigation.mit_id,  # 0
            literal_column(tsvec).label("tsvec"),  # 1
            literal_column(search_tsqry).label("tsqry"),  # 2
        )
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.source, " ", "_")).in_(mitigation_sources)))
    ).subquery() 

    # get techniques matching search tsquery
    generate_existing = (db.session.query(mit_subq, literal_column("tsvec @@ tsqry").label("exists"))).subquery()

    # filter non-matching and get scores - returns IDs and their scores, pull into dict
    filter_and_scoreq = (
        db.session.query(
            generate_existing.c.mit_id,
            literal_column("ts_rank(tsvec, tsqry)").label("score"),
        ).filter(generate_existing.c.exists)
    )
        
    filter_and_score = filter_and_scoreq.all()

    logger.debug(f"got {len(filter_and_score)} matching Mitigations")
    mit_to_score = {mit: score for mit, score in filter_and_score}

    # fetch details of matching mitigations
    logger.debug("querying details for the earlier-matched Mitigations")
    result_subq = (
        db.session.query(
            Mitigation.mit_id,  # 0
            Mitigation.name,  # 1
            Mitigation.description,  # 2
            Mitigation.description,  # 3
            MitigationSource.source,  # 4
            MitigationSource.display_name,  # 5
            literal_column(search_tsqry).label("tsqry"),  # 6
        )
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.source, " ", "_")).in_(mitigation_sources)))
        .filter(Mitigation.mit_id.in_(list(mit_to_score.keys())))
    ).subquery()

    # generate highlights for ID, Name, Description

    # processing tech desc for ts_headline is easier to read as multiple stages
    s0 = PSQLTxt.unaccent("description")
    s1 = PSQLTxt.no_html(s0)
    s2 = PSQLTxt.no_citation_nums(s1)
    s3 = PSQLTxt.no_md_urls(s2)
    s4 = PSQLTxt.newlines_as_space(s3)
    tech_desc_processed = PSQLTxt.zwspace_pad_special(s4)

    tech_desc_headline = PSQLTxt.multiline_cleanup(
        f"""
        ts_headline(
            'english_nostop',
            {tech_desc_processed},
            tsqry,
            '
                HighlightAll=false,
                MinWords=1,
                MaxWords=16,
                MaxFragments=4,
                FragmentDelimiter=<red>...</red><br>,
                StartSel=<mark>,
                StopSel=</mark>
            '
        )
    """
    )

    result_q = (
        db.session.query(
            result_subq,
            # 6, 7, 8
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("mit_id"), "tsqry")).label("hl_id"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.unaccent("name"), "tsqry")).label("hl_name"),
            literal_column(tech_desc_headline).label("hl_desc")
        )
    ).all()
    logger.debug("query finished")

    # build response
    for (
        mit_id,
        mit_name,
        mit_desc,
        mit_url, #desc replica
        mit_src,
        mit_src_display_name,
        _,  # tsqry
        hl_id,
        hl_name,
        hl_desc,
    ) in result_q:
        # for ts_headlined descriptions - finish off any ... between snippets
        if len(hl_desc) > 50:
            tdesc = hl_desc.replace("<red>", '<span class="redtext">').replace("</red>", "</span>")

        # if no terms are matched in the description - get the first 250 chars, cut to last space, and add ... in red
        else:
            cleaned_desc = bleach.clean(markdown.markdown(mit_desc), tags=[], strip=True)[:250]
            cleaned_desc = cleaned_desc[: cleaned_desc.rfind(" ")]
            tdesc = f'{cleaned_desc}<span class="redtext">...</span>'

        results.append(
            {
                "mitigation": True,
                "mit_id": hl_id,
                "card_id_plain": mit_id,
                "mit_src_display_name": mit_src_display_name,
                "mitigation_name": hl_name,
                "mitigation_name_plain": mit_name,
                "description": tdesc,
                "attack_url": "http://localhost/test",
                "internal_url": url_for(
                    "mitigations_.mitigation_success", version=version, source=mit_src.lower(), mit_id=mit_id
                ),
                "score": mit_to_score[mit_id],
            }
        )
    
    return results

def mitigation_use_search(search_tsqry, mitigation_sources, version):
    results = []
    
    tsvec = PSQLTxt.multiline_cleanup(
        """
        technique_mitigation_map.tech_mit_use_ts 
    """
    )

    # filter Mitigations by Mitigation Source filters, then generate tsvecs for remaining
    logger.debug("querying Technqiue Mitigations Use filtered by Mitigation Source, and Technique Version selections and ranked by relevance")
    
    mit_subq = (
        db.session.query(
            technique_mitigation_map.c.uid,  # 0
            literal_column(tsvec).label("tsvec"),  # 1
            literal_column(search_tsqry).label("tsqry"),  # 2
        )
        .join(Mitigation, Mitigation.uid == technique_mitigation_map.c.mitigation)
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .join(Technique, Technique.uid == technique_mitigation_map.c.technique)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.source, " ", "_")).in_(mitigation_sources)))
        .filter(Technique.attack_version == version)
    ).subquery()    

    # get techniques matching search tsquery
    generate_existing = (db.session.query(mit_subq, literal_column("tsvec @@ tsqry").label("exists"))).subquery()

    # filter non-matching and get scores - returns IDs and their scores, pull into dict
    filter_and_scoreq = (
        db.session.query(
            generate_existing.c.uid,
            literal_column("ts_rank(tsvec, tsqry)").label("score"),
        ).filter(generate_existing.c.exists)
    )
    
    filter_and_score = filter_and_scoreq.all()

    print(f"got {len(filter_and_score)} matching Uses for Technique Mitigations")
    mit_to_score = {mit: score for mit, score in filter_and_score}

    # fetch details of matching mitigations
    print("querying details for the earlier-matched Uses for Technique Mitigation")
    result_subq = (
        db.session.query(
            technique_mitigation_map.c.uid,  # 0
            technique_mitigation_map.c.use,  # 1
            Technique.tech_id,  # 2
            Technique.tech_name,  # 3
            Mitigation.mit_id,  # 4
            Mitigation.name,  # 5
            MitigationSource.source,  # 7
            MitigationSource.display_name,  # 8
            literal_column(search_tsqry).label("tsqry"),  # 9
        )
        .join(Mitigation, Mitigation.uid == technique_mitigation_map.c.mitigation)
        .join(Technique, Technique.uid == technique_mitigation_map.c.technique)
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.source, " ", "_")).in_(mitigation_sources)))
        .filter(technique_mitigation_map.c.uid.in_(list(mit_to_score.keys())))
    ).subquery()

    # processing tech desc for ts_headline is easier to read as multiple stages
    s0 = PSQLTxt.unaccent("use")
    s1 = PSQLTxt.no_html(s0)
    s2 = PSQLTxt.no_citation_nums(s1)
    s3 = PSQLTxt.no_md_urls(s2)
    s4 = PSQLTxt.newlines_as_space(s3)
    mit_tech_use_processed = PSQLTxt.zwspace_pad_special(s4)

    mit_tech_use_headline = PSQLTxt.multiline_cleanup(
        f"""
        ts_headline(
            'english_nostop',
            {mit_tech_use_processed},
            tsqry,
            '
                HighlightAll=false,
                MinWords=1,
                MaxWords=16,
                MaxFragments=4,
                FragmentDelimiter=<red>...</red><br>,
                StartSel=<mark>,
                StopSel=</mark>
            '
        )
    """
    )

    result_q = (
        db.session.query(
            result_subq,
            # 10, 11, 12, 13, 14
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("mit_id"), "tsqry")).label("hl_mit_id"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.unaccent("name"), "tsqry")).label("hl_mit_name"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("tech_id"), "tsqry")).label("hl_tech_id"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.unaccent("tech_name"), "tsqry")).label("hl_tech_name"),
            literal_column(mit_tech_use_headline).label("hl_use")
        )
    ).all()

    logger.debug("query finished")

    # build response
    for (
        mit_tech_uid,
        mit_tech_use,
        tech_id,
        tech_name,
        mit_id,
        mit_name,
        mit_src,
        mit_src_display_name,
        _,  # tsqry
        hl_mit_id,
        hl_mit_name,
        hl_tech_id,
        hl_tech_name,
        hl_use,
    ) in result_q:
        # for ts_headlined descriptions - finish off any ... between snippets
        if len(hl_use) > 50:
            tdesc = hl_use.replace("<red>", '<span class="redtext">').replace("</red>", "</span>")

        # if no terms are matched in the description - get the first 250 chars, cut to last space, and add ... in red
        else:
            cleaned_desc = bleach.clean(markdown.markdown(hl_use), tags=[], strip=True)[:250]
            cleaned_desc = cleaned_desc[: cleaned_desc.rfind(" ")]
            tdesc = f'{cleaned_desc}<span class="redtext">...</span>'

        results.append(
            {
                "mitigation_use": True,
                "tech_id": hl_tech_id,
                "mit_id": hl_mit_id,
                "mit_src_display_name": mit_src_display_name,
                "card_id_plain": hl_tech_name+". "+hl_mit_name,
                "technique_name": hl_tech_name,
                "mitigation_name": hl_mit_name,
                "use_name_plain": hl_tech_name +"("+tech_id+")" + " - " + hl_mit_name +"("+ mit_id+")",
                "use": hl_use,
                "attack_url": "http://localhost/test",                
                "internal_url": url_for(
                    "mitigations_.mitigation_success", version=version, source=mit_src.lower(), mit_id=mit_id, _anchor=tech_id
                ),
                "score": mit_to_score[mit_tech_uid],
            }
        )
    
    return results

def usage_example_search(search_tsqry, mitigation_sources, version):
    results = []
    
    tsvec = PSQLTxt.multiline_cleanup(
        """
        blurb.blurb_ts 
    """
    )

    # filter Blurbs then generate tsvecs for remaining
    logger.debug("querying Usage Example selections and ranked by relevance")
    
    blurb_subq = (
        db.session.query(
            Blurb.uid,  # 0
            literal_column(tsvec).label("tsvec"),  # 1
            literal_column(search_tsqry).label("tsqry"),  # 2
        )
        .join(Technique, Technique.uid == Blurb.technique)
        .filter(Technique.attack_version == version)
    ).subquery()    

    # get techniques matching search tsquery
    generate_existing = (db.session.query(blurb_subq, literal_column("tsvec @@ tsqry").label("exists"))).subquery()

    # filter non-matching and get scores - returns IDs and their scores, pull into dict
    filter_and_scoreq = (
        db.session.query(
            generate_existing.c.uid,
            literal_column("ts_rank(tsvec, tsqry)").label("score"),
        ).filter(generate_existing.c.exists)
    )
    
    filter_and_score = filter_and_scoreq.all()

    print(f"got {len(filter_and_score)} matching Usage Examples")
    blurb_to_score = {blurb: score for blurb, score in filter_and_score}

    # fetch details of matching blurbs
    print("querying details for the earlier-matched Uses for Technique Mitigation")
    result_subq = (
        db.session.query(
            Blurb.uid,  # 0
            Blurb.sentence.regexp_replace('(<sup.*\\/sup>|\\(http.*?\\))', '', 'g').regexp_replace('([^\\[]*)\\[(.*?)\\](.*)', '\\2', 'g').label("use_threat_actor"), # 1
            Technique.tech_id, # 2
            Technique.tech_name, # 3
            Blurb.sentence,  # 4
        )
        .join(Technique, Technique.uid == Blurb.technique)
        .filter(Blurb.uid.in_(list(blurb_to_score.keys())))
    ).subquery()

    result_q = (
        db.session.query(
            result_subq
        )
    ).all()

    logger.debug("query finished")

    # build response
    for (
        uid,
        use_threat_actor,
        tech_id,
        tech_name,
        sentence,
    ) in result_q:
        # for ts_headlined descriptions - finish off any ... between snippets
        if len(use_threat_actor) > 50:
            tdesc = use_threat_actor.replace("<red>", '<span class="redtext">').replace("</red>", "</span>")

        # if no terms are matched in the description - get the first 250 chars, cut to last space, and add ... in red
        else:
            cleaned_desc = bleach.clean(markdown.markdown(sentence), tags=[], strip=True)[:250]
            cleaned_desc = cleaned_desc[: cleaned_desc.rfind(" ")]
            tdesc = f'{cleaned_desc}<span class="redtext">...</span>'

        results.append(
            {
                "card_id_plain": uid,
                "usage_example": True,
                "tech_id": tech_id,
                "technique_name": tech_name,
                "use": tdesc,    
                "actor": use_threat_actor,
                "internal_url": url_for(
                    "question_.notactic_success", version=version, subpath=tech_id.replace(".", "/")
                ),
                "score": blurb_to_score[uid],
            }
        )
    
    return results


@search_.route("/search/full", methods=["GET"])
@wrap_exceptions_as(ErrorDuringAJAXRoute)
def full_search():
    
    results = []
    g.route_title = "Full-Search"

    # get and validate parameters
    version = request.args.get("version")
    search_str = request.args.get("search")
    tactics = request.args.getlist("tactics")
    options = request.args.getlist("options")
    mitigation_sources = request.args.getlist("mitigation_sources")
    platforms = request.args.getlist("platforms")
    data_sources = request.args.getlist("data_sources")

    if not technique_search_args_are_valid(version, search_str, tactics, mitigation_sources, platforms, data_sources):
        # technique_search_args_are_valid has the error log action - this just shows a 400 will be sent
        logger.debug("request malformed - serving them a 400 code")
        return jsonify(message="Invalid search parameters"), 400

    # empty & too-long (arbitrary really) search cases
    if not search_str:
        logger.info("request skipped - no search query entered")
        return jsonify(status="Please type a search query"), 200
    elif len(search_str) > 512:
        logger.info("request skipped - query >512 characters long entered")
        return jsonify(status="Please type a shorter search query"), 200

    # parse the search string
    try:
        parsed_search = parse_search_str(search_str)

        # handled misformatting -> relay error msg
        if parsed_search.error is not None:
            logger.info("request skipped - they typed an invalid search query")
            return jsonify(status=parsed_search.error), 200

    # unexpected error -> generic response
    except Exception as e:
        logger.exception("request skipped - they typed an invalid search query (unexpected error)", exc_info=e)
        return jsonify(status="Unable to parse the provided search query"), 200

    search_tsqry = tsqry_rep(parsed_search.bool_expr, parsed_search.sym_to_term)

    print (options)
    if (options is None or len(options) == 0) or "techniques" in options:
        results.extend(technique_search(search_tsqry, tactics, version, platforms, data_sources))

    if (options is None or len(options) == 0) or "mitigations" in options:
        results.extend(mitigation_search(search_tsqry, mitigation_sources, version))
    
    if (options is None or len(options) == 0) or "mitigation_uses" in options:
        results.extend(mitigation_use_search(search_tsqry, mitigation_sources, version))
    
    if (options is None or len(options) == 0) or "usage_examples" in options:
        results.extend(usage_example_search(search_tsqry, mitigation_sources, version))
                
    # order by match score and then Tech ID
    results.sort(key=lambda t: (-t["score"])) #, float(t["card_id_plain"][1:])))
    
    # send results and what search was used for debugging purposes
    logger.info("sending search results")
    return jsonify(techniques=results, status=plain_rep(parsed_search.bool_expr, parsed_search.sym_to_term)), 200

@search_.route("/search/answer_cards", methods=["GET"])
@wrap_exceptions_as(ErrorDuringAJAXRoute)
def answer_card_search():
    """A more-powerful search of Answer Cards for non-start pages

    - MiniSearch only searches the context on the cards
      + this is fine for the question start page
    - Postgres Full Text Search searches Technique descriptions & sub-tech content too
      + this adds more search content to the succinct answer card content
    """
    g.route_title = "Answer Card Search"

    # -------- get arguments --------

    # location in tree
    version = request.args.get("version", "")
    tactic_context = request.args.get("tactic_context", "")
    index = request.args.get("index", "")

    # filter options
    platforms = request.args.getlist("platforms")
    data_sources = request.args.getlist("data_sources")

    # influences order / highlighting
    search = request.args.get("search", "").strip()

    # -------- validate arguments --------

    # version
    if not is_attack_version(version):  # format
        logger.error("Malformed ATT&CK version specified")
        return jsonify(message="ATT&CK version specified is malformed"), 400

    logger.debug(f"Checking existince of ATT&CK {version}")
    version_picker = VersionPicker(version)

    if not version_picker.is_valid:  # existence
        logger.error(f"Checking existince of ATT&CK {version} - doesn't exist")
        return jsonify(message="ATT&CK version specified is not on server"), 400

    logger.debug(f"Checking existince of ATT&CK {version} - it exists")
    version_model = version_picker.cur_version_model

    # index (format)
    if is_tact_id(index):  # Tactic -> Techs page
        parent_is_technique = False
    elif is_base_tech_id(index):  # Tech -> Subs page
        parent_is_technique = True
    else:
        logger.error("Question node index doesn't match Tactic or Base-Technique ID format")
        return jsonify(message="Question node requested is not a Tactic / Base-Technique"), 400

    # index (existence)
    if parent_is_technique:
        logger.debug(f"Querying existence of Technique {index} in {version}")
        tech_parent_uid = (
            db.session.query(Technique.uid)
            .filter(Technique.tech_id == index)
            .filter(Technique.attack_version == version)
        ).scalar()

        if tech_parent_uid is None:  # question node doesn't exist
            logger.error(f"Querying existence of Technique {index} in {version} - doesn't exist")
            return jsonify(message="Question node requested does not exist"), 400
        else:
            logger.debug(f"Querying existence of Technique {index} in {version} - it exists")

    else:  # parent is tactic
        tech_parent_uid = None

    # tactic_context
    if not is_tact_id(tactic_context):  # format
        logger.error("Tactic context ID is malformed")
        return jsonify(message="Tactic context specified is malformed"), 400

    logger.debug(f"Querying existence of Tactic {tactic_context} in {version}")
    if not (  # existence
        db.session.query(Tactic.uid).filter(Tactic.tact_id == tactic_context).filter(Tactic.attack_version == version)
    ).scalar():
        logger.error(f"Querying existence of Tactic {tactic_context} in {version} - doesn't exist")
        return jsonify(message="Tactic context specified doesn't exist"), 400
    logger.debug(f"Querying existence of Tactic {tactic_context} in {version} - it exists")

    # tactic_context / index (constraint)
    if (not parent_is_technique) and (index != tactic_context):  # index must = tactic_context if index is a tactic
        logger.error(
            f"index ({index}) and tactic_context ({tactic_context}) don't match, they should as index is a Tactic"
        )
        return jsonify(message="index and tactic_context must be equal if index is a Tactic"), 400

    # platforms (format, existence)
    logger.debug(f"Checking specified platforms against ATT&CK {version}")
    valid_platforms = {p.internal_name for p in version_model.platforms}
    specified_platforms = set(platforms)
    if len(specified_platforms) != len(specified_platforms.intersection(valid_platforms)):
        logger.error(f"Checking specified platforms against ATT&CK {version} - some are invalid")
        return jsonify(message="Invalid platforms specified"), 400
    logger.debug(f"Checking specified platforms against ATT&CK {version} - all are valid")

    # data_sources (format, existence)
    logger.debug(f"Checking specified data sources against ATT&CK {version}")
    valid_data_sources = {s.internal_name for s in version_model.data_sources}
    specified_data_sources = set(data_sources)
    if len(specified_data_sources) != len(specified_data_sources.intersection(valid_data_sources)):
        logger.error(f"Checking specified data sources against ATT&CK {version} - some are invalid")
        return jsonify(message="Invalid data sources specified"), 400
    logger.debug(f"Checking specified data sources against ATT&CK {version} - all are valid")

    # search (empty & overly-long limits)
    if not search:
        logger.info("request skipped - no search query entered")
        return jsonify(status="Search query empty"), 200
    elif len(search) > 512:
        logger.info("request skipped - query >512 characters long entered")
        return jsonify(status="Search query too long"), 200

    # parse the search string
    try:
        parsed_search = parse_search_str(search, joiner="|")

        # handled misformatting -> relay error msg
        if parsed_search.error is not None:
            logger.info("request skipped - they typed an invalid search query")
            return jsonify(status=parsed_search.error), 200

    # unexpected error -> generic response
    except Exception:
        logger.info("request skipped - they typed an invalid search query (unexpected error)")
        return jsonify(status="Unable to parse the provided search query"), 200

    search_tsqry = tsqry_rep(parsed_search.bool_expr, parsed_search.sym_to_term)

    # -------- perform search --------

    # get ans/desc vectors for answer cards and any cards under those as well (subquery)
    SubTechnique = aliased(Technique)
    card_vectors = (
        db.session.query(
            Technique.tech_id.label("upper_tid"),
            Technique.tech_ans_ts.label("upper_ans_vec"),
            Technique.tech_ts.label("upper_desc_vec"),
            func.array_remove(func.array_agg(distinct(SubTechnique.tech_ans_ts)), None).label("lower_ans_vecs"),
            func.array_remove(func.array_agg(distinct(SubTechnique.tech_ts)), None).label("lower_desc_vecs"),
        )
        .filter(Technique.attack_version == version)
        .group_by(Technique.uid)
        # limit scope to tactic context (less search-space for multi-tactic'd)
        .join(tactic_technique_map, Technique.uid == tactic_technique_map.c.technique)
        .join(Tactic, Tactic.uid == tactic_technique_map.c.tactic)
        .filter(Tactic.tact_id == tactic_context)
        # tech_parent_uid -> None: we get base techs
        # tech_parent_uid -> Tech: we get subs of Tech and Tech itself
        # no worry of getting None Tech.uid as it's a non-nullable field
        .filter(or_(Technique.parent_uid == tech_parent_uid, Technique.uid == tech_parent_uid))
        # filter on platforms if specified
        .outerjoin(technique_platform_map, Technique.uid == technique_platform_map.c.technique)
        .outerjoin(Platform, Platform.uid == technique_platform_map.c.platform)
        .filter(or_(not platforms, func.lower(func.replace(Platform.readable_name, " ", "_")).in_(platforms)))
        # filter on data sources if defined
        .outerjoin(technique_ds_map, Technique.uid == technique_ds_map.c.technique)
        .outerjoin(DataSource, DataSource.uid == technique_ds_map.c.data_source)
        .filter(or_(not data_sources, func.lower(func.replace(DataSource.readable_name, " ", "_")).in_(data_sources)))
        # only join subtech IDs if parent is a tactic
        .outerjoin(SubTechnique, and_(not parent_is_technique, SubTechnique.parent_uid == Technique.uid))
    ).subquery()

    # weights of these fields in search can be adjusted: from 'A'..'D', 'A' being most important
    # upper_ans_vec   : immediate answer card - answer content on card
    # upper_desc_vec  : immediate answer card - Technique description
    # lower_ans_vecs  : cards under card      - answer content on cards
    # lower_desc_vecs : cards under card      - Technique descriptions

    # generate vector for card + children, query for search (subquery)
    uid_vec_qry = (
        db.session.query(
            card_vectors.c.upper_tid,
            literal_column(
                """
                setweight(upper_ans_vec, 'A') ||
                setweight(upper_desc_vec, 'B') ||
                setweight(tsvector_agg(lower_ans_vecs), 'C') ||
                setweight(tsvector_agg(lower_desc_vecs), 'D')
            """.strip()
            ).label("tsvec"),
            literal_column(search_tsqry).label("tsqry"),
        )
    ).subquery()

    # determine what cards match the search (subquery)
    determine_matching = (
        db.session.query(uid_vec_qry, literal_column("tsvec @@ tsqry").label("does_match"))
    ).subquery()

    # keep cards matching search and score them
    logger.debug("starting search query to determine matching cards")
    filter_matching_score = (
        db.session.query(
            determine_matching.c.upper_tid, literal_column("ts_rank(tsvec, tsqry)").label("score")
        ).filter(determine_matching.c.does_match)
    ).all()
    logger.debug(f"query finished - got {len(filter_matching_score)} matching cards")

    result_info = {tech_id: {"score": score} for tech_id, score in filter_matching_score}

    # -------- generate terms to highlight --------

    # get content we searched within before
    get_searched_content = (
        db.session.query(
            Technique.tech_id,
            # displayed content
            literal_column(
                PSQLTxt.zwspace_pad_special(
                    "technique.tech_id || ' ' || technique.tech_name || ' ' || technique.tech_answer"
                )
            ).label("displayed_content"),
            # additional content
            Technique.tech_description,
            func.array_to_string(func.array_agg(distinct(SubTechnique.tech_description)), " ", "").label(
                "subs_desc_concat"
            ),
        )
        .filter(Technique.attack_version == version)
        # get original results
        .filter(Technique.tech_id.in_(list(result_info.keys())))
        .group_by(Technique.uid)
        # join children to these cards if they're techniques (question root is tactic)
        .outerjoin(SubTechnique, and_(not parent_is_technique, SubTechnique.parent_uid == Technique.uid))
    ).subquery()

    # cleanup content to pull headline terms from
    s0 = PSQLTxt.unaccent("tech_description || subs_desc_concat")
    s1 = PSQLTxt.no_html(s0)
    s2 = PSQLTxt.no_citation_nums(s1)
    s3 = PSQLTxt.no_md_urls(s2)
    s4 = PSQLTxt.newlines_as_space(s3)
    additional_content_processed = PSQLTxt.zwspace_pad_special(s4)

    # clean'n'combine the non-visible pieces of content
    clean_searched_content = (
        db.session.query(
            get_searched_content,
            literal_column(additional_content_processed).label("additional_content"),
            literal_column(search_tsqry).label("tsqry"),
        )
    ).subquery()

    # match smallest amount possible, up to 30 terms (sadly couldn't set 1-1 for only matches)
    headline_terms = PSQLTxt.multiline_cleanup(
        """
        ts_headline(
            'english_nostop',
            {},
            tsqry,
            '
                HighlightAll=false,
                MinWords=1,
                MaxWords=2,
                MaxFragments=30,
                FragmentDelimiter=...,
                StartSel=___,
                StopSel=___
            '
        )
    """
    )

    # get term matches + clear null if present
    logger.debug("starting query to get matched terms")
    generate_headlines = (
        db.session.query(
            clean_searched_content.c.tech_id,
            literal_column(f"coalesce({headline_terms.format('displayed_content')}, '')").label("displayed_matches"),
            literal_column(f"coalesce({headline_terms.format('additional_content')}, '')").label("additional_matches"),
        )
    ).all()
    logger.debug("query finished")

    # process all techniques - adding the in-card and off-card matches to the response
    for tech_id, display_match_str, additional_match_str in generate_headlines:
        display_matches = set(re.findall("___(.+?)___", display_match_str.lower()))
        additional_matches = set(re.findall("___(.+?)___", additional_match_str.lower()))
        additional_matches = additional_matches - display_matches  # only mention unique additional matches
        result_info[tech_id]["display_matches"] = list(display_matches)
        result_info[tech_id]["additional_matches"] = list(additional_matches)

    # send match scores / highlights and how search was interpreted
    logger.info("sending search result scores & highlights to user")
    return jsonify(results=result_info, status=plain_rep(parsed_search.bool_expr, parsed_search.sym_to_term)), 200
