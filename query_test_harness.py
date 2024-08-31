from flask import Flask

from app.models import db
from app.utils.db.source_loader import SourceManager
import app.utils.db.create as db_create
import app.utils.db.destroy as db_destroy
import app.utils.db.read as db_read
from app.utils.db.util import app_config_selector
from sqlalchemy import REAL, literal_column, String, or_, and_

from app.domain import PSQLTxt
import sqlalchemy as sqlalch
from operator import and_
from flask import Blueprint, redirect, render_template, current_app, g, url_for
from app.models import (
    AttackVersion,
    Platform,
    db,
    Tactic,
    Technique,
    Aka,
    Mismapping,
    Blurb,
    Mitigation,
    MitigationSource,
)

from app.models import (
    technique_aka_map,
    technique_platform_map,
    tactic_technique_map,
    technique_mitigation_map,
)

from app.env_vars import (
    DB_PORT,
    DB_DATABASE,
    DB_ADMIN_NAME,
    DB_ADMIN_PASS,
)

from sqlalchemy import asc, func, distinct
from sqlalchemy.orm import aliased
from sqlalchemy.dialects.postgresql import array


def main():
    config = "DefaultConfig"

    app_config = app_config_selector(config)
    
    app_config.SQLALCHEMY_DATABASE_URI = sqlalch.engine.URL.create(
        drivername="postgresql",
        username=DB_ADMIN_NAME,
        password=DB_ADMIN_PASS,
        host="localhost",
        port=DB_PORT,
        database=DB_DATABASE,
    )
    
    app = Flask(__name__)
    app.config.from_object(app_config)
    db.init_app(app)
    
    with app.app_context():
        test_technique_mitigation_use_ts()

def test_technique_mitigation_use_ts():
    tsvec = "technique_mitigation_map.tech_mit_use_ts"
    mitigation_sources = ['mitre', 'nist']
    version ="v15.1"
    search_tsqry = "(to_tsquery('english_nostop', 'account') && to_tsquery('english_nostop', 'attempt'))"
    mit_subq = (
        db.session.query(
            technique_mitigation_map.c.uid,  # 0
            literal_column(tsvec).label("tsvec"),  # 1
            literal_column(search_tsqry).label("tsqry"),  # 2
        )
        .join(Mitigation, Mitigation.uid == technique_mitigation_map.c.mitigation)
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .join(Technique, Technique.uid == technique_mitigation_map.c.technique)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.name, " ", "_")).in_(mitigation_sources)))
        .filter(Technique.attack_version == version)
    )    

    print (str(mit_subq.statement))
    # get techniques matching search tsquery
    generate_existing = (db.session.query(mit_subq.subquery(), literal_column("tsvec @@ tsqry").label("exists"))).subquery()

    # filter non-matching and get scores - returns IDs and their scores, pull into dict
    filter_and_scoreq = (
        db.session.query(
            generate_existing.c.uid,
            literal_column("ts_rank(tsvec, tsqry)").label("score"),
        ).filter(generate_existing.c.exists)
    )
        
    filter_and_score = filter_and_scoreq.all()

    print(f"got {len(filter_and_score)} matching Usees for Technique Mitigations")
    print(str(filter_and_scoreq.statement))
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
            literal_column(search_tsqry).label("tsqry"),  # 6
        )
        .join(Mitigation, Mitigation.uid == technique_mitigation_map.c.mitigation)
        .join(Technique, Technique.uid == technique_mitigation_map.c.technique)
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.name, " ", "_")).in_(mitigation_sources)))
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
            # 6, 7, 8, 9, 10
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("mit_id"), "tsqry")).label("hl_mit_id"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.unaccent("name"), "tsqry")).label("hl_mit_name"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("tech_id"), "tsqry")).label("hl_tech_id"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.unaccent("tech_name"), "tsqry")).label("hl_tech_name"),
            literal_column(mit_tech_use_headline).label("hl_use")
        )
    ).all()

    print(str(result_q))

def test_mitigation_ts():
    tsvec = "mitigation.mit_ts"
    search_tsqry = "(to_tsquery('english_nostop', 'account') && to_tsquery('english_nostop', 'attempt'))"
    mitigation_sources = ['mitre', 'nist']
    mit_subq = (
        db.session.query(
            Mitigation.mit_id,  # 0
            literal_column(tsvec).label("tsvec"),  # 1
            literal_column(search_tsqry).label("tsqry"),  # 2
        )
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.name, " ", "_")).in_(mitigation_sources)))
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

    print(f"got {len(filter_and_score)} matching Mitigations")
    mit_to_score = {mit: score for mit, score in filter_and_score}

    # fetch details of matching mitigations
    print("querying details for the earlier-matched Mitigations")
    result_subq = (
        db.session.query(
            Mitigation.mit_id,  # 0
            Mitigation.name,  # 1
            Mitigation.description,  # 2
            Mitigation.description,  # 3
            literal_column(search_tsqry).label("tsqry"),  # 4
        )
        .join(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .filter(or_(not mitigation_sources, func.lower(func.replace(MitigationSource.name, " ", "_")).in_(mitigation_sources)))
        .filter(Mitigation.mit_id.in_(list(mit_to_score.keys())))
        .group_by(Mitigation.uid)
    ).subquery()

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
            # 5, 6, 7
            literal_column(PSQLTxt.basic_headline(PSQLTxt.zwspace_pad_special("mit_id"), "tsqry")).label("hl_id"),
            literal_column(PSQLTxt.basic_headline(PSQLTxt.unaccent("name"), "tsqry")).label("hl_name"),
            literal_column(tech_desc_headline).label("hl_desc")
        )
    )

    print(str(result_q.statement))

def test_mitigation_join():
    q = (
        db.session.query(
            Technique,  # 0
            func.array_agg(distinct(array([Tactic.tact_id, Tactic.tact_name]))),  # 1
            func.array_agg(distinct(Platform.readable_name)),  # 2
            func.array_remove(func.array_agg(distinct(Aka.term)), None),  # 3
            func.array_agg(distinct(array([Mitigation.mit_id, MitigationSource.source, MitigationSource.display_name, MitigationSource.url, Mitigation.name, Mitigation.description, technique_mitigation_map.c.use]))),  # 4

        )
        .filter(
            and_(
                Technique.attack_version == "v15.1",
                Technique.tech_id == "T1552.003",
            )
        )
        .join(tactic_technique_map, tactic_technique_map.c.technique == Technique.uid)
        .join(Tactic, Tactic.uid == tactic_technique_map.c.tactic)
        .outerjoin(technique_platform_map, technique_platform_map.c.technique == Technique.uid)
        .outerjoin(Platform, Platform.uid == technique_platform_map.c.platform)
        .outerjoin(technique_aka_map, technique_aka_map.c.technique == Technique.uid)
        .outerjoin(Aka, technique_aka_map.c.aka == Aka.uid)
        .outerjoin(technique_mitigation_map, technique_mitigation_map.c.technique == Technique.uid)
        .outerjoin(Mitigation, Mitigation.uid == technique_mitigation_map.c.mitigation)
        .outerjoin(MitigationSource, MitigationSource.uid == Mitigation.mitigation_source)
        .group_by(Technique.uid)
    )

    _, tact_ids_names, platforms, akas, mitigation = q.first()

    print(mitigation)
    print(f"got {len(tact_ids_names)} Tactics, {len(platforms)} Platforms, {len(akas)} AKAs, and {len(mitigation)} Mitigations")
    
if __name__ == "__main__":
    main()