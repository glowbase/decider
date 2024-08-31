from . import postbuild

from app.models import (
    db,
    Technique,
    technique_mitigation_map,
    Mitigation,
    MitigationSource,
    AttackVersion,
)

from sqlalchemy import and_

import app.utils.db.read as db_read
import app.utils.db.create as db_create

from app.utils.db.util import messaged_timer

from collections import defaultdict

@messaged_timer("Building MitigationSource table")
def mitigation_sources_table(version, src_mgr):
        # query data components from ATT&CK
        mitigation_sources = src_mgr.mitigation_sources.get_data()[version]
        source_rows = []
    
        # determine where they'll be inserted
        next_mitigation_source_uid = db_read.util.max_primary_key(MitigationSource.uid) + 1
        uid_offset = 0
    
        # create the data components
        for mtg in mitigation_sources:
            source_rows.append(
                {
                    # fmt: off
                    "uid"           : next_mitigation_source_uid + uid_offset,
                    "source"        : mtg["source"],
                    "name"          : mtg["name"],
                    "description"   : mtg["description"],
                    "display_name"  : mtg["display_name"],
                    "url"           : mtg["url"],
                    "attack_version": version,
                    # fmt: on
                }
            )
            uid_offset += 1
    
        # insert them
        db.session.bulk_insert_mappings(MitigationSource, source_rows, render_nulls=True)
        db.session.commit()

@messaged_timer("Building Mitigations table")
def mitigations_table(version, src_mgr):

    # query data components from ATT&CK
    mitigation_mappings: dict = src_mgr.mitigations[version].get_data()
    mitigation_list = []
    mitigation_rows = []

    # determine where they'll be inserted
    next_mitigation_uid = db_read.util.max_primary_key(Mitigation.uid) + 1
    mitigation_sources_id_to_uid = db_read.mitigation.mit_src_to_uid(version)
    uid_offset = 0

    # create the data components
    for index, mit_id in enumerate(mitigation_mappings):
        mtg = mitigation_mappings[mit_id]
        mtg_source = mtg["source"]

        mitigation_rows.append(
            {
                # fmt: off
                "uid"           : next_mitigation_uid + uid_offset,
                "name"          : mtg["name"],
                "attack_version": version,
                "mit_id"        : mit_id,
                "mitigation_source" : mitigation_sources_id_to_uid[mtg_source],
                "description"   : mtg["description"],
                # fmt: on
            }
        )

        mitigation_list.append(mit_id)
        uid_offset += 1

    # insert them
    db.session.bulk_insert_mappings(Mitigation, mitigation_rows, render_nulls=True)
    db.session.commit()


@messaged_timer("Building Mitigations <-> Technique map")
def tech_mitigations_map(version, src_mgr):

    # get DataComponent -detects-> Technique rels
    mitigations: dict = src_mgr.mitigations[version].get_data()

    next_technique_mitigation_uid = db_read.util.max_primary_key(technique_mitigation_map.c.uid) + 1
    uid_offset = 0
    # get DB UID resolvers for Technique and DataComponent
    tech_id_to_uid = db_read.attack.tech_id_to_uid(version)
    mitigation_id_to_uid = db_read.mitigation.mit_id_to_uid(version)

    # for all ATT&CK Technique <-> Mitigtaion mappings
    tech_mit_map_rows = []
    for index, mit_id in enumerate(mitigations):
        mit = mitigations[mit_id]
        if "techniques" not in mit:
            continue

        for tech_id in mit["techniques"]:
            tech_mit_use = mit["techniques"][tech_id]
            
            # get UID of Technique in relationship
            tech_uid = tech_id_to_uid.get(tech_id)

            # get UID of DataComponent in relationship
            mit_uid = mitigation_id_to_uid.get(mit_id)

            # if both Tech and DataComp exist in DB for this version, add their mapping
            if tech_uid and mit_uid:
                tech_mit_map_rows.append({"uid": next_technique_mitigation_uid+uid_offset ,"technique": tech_uid, "mitigation": mit_uid, "use": tech_mit_use["use"]})
                uid_offset += 1

    # insert them
    db.session.execute(technique_mitigation_map.insert().values(tech_mit_map_rows))
    db.session.commit()

def add_version(version, src_mgr):
    # mitigations
    db_create.mitigation.mitigation_sources_table(version, src_mgr)
    db_create.mitigation.mitigations_table(version, src_mgr)

    # Data Components & Sources for ATT&CK 10+
    base_version_num = int(version.replace("v", "").split(".")[0])  # [8], v[8], v[9], v[9].1, v[9].2
    if base_version_num >= 15:
        db_create.mitigation.tech_mitigations_map(version, src_mgr)

    # Ensures generated TS vector and index exists for Mitigations and Mitigation Uses
    db_create.mitigation.postbuild.add_mitigation_search_index()
    db_create.mitigation.postbuild.add_technique_mitigation_use_search_index()