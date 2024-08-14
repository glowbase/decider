from app.models import (
    db,
    Technique,
    technique_mitigation_map,
    Mitigation,
    AttackVersion,
)

from sqlalchemy import and_

import app.utils.db.read as db_read
import app.utils.db.create as db_create

from app.utils.db.util import messaged_timer

from collections import defaultdict

mitigation_sets = ["ism", "remediation", "nist"]

@messaged_timer("Building Mitigations table")
def mitigations_table(version, src_mgr):

    # query data components from ATT&CK
    mitigation_mappings: dict = src_mgr.mitigations[version].get_data()
    mitigation_list = []

    mitigation_rows = []
    # determine where they'll be inserted
    next_mitigation_uid = db_read.util.max_primary_key(Mitigation.uid) + 1
    uid_offset = 0

    for ms in mitigation_sets:
        mitigations =  [i[ms] for i in mitigation_mappings.values() if len(i[ms]) > 0]

        # create the data components
        for index, mtgs in enumerate(mitigations):
            for mtg in mtgs:
                internal_name = mtg["code"]
                if internal_name in mitigation_list:
                    continue

                mitigation_rows.append(
                    {
                        # fmt: off
                        "uid"           : next_mitigation_uid + uid_offset,
                        "attack_version": version,
                        "mit_id"        : internal_name,
                        "section"     : mtg["section"],
                        "description" : mtg["description"],
                        "url"         : mtg["url"],
                        # fmt: on
                    }
                )

                mitigation_list.append(internal_name)
                uid_offset += 1

    # insert them
    db.session.bulk_insert_mappings(Mitigation, mitigation_rows, render_nulls=True)
    db.session.commit()


@messaged_timer("Building Mitigations <-> Technique map")
def tech_mitigations_map(version, src_mgr):

    # get DataComponent -detects-> Technique rels
    mitigations: dict = src_mgr.mitigations[version].get_data()

    ism_rels = [
        # fmt: off
        i
        for i in mitigations.values()
        if len(i["ism"]) > 0
        # fmt: on
    ]

    # get DB UID resolvers for Technique and DataComponent
    tech_id_to_uid = db_read.attack.tech_id_to_uid(version)
    mitigation_id_to_uid = db_read.mitigation.mit_id_to_uid(version)

    # for all ATT&CK Technique <-> Mitigtaion mappings
    tech_mit_map_rows = []
    for tech_mit in ism_rels:

        # get UID of Technique in relationship
        tech_id = tech_mit["technique"]
        tech_uid = tech_id_to_uid.get(tech_id)

        for ms in mitigation_sets:
            for mit in tech_mit[ms]:
                # get UID of DataComponent in relationship
                mit_id = mit["code"]
                mit_uid = mitigation_id_to_uid.get(mit_id)

                # if both Tech and DataComp exist in DB for this version, add their mapping
                if tech_uid and mit_uid:
                    tech_mit_map_rows.append({"technique": tech_uid, "mitigation": mit_uid})

    # insert them
    db.session.execute(technique_mitigation_map.insert().values(tech_mit_map_rows))
    db.session.commit()

def add_version(version, src_mgr):
    # mitigations
    db_create.mitigation.mitigations_table(version, src_mgr)

    # Data Components & Sources for ATT&CK 10+
    base_version_num = int(version.replace("v", "").split(".")[0])  # [8], v[8], v[9], v[9].1, v[9].2
    if base_version_num >= 15:
        db_create.mitigation.tech_mitigations_map(version, src_mgr)
