from app.models import db, Mitigation, Technique, technique_mitigation_map
from sqlalchemy import and_

import app.utils.db.read as db_read


def mit_id_to_uid(version):
    tech_ids_uids = (
        db.session.query(Mitigation.mit_id, Mitigation.uid).filter(Mitigation.attack_version == version)
    ).all()
    return {tid: uid for tid, uid in tech_ids_uids}

def mit_for_tech_id(version, tech_id):
    mitigations = (
        db.session.query(Mitigation)
        .filter(Mitigation.attack_version == version)
        .join(technique_mitigation_map, Mitigation.uid == technique_mitigation_map.c.mitigation)
        .join(Technique, technique_mitigation_map.c.technique == Technique.uid)
        .filter(Technique.tech_id == tech_id)
    ).all()

    return [
        {
            "uid": m.uid,
            "attack_version": m.attack_version,
            "mit_id": m.mit_id,
            "section": m.section,
            "url": m.url,
            "description": m.description,
            "source": m.source,
        }
        for m in mitigations
    ]