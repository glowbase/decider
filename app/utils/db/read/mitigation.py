from app.models import db, Mitigation, MitigationSource, Technique, technique_mitigation_map
from sqlalchemy import and_, func

import app.utils.db.read as db_read


def mit_id_to_uid(version):
    tech_ids_uids = (
        db.session.query(Mitigation.mit_id, Mitigation.uid)
        .join(MitigationSource, Mitigation.mitigation_source == MitigationSource.uid)
        .filter(MitigationSource.attack_version == version)
    ).all()
    return {tid: uid for tid, uid in tech_ids_uids}

def mit_src_to_uid(version):
    src_uids = (
        db.session.query(MitigationSource.source, MitigationSource.uid)
        .filter(MitigationSource.attack_version == version)
    ).all()
    return {src: uid for src, uid in src_uids}

def mit_src(source):
    return db.session.query(MitigationSource).filter(func.lower(MitigationSource.source) == source.lower()).first()