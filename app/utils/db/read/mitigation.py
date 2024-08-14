from app.models import db, Mitigation


def mit_id_to_uid(version):
    tech_ids_uids = (
        db.session.query(Mitigation.mit_id, Mitigation.uid).filter(Mitigation.attack_version == version)
    ).all()
    return {tid: uid for tid, uid in tech_ids_uids}
