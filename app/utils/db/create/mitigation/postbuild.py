from app.models import db

from app.utils.db.util import messaged_timer

@messaged_timer("Creating index for Mitigations search")
def add_mitigation_search_index():
    # remove and remake ts_vec and index it
    # 1. imm_unaccent(mitigation.name)
    #    unaccent - useful for 'doppelganging'
    # 2. imm_unaccent(mitigation.description)
    #    unaccent - useful for 'doppelganging'
    # 3. regexp_replace(__1__, '[^a-z0-9 ]+', ' ', 'gi')
    #    all non A-z0-9/space -> ' '
    db.session.execute(
        r"""
    DROP INDEX IF EXISTS mit_ts_index;
    ALTER TABLE mitigation DROP COLUMN IF EXISTS mit_ts;

    ALTER TABLE mitigation ADD COLUMN mit_ts tsvector
        GENERATED ALWAYS AS
            (setweight(to_tsvector('english_nostop',
            imm_unaccent(mitigation.name)), 'A') ||
            setweight(to_tsvector('english_nostop',
            imm_unaccent(mitigation.description)), 'B') ||
            setweight(to_tsvector('english_nostop',
            regexp_replace(mitigation.mit_id, '[^a-z0-9 ]+', ' ', 'gi')), 'B')) STORED;
    CREATE INDEX mit_ts_index ON mitigation USING gist(mit_ts);
    """.strip()
    )
    db.session.commit()

@messaged_timer("Creating index for Technique Mitigation Uses search")
def add_technique_mitigation_use_search_index():
    # remove and remake ts_vec and index it
    # 1. imm_unaccent(technique_mitigation_map.use)
    #    unaccent - useful for 'doppelganging'
    db.session.execute(
        r"""
    DROP INDEX IF EXISTS tech_mit_use_ts_index;
    ALTER TABLE technique_mitigation_map DROP COLUMN IF EXISTS tech_mit_use_ts;

    ALTER TABLE technique_mitigation_map ADD COLUMN tech_mit_use_ts tsvector
        GENERATED ALWAYS AS
            (setweight(to_tsvector('english_nostop',
            imm_unaccent(technique_mitigation_map.use)), 'A')) STORED;
    CREATE INDEX tech_mit_use_ts_index ON technique_mitigation_map USING gist(tech_mit_use_ts);
    """.strip()
    )
    db.session.commit()
