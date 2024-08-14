import json
import os
import app.constants as constants

from flask_login import current_user
from sqlalchemy import asc, func, distinct, and_, or_, literal_column
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm.util import aliased
from app.utils.db.read import mitigation

class MitigationsService(object):
  def __new__(cls):
    if not hasattr(cls, 'instance'):
      cls.instance = super(MitigationsService, cls).__new__(cls)
    return cls.instance
  
  def get_mitigations(self, technique, attack_version):
    return mitigation.mit_for_tech_id(attack_version, technique)