import json
import os
import app.constants as constants

from flask_login import current_user
from sqlalchemy import asc, func, distinct, and_, or_, literal_column
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm.util import aliased

class MitigationsService(object):
  def __new__(cls):
    if not hasattr(cls, 'instance'):
      cls.instance = super(MitigationsService, cls).__new__(cls)
    return cls.instance
  
  def get_mitigations(self, technique, attack_version):
    with open(f'{os.path.join(constants.BUILD_SOURCES_DIR, constants.mitigations_mapping_dir, constants.mitigations_mapping_file_base)}-{attack_version}.json') as mappings_file:
        mappings_data = json.load(mappings_file)
      
    return_value = mappings_data[technique] if technique in mappings_data else []
    return return_value