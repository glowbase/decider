import json

class MitigationsService(object):
  def __new__(cls):
    if not hasattr(cls, 'instance'):
      cls.instance = super(MitigationsService, cls).__new__(cls)
    return cls.instance
  
  def get_mitigations(self, technique):
    path = "./config/build_sources/mappings"
    with open(f'{path}/mappings.json') as mappings_file:
        mappings_data = json.load(mappings_file)
      
    return_value = mappings_data[technique] if technique in mappings_data else []
    return return_value