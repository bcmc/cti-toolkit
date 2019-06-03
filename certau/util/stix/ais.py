
from stix.extensions.marking import ais
from stix.common.information_source import InformationSource
from pymisp.tools.abstractgenerator import AbstractMISPObjectGenerator
import os, logging
#from pymisp.tools import GenericObjectGenerator
#from pymisp.mispevent import MISPObject

from .helpers import dereference_observables

def ais_refactor(package, proprietary, consent, color, organisation, industry,
                 country, admin_area):
    """Refactor a STIX package to meet AIS requirements."""
    # Add an AIS Marking to the header
    # Note add_ais_marking() removes existing markings
    ais.add_ais_marking(
        stix_package=package,
        proprietary=proprietary,
        consent=consent,
        color=color,
        country_name_code=country,
        industry_type=industry,
        admin_area_name_code=admin_area,
        organisation_name=organisation,
        country_name_code_type='ISO-3166-1_alpha-2',
        admin_area_name_code_type='ISO-3166-2',
    )
    # Dereference observables
    dereference_observables(package)
    # Remove the observables from the root of the package
    package.observables = None

AIS_MARKINGS = {'ais-marking:AISConsent="EVERYONE"',
                'ais-marking:AISConsent="NONE"',
                'ais-marking:AISConsent="USG"',
                'ais-marking:AISMarking="Is_Proprietary"',
                'ais-marking:AISMarking="Not_Proprietary"',
                'ais-marking:CISA_Proprietary="false"',
                'ais-marking:CISA_Proprietary="true"',
                'ais-marking:TLPMarking="AMBER"',
                'ais-marking:TLPMarking="GREEN"',
                'ais-marking:TLPMarking="WHITE"'}

AIS_FORMAT =     {'AISConsent'          :'ais-marking:AISConsent="{}"',
                  'AISMarking'          :'ais-marking:AISMarking="{}"',
                  'CISA_Proprietary'    :'ais-marking:CISA_Proprietary="{}"',
                  'TLPMarking'          :'ais-marking:TLPMarking="{}"',
                  'admin_area_code'     :'ais-info:AISAdminAreaNameCode="{}"',
                  'admin_area_code_type':'ais-info:AISAdminAreaNameCodeType="ISO-3166-2"',
                  'country_code'        :'ais-info:AISCountryNameCode="{}"',
                  'country_code_type'   :'ais-info:AISCountryNameCodeType="ISO-3166-1_alpha-2"',
                  'industry_type'       :'ais-info:AISIndustryType="{}"',
                  'org_name'            :'ais-info:AISOrganizationName="{}"'
                  }

AIS_INFO_OBJECT_RELATIONS = {
                'admin_area_code'     :'administrative-area',
                'country_code'        :'country',
                'industry_type'       :'industry',
                'org_name'            :'organisation',
    }

INDUSTRY_TYPE = {
 'chemical sector'                              : 'Chemical Sector',
 'commercial facilities sector'                 : 'Commercial Facilities Sector',
 'communications sector'                        : 'Communications Sector',
 'critical manufacturing sector'                : 'Critical Manufacturing Sector',
 'dams sector'                                  : 'Dams Sector',
 'defense industrial base sector'               : 'Defense Industrial Base Sector',
 'emergency services sector'                    : 'Emergency Services Sector',
 'energy sector'                                : 'Energy Sector',
 'financial services sector'                    : 'Financial Services Sector',
 'food and agriculture sector'                  : 'Food and Agriculture Sector',
 'government facilities sector'                 : 'Government Facilities Sector',
 'healthcare and public health sector'          : 'Healthcare and Public Health Sector',
 'information technology sector'                : 'Information Technology Sector',
 'nuclear reactors, materials, and waste sector': 'Nuclear Reactors, Materials, and Waste Sector',
 'transportation systems sector'                : 'Transportation Systems Sector',
 'water and wastewater systems sector'          : 'Water and Wastewater Systems Sector',
 'other'                                        : 'Other'
    }
class ais_markings():
#   marking_set = set()
#    info_set = set()
#    info_list = []


    def __init__(self, package):
        """Retrieves the STIX package AIS (str) from the header."""
        self.marking_set = set()
        self.info_list = []
        self.ais_info_object = None
        if package.stix_header:
            handling = package.stix_header.handling
            if handling and handling.marking:
                for marking_spec in handling.marking: #Expects only 1 loop
                    for marking_struct in marking_spec.marking_structures:
                        if isinstance(marking_struct, ais.AISMarkingStructure):
                            self.ais_proprietary(marking_struct)
                    if isinstance(marking_spec.information_source, InformationSource):
                        self.ais_info_source(marking_spec.information_source)
                        self.ais_info_object = AISInfoObject(self.info_list)
                    elif isinstance(package.stix_header.information_source, InformationSource): #outbound format
                        outbound = package.stix_header.information_source.contributing_sources.source
                        if outbound and len(outbound)>0:
                            self.ais_info_source(package.stix_header.information_source.contributing_sources.source[0])
                            self.ais_info_object = AISInfoObject(self.info_list)
                        else:
                            logging.warning("Did not find contributing_sources.source in AIS information source structure in outbound STIX file")
                    else:
                        logging.warning("Did not find AIS information source structure in STIX file")
                        
                        
    def ais_proprietary(self, marking_struct):
        if marking_struct.is_proprietary:
            proprietary_struct = marking_struct.is_proprietary
            self.marking_set.add('ais-marking:AISMarking="Is_Proprietary"')
        elif marking_struct.not_proprietary:
            proprietary_struct = marking_struct.not_proprietary
            self.marking_set.add('ais-marking:AISMarking="Not_Proprietary"')
            
        if proprietary_struct:
            if proprietary_struct.cisa_proprietary is not None: #cisa_proprietary is a bool
                self.marking_set.add( 'ais-marking:CISA_Proprietary="{}"'.
                                      format(str(proprietary_struct.cisa_proprietary).lower()))
            if proprietary_struct.tlp_marking:
                self.marking_set.add( 'ais-marking:TLPMarking="{}"'.
                                      format(proprietary_struct.tlp_marking.color.upper()))
            if proprietary_struct.ais_consent:
                self.marking_set.add( 'ais-marking:AISConsent="{}"'.
                                      format(proprietary_struct.ais_consent.consent.upper()))
    def ais_info_source(self, info_struct):
        if info_struct.identity.specification:
            identity = info_struct.identity.specification
            if identity: #.party_name.organisation_names[0].name_elements[0].value:
                if identity.party_name:
                    if identity.party_name.organisation_names:
                        if identity.party_name.organisation_names[0].name_elements:
                            if identity.party_name.organisation_names[0].name_elements[0].value:
                                org_name = identity.party_name.organisation_names[0].name_elements[0].value
                                self.info_list.append((AIS_INFO_OBJECT_RELATIONS['org_name'], org_name))
            if identity.addresses:
                if identity.addresses[0].country:
                    if identity.addresses[0].country.name_elements:
                        if identity.addresses[0].country.name_elements[0].name_code:
                            country_code = identity.addresses[0].country.name_elements[0].name_code
                            self.info_list.append((AIS_INFO_OBJECT_RELATIONS['country_code'], country_code))
#                        if identity.addresses[0].country.name_elements[0].name_code_type:
#                            country_code_type = identity.addresses[0].country.name_elements[0].name_code_type
                if identity.addresses[0].administrative_area:
                    if identity.addresses[0].administrative_area.name_elements:
                        if identity.addresses[0].administrative_area.name_elements[0].name_code:
                            admin_area_code = identity.addresses[0].administrative_area.name_elements[0].name_code
                            self.info_list.append((AIS_INFO_OBJECT_RELATIONS['admin_area_code'], admin_area_code))
#                        if identity.addresses[0].administrative_area.name_elements[0].name_code_type:
#                            admin_area_code_type = identity.addresses[0].administrative_area.name_elements[0].name_code_type
            if identity.organisation_info:
                if identity.organisation_info.industry_type:
                    industry_type = identity.organisation_info.industry_type
                    if '|' in str(industry_type):
                        list_industry = str(industry_type).split('|')
                        for ind in list_industry:
                            ind_strip = ind.strip().lower()
                            if ind_strip in INDUSTRY_TYPE:
                                self.info_list.append((AIS_INFO_OBJECT_RELATIONS['industry_type'], INDUSTRY_TYPE[ind_strip]))
                            else:
                                logging.warning("Found invalid industry type: " + ind_strip)
                    elif str(industry_type).lower() in INDUSTRY_TYPE:
                        self.info_list.append((AIS_INFO_OBJECT_RELATIONS['industry_type'], INDUSTRY_TYPE[str(industry_type).lower()]))

        
class AISInfoObject(AbstractMISPObjectGenerator):
    def __init__(self, list_tuple_pairs, 
                 custom_path= os.path.dirname(os.path.realpath(__file__))):
        super(AISInfoObject, self).__init__("ais-info", 
                                            misp_objects_path_custom=custom_path)
        logging.debug("AIS-info object path: "+ custom_path)
        self.__attributes = list_tuple_pairs
        self.generate_attributes(self.__attributes)
        
    def generate_attributes(self, list_attributes):
        for object_relation, value in list_attributes:
            self.add_attribute(object_relation, value=value)
    def get_template_id(self, misp, template_name= "ais-info"):
        try:
            template_id = [x['ObjectTemplate']['id'] for x in misp.get_object_templates_list() if x['ObjectTemplate']['name'] == template_name][0]
            return template_id
        except IndexError:
            valid_types = ", ".join([x['ObjectTemplate']['name'] for x in misp.get_object_templates_list()])
            logging.error("MISP Object Template for type %s not found on MISP Instance! Valid types are: %s" % (template_name, valid_types))
                        