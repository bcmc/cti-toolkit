
from stix.extensions.marking import ais
from stix.common.information_source import InformationSource
from pymisp.tools.abstractgenerator import AbstractMISPObjectGenerator
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
                'admin_area_code'     :'adminarea',
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
    def get_set(self):
        return self.marking_set
    def get_info_list(self):
        return self.info_list

    def __init__(self, package):
        """Retrieves the STIX package AIS (str) from the header."""
        self.marking_set = set()
        self.info_set = set()
        self.info_list = []
        if package.stix_header:
            handling = package.stix_header.handling
            if handling and handling.marking:
                for marking_spec in handling.marking: #Expects only 1 loop
                    for marking_struct in marking_spec.marking_structures:
                        if isinstance(marking_struct, ais.AISMarkingStructure):
                            self.ais_proprietary(marking_struct)
                    if isinstance(marking_spec.information_source, InformationSource):
                        print("Found information_source structure")
                        self.ais_info_source(marking_spec.information_source)
                        
                        
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
            if identity.party_name.organisation_names[0].name_elements[0].value:
                if identity.party_name:
                    if identity.party_name.organisation_names:
                        if identity.party_name.organisation_names[0].name_elements:
                            if identity.party_name.organisation_names[0].name_elements[0].value:
                                org_name = identity.party_name.organisation_names[0].name_elements[0].value
                                self.info_set.add(AIS_FORMAT['org_name'].format(org_name.upper()))
#                                self.info_list.append((AIS_INFO_OBJECT_RELATIONS['org_name'], org_name))
            if identity.addresses:
                if identity.addresses[0].country:
                    if identity.addresses[0].country.name_elements:
                        if identity.addresses[0].country.name_elements[0].name_code:
                            country_code = identity.addresses[0].country.name_elements[0].name_code
                            self.info_set.add(AIS_FORMAT['country_code'].format(country_code.upper()))
#                        if identity.addresses[0].country.name_elements[0].name_code_type:
#                            country_code_type = identity.addresses[0].country.name_elements[0].name_code_type
                if identity.addresses[0].administrative_area:
                    if identity.addresses[0].administrative_area.name_elements:
                        if identity.addresses[0].administrative_area.name_elements[0].name_code:
                            admin_area_code = identity.addresses[0].administrative_area.name_elements[0].name_code
                            self.info_set.add(AIS_FORMAT['admin_area_code'].format(admin_area_code.upper()))
#                        if identity.addresses[0].administrative_area.name_elements[0].name_code_type:
#                            admin_area_code_type = identity.addresses[0].administrative_area.name_elements[0].name_code_type
            if identity.organisation_info:
                if identity.organisation_info.industry_type:
                    industry_type = identity.organisation_info.industry_type
                    print("industry_type: " + industry_type)
                    if '|' in str(industry_type):
                        list_industry = str(industry_type).split('|')
                        for ind in list_industry:
                            ind_strip = ind.strip().lower()
                            if ind_strip in INDUSTRY_TYPE:
                                self.info_set.add(AIS_FORMAT['industry_type'].format(INDUSTRY_TYPE[ind_strip]))
                    elif str(industry_type).lower() in INDUSTRY_TYPE:
                        self.info_set.add(AIS_FORMAT['industry_type'].format(INDUSTRY_TYPE[str(industry_type).lower()]))
#         print "org_name: " + org_name
#         print "country_code: " + country_code
#         print "admin_area_code: " + admin_area_code
#         print "industry_type: " + industry_type
#         print("Organization Name: %s" % identity.party_name.organisation_names[0].name_elements[0].value)
#         self.print_list(identity.party_name.organisation_names)
#         print("Country: %s" % identity.addresses[0].country.name_elements[0].name_code)
#         print("Country code type: %s" % identity.addresses[0].country.name_elements[0].name_code_type)
#         print("Administrative area: %s" % identity.addresses[0].administrative_area.name_elements[0].name_code)
#         print("Administrative code type: %s" % identity.addresses[0].administrative_area.name_elements[0].name_code_type)
#         print("Industry Type: %s" % identity.organisation_info.industry_type)
#         #InformationSource.identity.specification
            
        
    def print_list(self, list1):
        print ("OBJ: " + str(list1))
        print (str(type(list1)) + " has " + str(len(list1)) + " elements") 
        for x in list1:
            print x
        
class AISInfoObject(AbstractMISPObjectGenerator):
    def __init__(self, template_name1, data_dict):
        super(AISInfoObject, self).__init__(template_name1, 
                                            misp_objects_path_custom=r"C:\Users\angelo.huan\git\cti-toolkit\certau\lib\stix")
        self.__data = data_dict
        self.generate_attributes()
        
#template_name1, misp_objects_path_custom=r"C:\Users\angelo.huan\git\cti-toolkit\certau\lib\stix"

    def generate_attributes(self):
        self.add_attribute('country', value='US')
#        for key, value in self.__data.items():
#            self.add_attribute(key, value=value)
                        