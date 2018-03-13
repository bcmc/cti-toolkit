
from stix.extensions.marking import ais
from stix.common.information_source import InformationSource

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
class ais_markings():
    marking_set = set()
    def get_set(self):
        return self.marking_set

    def __init__(self, package):
        """Retrieves the STIX package TLP (str) from the header."""
        if package.stix_header:
            handling = package.stix_header.handling
            if handling and handling.marking:
                for marking_spec in handling.marking: #Expects only 1 loop
                    for marking_struct in marking_spec.marking_structures:
                        if isinstance(marking_struct, ais.AISMarkingStructure):
                            self.ais_proprietary(marking_struct)
                    if marking_spec.information_source:
                        self.ais_info_source(marking_spec.information_source)
                        print("Found information_source structure")
                        
    def ais_proprietary(self, marking_struct):
        if marking_struct.is_proprietary:
            proprietary_struct = marking_struct.is_proprietary
            self.marking_set.add('ais-marking:AISMarking="Is_Proprietary"')
        elif marking_struct.not_proprietary:
            proprietary_struct = marking_struct.not_proprietary
            self.marking_set.add('ais-marking:AISMarking="Not_Proprietary"')
            
        if proprietary_struct:
            if proprietary_struct.cisa_proprietary is not None:
                self.marking_set.add( 'ais-marking:CISA_Proprietary="{}"'.
                                      format(str(proprietary_struct.cisa_proprietary).lower()))
            if proprietary_struct.tlp_marking:
                self.marking_set.add( 'ais-marking:TLPMarking="{}"'.
                                      format(proprietary_struct.tlp_marking.color.upper()))
            if proprietary_struct.ais_consent:
                self.marking_set.add( 'ais-marking:AISConsent="{}"'.
                                      format(proprietary_struct.ais_consent.consent.upper()))
    def ais_info_source(self, info_struct):
        pass
        #InformationSource.identity.specification
    

                        