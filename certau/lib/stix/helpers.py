from __future__ import absolute_import

from stix.extensions.marking.tlp import TLPMarkingStructure

def package_title(package):
    """Retrieves the STIX package title (str) from the header."""
    if package.stix_header and package.stix_header.title:
        return package.stix_header.title.encode('utf-8')
    else:
        return None

def package_description(package):
    """Retrieves the STIX package description (str) from the header."""
    if package.stix_header and package.stix_header.description:
        return package.stix_header.description.value.encode('utf-8')
    else:
        return None

def package_tlp(package):
    """Retrieves the STIX package TLP (str) from the header."""
    if package.stix_header:
        handling = package.stix_header.handling
        if handling and handling.marking:
            for marking_spec in handling.marking:
                for marking_struct in marking_spec.marking_structures:
                    if isinstance(marking_struct, TLPMarkingStructure):
                        return marking_struct.color
    return None