"""Classes for transforming STIX packages to various formats.

The base class :py:class:`StixTransform` provides helper functions for
processing :py:class:`STIXPackage<stix.core.stix_package.STIXPackage>`
elements.

There are two broad types of transform currently supported:

#. Transforms to a text format (these transforms extend the
   :py:class:`StixTextTransform` class):

     * :py:class:`StixStatsTransform` - display statistics about a package
     * :py:class:`StixCsvTransform` - display indicators in CSV format
     * :py:class:`StixBroIntelTransform` - display indicators in the Bro
       Intel format
     * :py:class:`StixSnortTransform` - display indicators in the Snort
       rule format

#. Transforms that interact with a service:
     * :py:class:`StixMispTransform` - publish indicators to a MISP instance
"""

import sys

from .base import StixTransform
from .text import StixTextTransform
from .stats import StixStatsTransform
from .csv import StixCsvTransform
from .brointel import StixBroIntelTransform
from .snort import StixSnortTransform
from .misp import StixMispTransform


TRANSFORM_CLASS = {
    'text': StixTextTransform,
    'stats': StixStatsTransform,
    'csv': StixCsvTransform,
    'brointel': StixBroIntelTransform,
    'snort': StixSnortTransform,
    'misp': StixMispTransform,
}


def transform_package(package, transform, transform_kwargs):
    """Loads a STIX package and runs a transform over it."""
    if transform in TRANSFORM_CLASS:
        transform_class = TRANSFORM_CLASS[transform]
        transform = transform_class(package, **transform_kwargs)
        if isinstance(transform, StixTextTransform):
            sys.stdout.write(transform.text())
        elif isinstance(transform, StixMispTransform):
            transform.publish()
