"""
This script supports transforming indicators (observables) from a STIX Package
into the Bro Intelligence Format. It can interact with a TAXII server to obtain
the STIX package(s), or a STIX package file can be supplied.
"""

import os
import sys
import logging
import dateutil

from six.moves.urllib.parse import urlunparse

from certau.source import StixFileSource, TaxiiContentBlockSource
from certau.transform import StixTextTransform, StixStatsTransform
from certau.transform import StixCsvTransform, StixBroIntelTransform
from certau.transform import StixMispTransform, StixSnortTransform
from certau.transform import transform_package
from certau.util.stix.ais import ais_refactor
from certau.util.stix.helpers import package_tlp
from certau.util.taxii.client import SimpleTaxiiClient
from certau.util.config import get_arg_parser


def main():
    parser = get_arg_parser()
    options = parser.parse_args()

    # Initialise logging to stderr, capture warnings
    logging.basicConfig(stream=sys.stderr)
    logging.captureWarnings(True)
    logger = logging.getLogger()
    if options.quiet:
        logger.setLevel(logging.ERROR)
    elif options.verbose:
        logger.setLevel(logging.INFO)
    elif options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logger.info("logging enabled")

    transform_kwargs = {}
    transform_kwargs['default_title'] = options.default_title
    transform_kwargs['default_description'] = options.default_description
    transform_kwargs['default_tlp'] = options.default_tlp
    if options.stats:
        transform = 'stats'
    elif options.text:
        transform = 'csv'
        if options.field_separator:
            transform_kwargs['separator'] = options.field_separator
    elif options.bro:
        transform = 'brointel'
        transform_kwargs['do_notice'] = 'F' if options.bro_no_notice else 'T'
        if options.source:
            transform_kwargs['source'] = options.source
        if options.base_url:
            transform_kwargs['url'] = options.base_url
    elif options.misp:
        transform = 'misp'
        misp_kwargs = dict(
            misp_url=options.misp_url,
            misp_key=options.misp_key,
            misp_ssl=options.misp_ssl,
        )
        if options.misp_client_cert and options.misp_client_key:
            misp_kwargs['misp_cert'] = (options.misp_client_cert,
                                        options.misp_client_key)
        misp = StixMispTransform.get_misp_object(**misp_kwargs)
        transform_kwargs['misp'] = misp
        transform_kwargs['distribution'] = options.misp_distribution
        transform_kwargs['threat_level'] = options.misp_threat
        transform_kwargs['analysis'] = options.misp_analysis
        transform_kwargs['information'] = options.misp_info
        transform_kwargs['published'] = options.misp_published
    elif options.snort:
        transform = 'snort'
        transform_kwargs['snort_initial_sid'] = options.snort_initial_sid
        transform_kwargs['snort_rule_revision'] = options.snort_rule_revision
        transform_kwargs['snort_rule_action'] = options.snort_rule_action
    elif options.xml_output:
        pass
    else:
        logger.error('Unable to determine transform type from options')

    if options.header:
        transform_kwargs['include_header'] = options.header

    if options.taxii:
        logger.info("Processing a TAXII message")

        taxii_client = SimpleTaxiiClient(
            username=options.username,
            password=options.password,
            key_file=options.key,
            cert_file=options.cert,
            ca_file=options.ca_file,
        )

        # Build the poll URL if it wasn't provided
        if options.poll_url is None:
            scheme = 'https' if options.ssl else 'http'
            netloc = options.hostname
            if options.port:
                netloc += ':{}'.format(options.port)
            url_parts = [scheme, netloc, options.path, '', '', '']
            poll_url = urlunparse(url_parts)
        else:
            poll_url = options.poll_url

        # Parse begin and end timestamps if provided
        if options.begin_timestamp:
            begin_timestamp = dateutil.parser.parse(options.begin_timestamp)
        else:
            begin_timestamp = None

        if options.end_timestamp:
            end_timestamp = dateutil.parser.parse(options.end_timestamp)
        else:
            end_timestamp = None

        # Sanity checks for timestamps
        if (begin_timestamp is not None and end_timestamp is not None and
                begin_timestamp > end_timestamp):
            logger.error('poll end_timestamp is earlier than begin_timestamp')
            return

        content_blocks = taxii_client.poll(
            poll_url=options.poll_url,
            collection=options.collection,
            subscription_id=options.subscription_id,
            begin_timestamp=begin_timestamp,
            end_timestamp=end_timestamp,
            state_file=options.state_file,
        )

        source = TaxiiContentBlockSource(
            content_blocks=content_blocks,
            collection=options.collection,
        )

        logger.info("Processing TAXII content blocks")
    else:
        logger.info("Processing file input")
        source = StixFileSource(options.file, options.recurse)

    if options.xml_output:
        # Try to create the output directory if it doesn't exist
        if not os.path.isdir(options.xml_output):
            try:
                os.makedirs(options.xml_output)
            except Exception:
                logger.error('unable to create output directory')
                return

    for source_item in source.source_items():
        package = source_item.stix_package
        if package is not None:
            if options.xml_output:
                # Add AIS Marking
                if options.ais_marking:
                    tlp = package_tlp(package) or options.ais_default_tlp
                    ais_refactor(
                        package=package,
                        proprietary=options.ais_proprietary,
                        consent=options.ais_consent,
                        color=tlp,
                        country=options.ais_country,
                        industry=options.ais_industry_type,
                        admin_area=options.ais_administrative_area,
                        organisation=options.ais_organisation,
                    )
                source_item.save(options.xml_output)
            else:
                transform_package(package, transform, transform_kwargs)


if __name__ == '__main__':
    main()
