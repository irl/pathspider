import argparse
import bz2
import dateutil.parser
import json
import logging
import sys

from straight.plugin import load

def metadata_from_ps_ndjson(fp):
    y = None
    z = None

    for line in fp:
        d = json.loads(line)

        a = dateutil.parser.parse(d['time']['from'])
        b = dateutil.parser.parse(d['time']['to'])

        if y is None or a < y:
            y = a
        
        if z is None or b > z:
            z = b    

    return {'_time_start': y.strftime("%Y-%m-%dT%H:%M:%SZ"),
            '_time_end': z.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "_file_type": "pathspider-v2-ndjson-bz2"}

FILETYPE_MAP = { 'ps-ndjson': metadata_from_ps_ndjson }

def extract_metadata_for(filename, metadata_fn):
    metafilename = filename + ".meta.json"

    if filename.endswith(".bz2"):
        open_fn = bz2.open
    else:
        open_fn = open
    
    with open_fn(filename) as fp:
        metadata = metadata_fn(fp)

    return metafilename, metadata

def create_metadata(filename, filetype, entry):
    metafilename, metadata = extract_metadata_for(filename, FILETYPE_MAP[filetype])

    # add custom entries to metadata
    if entry is not None:
        for element in entry:
            keyword, value = element.split(":")
            metadata[keyword] = value

    write_metadata(metafilename, metadata)

def write_metadata(metafilename, metadata):
    with open(metafilename, mode="w") as mfp:
        json.dump(metadata, mfp, indent=2)

def metadata(args):
    logger = logging.getLogger("metadata")

    for filename in args.files:
        logger.info('processing %s...' % (filename,))
        sys.stdout.flush()
        create_metadata(filename, args.filetype, args.metadata)

def register_args(subparsers):
    parser = subparsers.add_parser(name='metadata',
                                   help="Create PTOv3 metadata files from results")
    parser.add_argument("files", nargs="*", help="input files", metavar="INPUTFILE")
    parser.add_argument("-t", "--filetype", help="filetype [ps-ndjson]",
                        metavar="FILETYPE", default="ps-ndjson")
    parser.add_argument("--metadata", nargs='+', help="Additional metadata entry",
                        metavar="ENTRY:VALUE")
    # Set the command entry point
    parser.set_defaults(cmd=metadata)
