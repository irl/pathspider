import pycurl
import argparse
import logging
import json
import bz2
import os
import random
import sys
import string

from io import BytesIO
import pathspider.cmd.metadata as metadata 

def compress_file(filename):
    '''
    compress file to bz2 if not already done
    
    :param filename: filename of file to compress
    :type filename: str
    :return: str -- filename of compressed file
    '''
    if filename.endswith(".bz2"):
        return filename
    else:
        new_filename = filename + ".bz2"
        compressionLevel = 9
        with open(filename, 'rb') as data:
            fh = open(new_filename, "wb")
            fh.write(bz2.compress(data.read(), compressionLevel))
            fh.close()
        return new_filename

def is_duplicate(filename):
    '''
    True if file is in campaign else False
    
    :param filename: filename of file to check
    :type filename: str
    :return: bool -- True if file is duplicate else False
    '''

    logger = logging.getLogger("uploader")
    url = BASELINK + os.path.basename(filename)
    logger.debug("checking url: " + url)
    answer = check_url(url, ["Authorization: APIKEY " + TOKEN])

    try:
        json.loads(answer)
        logger.info("File already exists")
        return True
    except:
        # we expect "file FILENAME not found" as answer
        if not answer.endswith("not found"):
            logger.debug("Unexpectes answer: " + answer)
        return False

def check_url(url, headers):
    '''
    checks a url with given header options
    returns answer as string
    
    :param url: url for file upload
    :type url: str
    :param header: additional http headers
    :type header: str
    :return: str -- answer from server
    '''
    
    buffer = BytesIO()
    c = pycurl.Curl()
    c.setopt(c.URL, url)
    c.setopt(c.WRITEDATA, buffer)
    c.setopt(pycurl.HTTPHEADER, headers)
    c.perform()
    c.close()
    return buffer.getvalue().decode('iso-8859-1')

def upload_metadata(filename):
    '''
    Uploads Metadata to PTO
    Updates metadata with PTO added fields
    returns url for measurment data as string
    
    :param filename: filename of metadata
    :type filename: str
    :param file: metadata
    :type file: :class: json
    :return: str -- url for data file or error
    '''
    
    logger = logging.getLogger("uploader")
    link = BASELINK + os.path.basename(filename).split(".")[0] + ".ndjson.bz2"
    content_type = ["Content-type: application/json", "Authorization: APIKEY " + TOKEN]
    answer = upload_file (link, content_type, filename)
    logger.debug("uploaded metadata")
    try:
        data = json.loads(answer)
        return (data["__data"])
    except:
        logger.debug("unexpected answer. excepted .json instead: " + answer)
        return "Error"

def upload_data(url, filename, metafilename):
    '''
    Uploads datafile to campaign on PTO server
    
    :param url: name of campaign the data belongs to
    :type url: str
    :param filename: filename of file to compress
    :type filename: str
    :param metafilename: filename of metafile
    :type metafilename: str    
    '''

    logger = logging.getLogger("uploader")
    content_type = ["Content-type: application/bzip2", "Authorization: APIKEY " + TOKEN]
    answer = upload_file(url, content_type, filename)
    logger.debug("uploaded data")
    try:
        data = json.loads(answer)
        logger.info("upload complete")
        metadata.write_metadata(metafilename, data)
        logger.info("saved metadata: " + metafilename)
    except:
        logger.info("upload failed")
        logger.debug("unexpected answer. excepted .json instead: " + answer)
    
def upload_file(url, headers, filename):
    '''
    Uploads file to campaign on PTO server
    
    :param url: name of campaign the data belongs to
    :type url: str
    :param filename: filename of file to compress
    :type filename: str
    :param headers: additional http headers
    :type headers: str
    :return: str -- answer from server
    '''

    buffer = BytesIO()
    c = pycurl.Curl()
    #set curl options
    # -X PUT
    c.setopt(c.URL, url)
    c.setopt(c.WRITEDATA, buffer)
    # upload the contents of this file --data-binary @file
    c.setopt(c.UPLOAD, 1)
    file = open(filename, "rb")
    c.setopt(c.READDATA, file)
    # -H "Content-type: application/xxx"
    # -H "Authorization: APIKEY $TOKEN"
    c.setopt(pycurl.HTTPHEADER, headers)
    c.perform()
    c.close()
    # File must be kept open while Curl object is using it
    file.close()
    return buffer.getvalue().decode('iso-8859-1')

def uploader(url, campaign, token, filename, metafilename):
    '''
    Uploads a given file to a campaign on the PTO using the provided token.
    Also creates and uploads the neccessary meta data.
    Prevents overwriting existing files on PTO
    
    :param campaign: name of campaign the data belongs to
    :type campaign: str
    :param filename: filename of file to compress and upload
    :type filename: str
    :param token: authentification tocken for PTO API
    :type token: str
    :param entry: Additional meta data tags
    :type entry: list of str
    '''

    logger = logging.getLogger("uploader")
    logger.debug("started uploader")

    global BASELINK
    global TOKEN
    if url.endswith('/'):
        BASELINK = url + campaign + "/"
    else:
        BASELINK = url + "/" + campaign + "/"
    TOKEN = token

    # check if metadata already exist on server
    if not is_duplicate(filename+'.bz2'):

        #upload and read out data link for data upload
        logger.debug("Start processing metadata")
        data_link = upload_metadata(metafilename)

        # compress data if necessary and upload data
        logger.debug("Start processing data")
        upload_data(data_link, compress_file(filename), metafilename)
    else:
        sys.exit(1)

def start_uploader(args):
    # Create custum datafile name if reqired
    if args.autoname:
        new_file = os.path.join(os.path.dirname(args.filename), ''.join(random.sample(string.ascii_letters + string.digits, k=15))+'.ndjson')
        os.rename(args.filename, new_file)
        args.filename = new_file
    #create metadata
    if args.metadata is None:
        metadata.create_metadata(args.filename, 'ps-ndjson', args.add)
        metafilename = args.filename +  ".meta.json"
    else:
        metafilename = args.metadata
    uploader(args.url, args.campaign, args.token, args.filename, metafilename)

def register_args(subparsers):
    parser = subparsers.add_parser(name='upload',
                                   help="Uploads data to PTO\nCreates metadata if not provided")

    parser.add_argument("filename", help="Data file in .ndjson", metavar="FILENAME")
    parser.add_argument("--campaign", help="Campaign the data belongs to")
    parser.add_argument("--token", help="Authentification token")
    parser.add_argument("--metadata", help="Metadata filename", metavar="FILENAME")
    parser.add_argument("--add", nargs='+', help="Additional metadata entry", metavar="TAG:VAL")
    parser.add_argument('--autoname', action='store_true', help=("Gives output file a generated name."))
    parser.add_argument("--url", default='https://v3.pto.mami-project.eu/raw/', help="URL for PTO data upload")

    # Set the command entry point
    parser.set_defaults(cmd=start_uploader)


