from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives import serialization
import os
import json
import argparse
import logger
import logging

def extract_pkcs12(args):
    
    config_path = args.config_path
    # Open the JSON file
    with open(config_path) as f:
        # Load the JSON data
        config = json.load(f)
        
    
    clients = config["clients"]


    for client in clients:
        
        path = client["path"]
        alias = client["alias"]
        store_folder = path+alias+"/"
        passcode = client["passcode"]
        new_passcode = client["new_passcode"]
        if new_passcode == "":
            new_passcode = None

        if passcode is not None:
            passcode = bytes(passcode, 'utf-8')

            
        logging.info('Start extracting pkcs12 certificate: {}'.format(alias))
        
        # Load the signing certificate and private key from the .p12 file
        with open(path+alias+'.p12', "rb") as f:
            p12_data = f.read()

        private_key, cert, additional_certs = load_key_and_certificates(p12_data, passcode)

        if not os.path.isdir(store_folder):
            os.mkdir(store_folder)
            
        if client["crt"]:
            try:
                logging.info('Extraction .crt from certificate: {}'.format(alias))
                with open(store_folder+alias+'.crt', 'wb') as f:
                    crt_out = cert.public_bytes(serialization.Encoding.PEM)
                    f.write(crt_out)
            except:
                logging.error('Extraction .crt from certificate: {} FAILED'.format(alias))

                
        if client["ca"]:
            try:
                logging.info('Extraction .ca from certificate: {}'.format(alias))
                with open(store_folder+'ca.crt', 'wb') as f:
                    ca_out = ""
                    for ac in additional_certs:
                        ca_out += (ac.public_bytes(serialization.Encoding.PEM)).decode()
                    ca_out = ca_out.encode()
                    f.write(ca_out)
            except:
                logging.error('Extraction .ca from certificate: {} FAILED'.format(alias))
                
        if client["key"]:
            try:
                logging.info('Extraction .key from certificate: {}'.format(alias))
                if new_passcode is not None:
                    encryption_algorithm = serialization.BestAvailableEncryption(bytes(new_passcode, 'utf-8'))
                else:
                    encryption_algorithm = serialization.NoEncryption()
                key_out = private_key.private_bytes(
                            serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            encryption_algorithm)
                with open(store_folder+alias+'.key', 'wb') as f:
                    f.write(key_out)
            except:
                logging.error('Extraction .key from certificate: {} FAILED'.format(alias))     
            
        logging.info('End of extracting pkcs12 certificate: {}'.format(alias))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        description='Generate client certificate(s).'
                        )
    parser.add_argument("-p", "--config-path", type=str, default="config/extract_pkcs12_req.json",
                        help="Path to config file.")
    args = parser.parse_args()

    logger.init_logger(print_to_stdout=True)
    logging.info('Start extracting pkcs12 certificate(s).')
    extract_pkcs12(args)
    logging.info('End extracting pkcs12 certificate(s).')
