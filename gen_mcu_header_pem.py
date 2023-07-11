from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives import serialization
import os
import json
import argparse
import logger
import logging

def modify_lines(lines):
    # Modify each line
    modified_lines = []
    for line in lines[:-1]:
        modified_line = '"' + line.rstrip() + '\\n" \\'
        modified_lines.append(modified_line)
        
    modified_line = '"' + lines[-1].rstrip() + '\\n";'
    modified_lines.append(modified_line)    
    return modified_lines
    
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
        
        header_lines = []
        header_lines.append("#ifndef CERTIFICATES_H")
        header_lines.append("#define CERTIFICATES_H")
        
        header_lines.append("")
        try:
            logging.info('Extraction .crt from certificate: {}'.format(alias))
            with open(store_folder+alias+'.crt', 'r') as f:
                lines = f.readlines()
            
            lines = modify_lines(lines)   
            lines.insert(0, "const char* clientCertificate = \\")
            header_lines.extend(lines)
        except:
            logging.error('Extraction .crt from certificate: {} FAILED'.format(alias))
            return

        header_lines.append("")
        try:
            logging.info('Extraction .key from certificate: {}'.format(alias))
            with open(store_folder+alias+'.key', 'r') as f:
                lines = f.readlines()
            
            lines = modify_lines(lines)     
            lines.insert(0, "const char* clientPrivateKey = \\")
            header_lines.extend(lines)
        except:
            logging.error('Extraction .key from certificate: {} FAILED'.format(alias))     
            return
             
        header_lines.append("")
        try:
            logging.info('Extraction .ca from certificate: {}'.format(alias))
            with open(store_folder+'ca.crt', 'r') as f:
                lines = f.readlines()
            
            lines = modify_lines(lines)
            lines.insert(0, "const char* rootCACertificate = \\")
            header_lines.extend(lines)
        except:
            logging.error('Extraction .ca from certificate: {} FAILED'.format(alias))
            return
    
    header_lines.append("")
    header_lines.append("#endif  // CERTIFICATES_H")
    try:
        logging.info('Writing to .h file for: {}'.format(alias))
        with open(store_folder+'certificates.h', 'w', encoding='utf-8') as f:
            for line in header_lines:
                f.write(line + "\n")     
    except:
        logging.error('Writing to .h file for: {} FAILED'.format(alias))
        return     
    logging.info('End of extracting pkcs12 certificate: {}'.format(alias))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        description='Generate header file for MCU certificate(s).'
                        )
    parser.add_argument("-p", "--config-path", type=str, default="config/mcu_header_req.json",
                        help="Path to config file.")
    args = parser.parse_args()

    logger.init_logger(print_to_stdout=True)
    logging.info('Start generating header file for MCU certificate(s).')
    extract_pkcs12(args)
    logging.info('End generating header file for MCU certificate(s).')