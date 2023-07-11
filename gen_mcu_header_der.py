from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_certificate
import binascii
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
        
        header_lines = []
        header_lines.append("#ifndef CERTIFICATES_DER_H")
        header_lines.append("#define CERTIFICATES_DER_H")
        
        header_lines.append("")
        try:
            logging.info('Extraction .crt from certificate: {}'.format(alias))
            with open(store_folder+alias+'.crt', 'rb') as f:
                crt_data = f.read()
            der_crt = binascii.hexlify(crt_data).decode('ascii')
            hex_array = [der_crt[i:i+2] for i in range(0, len(der_crt), 2)]

            #crt = load_pem_x509_certificate(crt_data)
            #der_crt = crt.public_bytes(encoding=serialization.Encoding.DER)

            variable_name = 'crt_DER'
            hex_data = ', '.join([f"0x{byte}" for byte in hex_array])

            data_len = len(hex_array)
            lines = []
            lines.append(hex_data)
            lines.insert(0, "unsigned char "+variable_name+f"[] = {{")
            lines.append(f"}};") 
            lines.append("unsigned int "+variable_name+"_len = "+str(data_len)+";")
            header_lines.extend(lines)
            header_lines.append("")
        except:
            logging.error('Extraction .crt from certificate: {} FAILED'.format(alias))
            return

        header_lines.append("")
        try:
            logging.info('Extraction .key from certificate: {}'.format(alias))
            with open(store_folder+alias+'.key', 'rb') as f:
                key_data = f.read()
            #private_key = serialization.load_pem_private_key(key_data, password=None)

            #der_private_key = private_key.private_bytes(
            #    encoding=serialization.Encoding.DER,
            #    format=serialization.PrivateFormat.PKCS8,
            #    encryption_algorithm=serialization.NoEncryption()
            #)
            der_private_key = binascii.hexlify(key_data).decode('ascii')
            hex_array = [der_private_key[i:i+2] for i in range(0, len(der_private_key), 2)]
            
            variable_name = 'key_DER'
            hex_data = ', '.join(f'0x{byte}' for byte in hex_array)
            data_len = len(hex_array)
            lines = []
            lines.append(hex_data)
            lines.insert(0, "unsigned char "+variable_name+f"[] = {{")
            lines.append(f"}};") 
            lines.append("unsigned int "+variable_name+"_len = "+str(data_len)+";")
            header_lines.extend(lines)
            header_lines.append("")
        except:
            logging.error('Extraction .key from certificate: {} FAILED'.format(alias))     
            return
             
        header_lines.append("")
        try:
            logging.info('Extraction .ca from certificate: {}'.format(alias))
            with open(store_folder+'ca.crt', 'rb') as f:
                ca_data = f.read()
            #ca = load_pem_x509_certificate(ca_data)

            # Convert the certificate to DER format
            #der_ca = ca.public_bytes(serialization.Encoding.DER)
            der_ca =  binascii.hexlify(ca_data).decode('ascii')
            hex_array = [der_ca[i:i+2] for i in range(0, len(der_ca), 2)]
            
            #TODO: I don't know if that is necessary.
            if False:
                
                variable_name = 'ca_DER'
                hex_data = ', '.join(f'0x{byte}' for byte in hex_array)
                data_len = len(hex_array) 
                lines = []
                lines.append(hex_data)
                lines.insert(0, "unsigned char "+variable_name+f"[] = {{")
                lines.append(f"}};") 
                lines.append("unsigned int "+variable_name+"_len = "+str(data_len)+";")
                header_lines.extend(lines)
                header_lines.append("")
        except:
            logging.error('Extraction .ca from certificate: {} FAILED'.format(alias))
            return
    
    header_lines.append("")
    header_lines.append("#endif  // CERTIFICATES_DER_H")
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
    parser.add_argument("-p", "--config-path", type=str, default="config_private/gen_mcu_header_req.json",
                        help="Path to config file.")
    args = parser.parse_args()

    logger.init_logger(print_to_stdout=True)
    logging.info('Start generating header file for MCU certificate(s).')
    extract_pkcs12(args)
    logging.info('End generating header file for MCU certificate(s).')
    