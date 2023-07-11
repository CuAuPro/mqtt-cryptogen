from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import os
import json
import argparse
import logging
import logger



def generate_self_signed_ca(args):

    config_path = args.config_path
    # Open the JSON file
    with open(config_path) as f:
        # Load the JSON data
        config = json.load(f)
        
    store_folder = config["store_folder"]
    validity_period = config["validity_period"]
    new_passcode = config["new_passcode"]
    
    country = config["country"]
    state = config["state"]
    locality = config["locality"]
    organization = config["organization"]
    organizational_unit = config["organizational_unit"]
    common_name = config["common_name"]
    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])

    # Set the validity period
    if 'days' in validity_period:
        days = int(validity_period.split()[0])
        expiry_date = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    elif 'months' in validity_period:
        months = int(validity_period.split()[0])
        expiry_date = datetime.datetime.utcnow() + datetime.timedelta(months=months)
    else:
        years = int(validity_period.split()[0])
        expiry_date = datetime.datetime.utcnow() + datetime.timedelta(days=365*years)

        
    # Build the certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        expiry_date
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    
    certificate = cert_builder.sign(private_key, hashes.SHA256())


    # Write the certificate and private key to separate files
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    if new_passcode is not None:
        encryption_algorithm = serialization.BestAvailableEncryption(bytes(new_passcode, 'utf-8'))
    else:
        encryption_algorithm = serialization.NoEncryption()
        
    # Create a PKCS#12 file with the new certificate and private key
    p12 = serialization.pkcs12.serialize_key_and_certificates(
        bytes('master', 'utf-8'), 
        key=private_key,
        cert=certificate,
        cas=[],
        encryption_algorithm=encryption_algorithm)

    if not os.path.isdir(store_folder):
        os.mkdir(store_folder)
    with open(store_folder+"master.p12", "wb") as f:
        f.write(p12)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        description='Generate self-signed root certificate.'
                        )
    parser.add_argument("-p", "--config-path", type=str, default="config/root_cert_req.json",
                        help="Path to config file.")
    args = parser.parse_args()
    
    logger.init_logger(print_to_stdout=True)
    logging.info('Start generation cloud certificate(s).')
    generate_self_signed_ca(args)
    logging.info('End generation cloud certificate(s).')