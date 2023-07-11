from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import ipaddress
import os
import json
import argparse
import logger
import logging

def gen_client_cert(args):
    
    config_path = args.config_path
    # Open the JSON file
    with open(config_path) as f:
        # Load the JSON data
        config = json.load(f)
        
    
    store_folder = config["store_folder"]
    signing_cert_path = config["signing_cert_path"]
    passcode = config["passcode"]
    
    clients = config["clients"]


    if passcode is not None:
        passcode = bytes(passcode, 'utf-8')

    # Load the signing certificate and private key from the .p12 file
    with open(signing_cert_path, "rb") as f:
        p12_data = f.read()

    private_key, cert, additional_certs = load_key_and_certificates(p12_data, passcode)

    for client in clients:
        
        new_alias = client["new_alias"]
        validity_period = client["validity_period"]
        new_passcode = client["new_passcode"]
        if new_passcode == "":
            new_passcode = None
            
        logging.info('Start generation client certificate: {}'.format(new_alias))
        country = client["country"]
        state = client["state"]
        locality = client["locality"]
        organization = client["organization"]
        organizational_unit = client["organizational_unit"]
        common_name = new_alias+'.'+cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        # Generate a new RSA key pair
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
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


        # Add Authority Key Identifier (AKI) extension
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest,
            authority_cert_issuer=[x509.DirectoryName(cert.issuer)],
            authority_cert_serial_number=cert.serial_number,
        )

        # Add Subject Key Identifier (SKI) extension
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

        # Add Subject Alternative Name (SAN) extension with DNS names and IP addresses specified by the user
        dns_names = client["dns_names"]
        ip_addresses = [ipaddress.IPv4Address(ip) for ip in client["ipv4_addresses"]]
        ip_addresses += [ipaddress.IPv6Address(ip) for ip in client["ipv6_addresses"]]
        
        san = x509.SubjectAlternativeName([
            x509.DNSName(name) for name in dns_names
        ] + [
            x509.IPAddress(ip) for ip in ip_addresses
        ])

        # Build the certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            expiry_date
        ).add_extension(
            aki, critical=False
        ).add_extension(
            san, critical=False
        ).add_extension(
            ski, critical=False
        )


        cert_builder = cert_builder.sign(
            private_key=private_key, algorithm=hashes.SHA256()
        )

        # Write the certificate and private key to separate files
        cert_bytes = cert_builder.public_bytes(serialization.Encoding.PEM)
        key_bytes = key.private_bytes(
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
            bytes(new_alias, 'utf-8'), 
            key=key,
            cert=cert_builder,
            cas=[cert]+additional_certs,
            encryption_algorithm=encryption_algorithm)

        if not os.path.isdir(store_folder):
            os.mkdir(store_folder)
        with open(store_folder+new_alias+".p12", "wb") as f:
            f.write(p12)
        logging.info('End of generation client certificate: {}'.format(new_alias))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        description='Generate client certificate(s).'
                        )
    parser.add_argument("-p", "--config-path", type=str, default="config/client_cert_req.json",
                        help="Path to config file.")
    args = parser.parse_args()

    logger.init_logger(print_to_stdout=True)
    logging.info('Start generation client certificate(s).')
    gen_client_cert(args)
    logging.info('End generation client certificate(s).')
