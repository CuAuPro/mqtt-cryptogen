# Tool for generating self signed (root) and client certificates.

This tool is primary intended to use for MQTTS certificate generation (.p12 fromat).



# Table of contents
- [Requirements](#requirements)
- [Self-signed certificate generation](#self_signed_generation)
- [End-entity (client) certificate generation](#client_generation)
- [Extract PKCS12 certificate](#extract_pkcs12)
- [MCU certificate header file generation](#header_generation)


# Requirements <a id='requirements'></a>

```
cryptography==40.0.2
```

# Self-signed certificate generation <a id='self_signed_generation'></a>

To generate self-signed certificates, you will need to use the `gen_root_cert.py` script with a configuration file. Before running this script, make sure you have all the dependencies installed.

To generate the certificates, follow these steps:


1. Edit a configuration file named `config/root_cert_req.json` with the following content:

```json
{
    "store_folder":         "./",
    "new_passcode":         "<passcode_of_root_cert>",
    "validity_period":      "10 years",

    "country":              "<country>",
    "state":                "<state>",
    "locality":             "<locality>",
    "organization":         "<organization>",
    "organizational_unit":  "<organizational_unit>",
    "common_name":          "mqtt.eu"
}

```

Here is what each option in the configuration file does:

 - `store_folder`: The folder where the generated certificates will be stored.

  - `new_passcode`: The password for the new self-signed certificate.

 - `validity_period`: The validity period of the new cloud certificate (`N days/months/years`).

 - `country`: OrganizationalUnit.

 - `state`: StateOrProvinceName.

 - `locality`: Locality.

 - `organization`: Organization.

 - `organizational_unit`: OrganizationalUnit.

 - `common_name`: You can just leave `mqtt.eu`.

 Example:

```json
{
    "store_folder":         "./",
    "new_passcode":         "123456",
    "validity_period":      "10 years",

    "country":              "SI",
    "state":                "Ljubljana",
    "locality":             "Ljubljana",
    "organization":         "org",
    "organizational_unit":  "it",
    "common_name":          "mqtt.eu"
}
```

2. Run the following command to generate the cloud certificates:



```bash
python gen_root_cert.py -p <path_to_config_file>
```
The `-p` option is optional and can be used to specify the path to the configuration file. If you do not use the `-p` option, the script will look for a file named `config/root_cert_req.json`.

3. After running the command, the script will generate certificates in `store_folder`.


# End-entity (client) certificate generation <a id='client_generation'></a>

To generate client certificates, you will need to use the `gen_client_certify.py` script with a configuration file. Before running this script, make sure you have all the dependencies installed.

To generate the certificates, follow these steps:

1. Obtain the root self-signed certificate.

2. Edit a configuration file named `config/client_cert_req.json` with the following content:

```json
{
    "store_folder":         "generated_certificates/",
    "signing_cert_path":    "<path_to_master_cert>",
    "passcode":             "<passcode_of_root_cert>",

    "clients": [
        {
            "new_alias":            "<client1_alias>",
            "validity_period":      "10 years",
            "new_passcode":         "123456",
            "country":              "<country>",
            "state":                "<state>",
            "locality":             "<locality>",
            "organization":         "<organization>",
            "organizational_unit":  "<organizational_unit>",
            "dns_names":            ["<SANdns1>", "<SANdns2>"],
            "ipv4_addresses":       ["<SANip1>", "<SANip2>"],
            "ipv6_addresses":       ["<SANip3>", "<SANip4>"]
        },
        {
            "new_alias":            "<client2_alias>",
            "validity_period":      "10 years",
            "new_passcode":         "<new_passcode>",
            "country":              "<country>",
            "state":                "<state>",
            "locality":             "<locality>",
            "organization":         "<organization>",
            "organizational_unit":  "<organizational_unit>",
            "dns_names":            ["<SANdns1>", "<SANdns2>"],
            "ipv4_addresses":       ["<SANip1>", "<SANip2>"],
            "ipv6_addresses":       ["<SANip3>", "<SANip4>"]
        }
    ]

}
```

Here is what each option in the configuration file does:

 - `store_folder`: The folder where the generated certificates will be stored.

 - `signing_cert_path`: The path to the self-signed (root) certificate.

 - `passcode`: The password for the self-signed (root) certificate.

 - `new_alias`:  The alias for the new client certificate.

 - `validity_period`: The validity period of the new client certificate (`N days/months/years`).

 - `new_passcode`: The password for the new client certificate.

 - `country`: OrganizationalUnit.

 - `state`: StateOrProvinceName.

 - `locality`: Locality.

 - `organization`: Organization.

 - `organizational_unit`: OrganizationalUnit.

- `dns_names`: DNS names for SAN.

 - `ipv4_addresses`: IPv4 addresses for SAN.

 - `ipv6_addresses`: IPv6 addresses for SAN.

3. Run the following command to generate the client certificates:


```bash
python gen_client_cert.py -p <path_to_config_file>
```
The `-p` option is optional and can be used to specify the path to the configuration file. If you do not use the `-p` option, the script will look for a file named `config/client_cert_req.json`.

4. After running the command, the script will generate certificates in `store_folder`.



# Extract PKCS12 certificate <a id='extract_pkcs12'></a>


This script loads a PKCS12 file (.p12) that contains a private key, a client certificate, and additional CA certificates. It then exports specified files: certificate, private key and (or) all additional CA certificates.

To generate seperate files, you will need to use the `extract_pkcs12_certs.py` script with a configuration file. Before running this script, make sure you have all the dependencies installed.

To generate the certificates, follow these steps:


1. Edit a configuration file named `config/extract_pkcs12_req.json` with the following content:

```json
{
    "clients": [
        {
            "path":     "generated_certificates/",
            "alias":    "<client1_alias>",
            "passcode": "<passcode>",
            "new_passcode": "<new_passcode>",
            "ca":       true,
            "crt":      true,
            "key":      true

        },
        {
            "path":     "generated_certificates/",
            "alias":    "<client2_alias>",
            "passcode": "<passcode>",
            "new_passcode": "<new_passcode>",
            "ca":       true,
            "crt":      true,
            "key":      true

        }
    ]

}
```

Here is what each option in the configuration file does:

 - `path`: The folder where the folder of generated files will be stored.

 - `alias`:  The alias of client.

 - `passcode`: The password of the client certificate.

 - `new_passcode`: The password for encrypting key.

 - `ca`: If export additional CA certificates: true/false

 - `crt`: If export certificate: true/false

 - `key`: If export private key: true/false



2. Run the following command to generate the client certificates:


```bash
python extract_pkcs12_certs.py -p <path_to_config_file>
```
The `-p` option is optional and can be used to specify the path to the configuration file. If you do not use the `-p` option, the script will look for a file named `config/extract_pkcs12_req.json`.

3. After running the command, the script will generate certificates in `path/alias`.


# MCU certificate header file generation <a id='header_generation'></a>


This script loads a extracted exported certificate, private key and (or) all additional CA certificates for client and generates `.h` file that can be used for MCUs.

Before running this script, make sure you have all the dependencies installed.


**PEM format**:  To generate seperate files, you will need to use the `gen_mcu_header_pem.py` script with a configuration file. 

**DER format**:  To generate seperate files, you will need to use the `gen_mcu_header_der.py` script with a configuration file. 

To generate the header file `.h`, follow these steps:


1. Edit a configuration file named `config/mcu_header_req.json` with the following content:

```json
{
    "clients": [
        {
            "path":     "generated_certificates/",
            "alias":    "<client1_alias>"
        },
        {
            "path":     "generated_certificates/",
            "alias":    "<client2_alias>"
        }
    ]

}
```

Here is what each option in the configuration file does:

 - `path`: The folder where the folder of files `.crt`, `.key` and `.ca` are be stored.

 - `alias`:  The alias of client.



2. Run the following command to generate the client certificates:


```bash
python gen_mcu_header_pem.py -p <path_to_config_file>
or
python gen_mcu_header_der.py -p <path_to_config_file>
```
The `-p` option is optional and can be used to specify the path to the configuration file. If you do not use the `-p` option, the script will look for a file named `config/mcu_header_req.json`.

3. After running the command, the script will generate certificate header `.h` file in `path/alias`.

