> [!CAUTION]
> The following guide is intended for lab/testing purposes only. It does not follow industry best practices and is meant to be used only as a learning tool and not for production networks.
>
> All commands were ran as the root user, which negated the needed to prepend "sudo" for commands that would typically require additional permissions. To become the root user, use the following command 
> ```
> sudo bash
> ```

# Overview
This is a guide on how to set up a lab Ubuntu (v24.04) server with the following roles:
* PKI/Certificate Authority using OpenSSL (v3.0.13)
    * [Two-tier hierarchy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786436(v=ws.11)#ca-hierarchy-options) (Root CA & Intermediate CA)
* RADIUS/RADSec using FreeRADIUS (v3.2.3)
    * EAP-PEAP & EAP-TLS
* LDAP using OpenLDAP (v2.6.7)
    * LDAP with STARTTLS support
    * Secure LDAP (LDAPS)

> [!NOTE]
> The operating system and package versions noted above are what were used while making this guide. Older/newer versions may require different commands or configurations.

# Contents
* [PKI with OpenSSL](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#pki-with-openssl)
    * [OpenSSL Root CA](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openssl-root-ca)
    * [OpenSSL Intermediate CA](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openssl-intermediate-ca)
    * [OpenSSL Server Certificate](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openssl-server-certificate)
    * [OpenSSL Client Certificate](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openssl-client-certificate)
* [RADIUS/RADSec with FreeRADIUS](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#radiusradsec-with-freeradius)
    * [FreeRADIUS Package Installation](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#freeradius-package-installation)
    * [FreeRADIUS Configuration](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#freeradius-configuration)
    * [FreeRADIUS Validatation](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#freeradius-validation)
    * [FreeRADIUS Debugging](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#freeradius-debugging)
* [LDAP with OpenLDAP](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#ldap-with-openldap)
    * [OpenLDAP Package Installation](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openldap-package-installation)
    * [OpenLDAP Configuration](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openldap-configuration)
    * [OpenLDAP Validatation](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openldap-validation)
    * [OpenLDAP Debugging](https://github.com/Bodayngo/lab-server?tab=readme-ov-file#openldap-debugging)


# PKI with OpenSSL

## OpenSSL Root CA
1. Create root directories and files
    ```
    mkdir /root/ca
    cd /root/ca
    mkdir certs crl newcerts private
    chmod 700 /root/ca/private
    touch /root/ca/index.txt
    echo 1000 > /root/ca/serial
    ```

2. Create root configuration file (example contents [here](openssl_root.cnf))
    ```
    nano /root/ca/openssl.cnf
    ```

3. Create root CA private key
    ```
    openssl genrsa -aes256 \
        -out /root/ca/private/ca-root.lab.local.key.pem 4096
    ```
    ```
    chmod 400 /root/ca/private/ca-root.lab.local.key.pem
    ``` 

4. Create root CA certificate
    ```
    openssl req -config /root/ca/openssl.cnf \
        -key /root/ca/private/ca-root.lab.local.key.pem \
        -new -x509 -days 3650 -sha256 -extensions v3_ca \
        -out /root/ca/certs/ca-root.lab.local.cert.pem
    ```
    ```
    chmod 444 /root/ca/certs/ca-root.lab.local.cert.pem
    ```

5. Validate certificate
    ```
    openssl x509 -noout -text -in /root/ca/certs/ca-root.lab.local.cert.pem
    ```

## OpenSSL Intermediate CA
1. Create intermediate directories and files
    ```
    mkdir /root/ca/intermediate
    cd /root/ca/intermediate
    mkdir certs crl csr newcerts private cnf
    chmod 700 /root/ca/intermediate/private
    touch /root/ca/intermediate/index.txt
    echo 1000 > /root/ca/intermediate/serial
    echo 1000 > /root/ca/intermediate/crlnumber
    ```

2. Create intermediate configuration file (example contents [here](openssl_intermediate.cnf))
    ```
    nano /root/ca/intermediate/openssl.cnf
    ```
    
3. Create intermediate CA private key
    ```
    openssl genrsa -aes256 \
        -out /root/ca/intermediate/private/ca-intermediate.lab.local.key.pem 4096
    ```
    ```
    chmod 400 /root/ca/intermediate/private/ca-intermediate.lab.local.key.pem
    ``` 

4. Create intermediate CA CSR
    ```
    openssl req -config /root/ca/intermediate/openssl.cnf -new -sha256 \
        -key /root/ca/intermediate/private/ca-intermediate.lab.local.key.pem \
        -out /root/ca/intermediate/csr/ca-intermediate.lab.local.csr.pem
    ```

5. Create intermediate CA certificate
    ```
    openssl ca -config /root/ca/openssl.cnf -extensions v3_intermediate_ca \
        -days 1825 -notext -md sha256 \
        -in /root/ca/intermediate/csr/ca-intermediate.lab.local.csr.pem \
        -out /root/ca/intermediate/certs/ca-intermediate.lab.local.cert.pem
    ```
    ```
    chmod 444 /root/ca/intermediate/certs/ca-intermediate.lab.local.cert.pem
    ```

6. Validate intermedate certificate
    ```
    openssl x509 -noout -text -in /root/ca/intermediate/certs/ca-intermediate.lab.local.cert.pem
    ```
    ```
    openssl verify -CAfile /root/ca/certs/ca-root.lab.local.cert.pem \
        /root/ca/intermediate/certs/ca-intermediate.lab.local.cert.pem
    ```

7. Create CA chain
    ```
    cat /root/ca/intermediate/certs/ca-intermediate.lab.local.cert.pem \
        /root/ca/certs/ca-root.lab.local.cert.pem > \
        /root/ca/intermediate/certs/ca-chain.lab.local.cert.pem
    ```
    ```
    chmod 444 /root/ca/intermediate/certs/ca-chain.lab.local.cert.pem
    ```

## OpenSSL Server Certificate

> [!NOTE]
> **Subject Alternative Names (SANs) and changing other certificate options:**
>
> If your certificate will require subject alternative names (SANs) such as hostnames or IP addresses, or even altering key/extended key usage options, then changes to the openSSL configuration file will need to be made. To do so, separate openSSL configration files are made for each server or client certificate generated. Not only does this allow you to alter configuration options from a template, but it keeps record of what was used an input for certificate creation, should it need to be referenced again in the future.
>
> As an example, Let's say I want to have a server certificate (cn=server.lab.local) that has two SANs. One will be a DNS subdomain (server), the other will be an IP address (10.1.20.10). I would need to make the following changes to the configuration file:
>
> ```
> [ server_cert ]
> --- output omitted ---
> subjectAltName = @alt_names
>
> [ alt_names ]
> DNS.1 = server
> IP.1 = 10.1.20.10
> ```

1. Create server openSSL configuration file and edit extensions/parameters, if necessary
    ```
    cp /root/ca/intermediate/openssl.cnf /root/ca/intermediate/cnf/server.lab.local.openssl.cnf
    ```
    ```
    nano /root/ca/intermediate/cnf/server.lab.local.openssl.cnf
    ```

2. Create server private key
    ```
    openssl genrsa -aes256 \
        -out /root/ca/intermediate/private/server.lab.local.key.pem 4096
    ```
    ```
    chmod 400 /root/ca/intermediate/private/server.lab.local.key.pem
    ``` 

3. Create server CSR
    ```
    openssl req -config /root/ca/intermediate/cnf/server.lab.local.openssl.cnf -new -sha256 \
        -key /root/ca/intermediate/private/server.lab.local.key.pem \
        -out /root/ca/intermediate/csr/server.lab.local.csr.pem
    ```

4. Create server certificate
    ```
    openssl ca -config /root/ca/intermediate/cnf/server.lab.local.openssl.cnf \
        -extensions server_cert -days 365 -notext -md sha256 \
        -in /root/ca/intermediate/csr/server.lab.local.csr.pem \
        -out /root/ca/intermediate/certs/server.lab.local.cert.pem
    ```
    ```
    chmod 444 /root/ca/intermediate/certs/server.lab.local.cert.pem
    ```

5. Validate server certificate
    ```
    openssl x509 -noout -text -in /root/ca/intermediate/certs/server.lab.local.cert.pem
    ```
    ```
    openssl verify -CAfile /root/ca/intermediate/certs/ca-chain.lab.local.cert.pem \
        /root/ca/intermediate/certs/server.lab.local.cert.pem
    ```

## OpenSSL Client Certificate
1. Create server openSSL configuration file and edit extensions/parameters, if necessary
    ```
    cp /root/ca/intermediate/openssl.cnf \
        /root/ca/intermediate/cnf/client.lab.local.openssl.cnf
    ```
    ```
    nano /root/ca/intermediate/cnf/client.lab.local.openssl.cnf
    ```

2. Create client private key
    ```
    openssl genrsa -aes256 \
        -out /root/ca/intermediate/private/client.lab.local.key.pem 4096
    ```
    ```
    chmod 400 /root/ca/intermediate/private/client.lab.local.key.pem
    ``` 

3. Create client CSR
    ```
    openssl req -config /root/ca/intermediate/cnf/client.lab.local.openssl.cnf \
        -key /root/ca/intermediate/private/client.lab.local.key.pem \
        -new -sha256 -out /root/ca/intermediate/csr/client.lab.local.csr.pem
    ```  

4. Create client certificate
    ```
    openssl ca -config /root/ca/intermediate/cnf/client.lab.local.openssl.cnf \
        -extensions usr_cert -days 365 -notext -md sha256 \
        -in /root/ca/intermediate/csr/client.lab.local.csr.pem \
        -out /root/ca/intermediate/certs/client.lab.local.cert.pem
    ```
    ```
    chmod 444 /root/ca/intermediate/certs/client.lab.local.cert.pem
    ```

5. Validate client certificate
    ```
    openssl x509 -noout -text -in /root/ca/intermediate/certs/client.lab.local.cert.pem
    ```
    ```
    openssl verify -CAfile /root/ca/intermediate/certs/ca-chain.lab.local.cert.pem \
        /root/ca/intermediate/certs/client.lab.local.cert.pem
    ```

6. (Optional) Export client CA certificate chain, cilent key, and client certificate as a single PFX/P12/PKCS#12 file
    ```
    openssl pkcs12 -export \
        -out /root/ca/intermediate/certs/client.lab.local.cert.pfx \
        -inkey /root/ca/intermediate/private/client.lab.local.key.pem \
        -in /root/ca/intermediate/certs/client.lab.local.cert.pem \
        -certfile /root/ca/intermediate/certs/ca-chain.lab.local.cert.pem
    ```
    ```
    chmod 444 /root/ca/intermediate/certs/client.lab.local.cert.pfx
    ```

# RADIUS/RADSec with FreeRADIUS

## FreeRADIUS Package Installation

1. Update package lists
    ```
    apt update
    ```

2. Install necessary packages
    ```
    apt install freeradius freeradius-utils -y
    ```

3. Configure the **freeradius** daemon to start automatically when system is booted
    ```
    systemctl enable freeradius
    ```

## FreeRADIUS Configuration

> [!TIP]
> When viewing FreeRADIUS configuration files, the following command can be used to look at the contents of the file while excluding all commented lines and whitespace, making it easier to look at applied configuration at a glance
>
> ```
> egrep -v "^\s*(#|$)" 
> ```
>
> ```
> # EXAMPLE:
> egrep -v "^\s*(#|$)" /etc/freeradius/3.0/sites-enabled/tls
> ```

1. Configure RADsec clients (access points) to trust root CA created in previous section (/root/ca/intermeiate/ca-chain.lab.local.cert.pem)

2. Create copies of the server certificate, server key, and CA certificate files (these will be used for (EAP-PEAP/TLS and RADSec)
    ```
    cp /root/ca/intermediate/certs/server.lab.local.cert.pem /etc/freeradius/3.0/certs/
    cp /root/ca/intermediate/private/server.lab.local.key.pem /etc/freeradius/3.0/certs/
    cp /root/ca/intermediate/certs/ca-chain.lab.local.cert.pem /etc/freeradius/3.0/certs/
    ```

3. Create the trusted root certificate file for RADSec (this will be what issued the AP RADSec certificates).
    ```
    nano /etc/freeradius/3.0/certs/ca-meraki.cert.pem
    ```

4. Ensure correct ownership and permissions
    ```
    chown freerad:freerad /etc/freeradius/3.0/certs/*
    chmod 444 /etc/freeradius/3.0/certs/*.cert.pem
    chmod 400 /etc/freeradius/3.0/certs/*.key.pem
    ```

5. Configure the certificates used for EAP-PEAP and EAP-TLS authentication
    ```
    nano /etc/freeradius/3.0/mods-available/eap
    ```
    ```
    # UPDATE THE FOLLOWING LINES, CHANGING WHERE NEEDED
    eap {
            tls-config tls-common {
                    private_key_password = <key_password>
                    private_key_file = ${certdir}/server.lab.local.key.pem
                    certificate_file = ${certdir}/server.lab.local.cert.pem
                    ca_file = ${cadir}/ca-chain.lab.local.cert.pem
            }
    }
    ```
    
6. Define RADIUS clients (access points)
    ```
    nano /etc/freeradius/3.0/clients.conf
    ```
    ```
    # UPDATE THE FOLLOWING LINES, CHANGING WHERE NEEDED
    client access_points {
        ipaddr = 10.0.0.0
        netmask = 8
        secret = radiussharedsecret
    } 
    ```

7. Configure RADsec by enabling the **tls** site, configuring the RADSec certificates, and defining RADSec clients (access points)
    ```
    cd /etc/freeradius/3.0/sites-enabled
    ln -s ../sites-available/tls tls
    ```
    ```
    nano /etc/freeradius/3.0/sites-available/tls
    ```
    ```
    # UPDATE THE FOLLOWING LINES, CHANGING WHERE NEEDED
    listen {
        tls {
                private_key_password = <password>
                private_key_file = ${certdir}/server.lab.local.key.pem
                certificate_file = ${certdir}/server.lab.local.cert.pem
                ca_file = ${cadir}/ca-meraki.cert.pem
        }
    }
    clients radsec {
            client access_points {
                    ipaddr = 10.0.0.0
                    netmask = 8
            }
    }
    ```
8. Configure the **inner-tunnel** site to copy attributes from the inner session to the outer session (such as when using EAP-PEAP or EAP-TTLS).
    ```
    nano /etc/freeradius/3.0/sites-available/inner-tunnel
    ```
    ```
    # UPDATE THE FOLLOWING LINES, CHANGING WHERE NEEDED
    post-auth {
            if (1) {
            }
    }
    ```
9. Define users (examples of EAP-PEAP and EAP-TLS provided).
    ```
    nano /etc/freeradius/3.0/users
    ```
    ```
    # EAP-PEAP
    username Cleartext-Password := "password"
             Session-Timeout := 3600,
             Tunnel-Type := 13,
             Tunnel-Medium-Type := 6,
             Tunnel-Private-Group-Id := 255
    # EAP-TLS
    client@lab.local
             Session-Timeout := 3600
    ```

10. Restart the **freeradius** daemon
    ```
    systemctl restart freeradius
    ```

## FreeRADIUS Validation

1. Validate that the **freeradius** daemon is running
    ```
    systemctl status freeradius
    ```
    ```
    ps -aux | grep freeradius
    ```

2. Validate that the **freeradius** daemon is listening on the correct IP address(es) and port(s)
    ```
    netstat -anoptu | grep freeradius
    ```

## FreeRADIUS Debugging

> [!NOTE]
> If additional debugging is needed (either for the service starting or for client authentication, then the service can be stopped and started ad-hoc with additional flags to enable verbose output.

1. Stop the standard FreeRADIUS daemon
    ```
    systemctl stop freeradius
    ```
2. Start a new FreeRADIUS proccess in the foreground (ad-hoc) with debugging enabled
    ```
    freeradius -fxx -l stdout
    ```
3. Once the logs are obtained, use Ctrl+C to kill the foreground FreeRADIUS process, then start the standard FreeRADIUS daemon again
    ```
    # CTRL+C to end ad-hoc process once output is obtained
    ```
    ```
    systemctl start freeradius
    ```

# LDAP with OpenLDAP
    
## OpenLDAP Package Installation

1. Update package lists
    ```
    apt update
    ```

2. Install necessary packages
    ```
    apt install slapd ldap-utils
    ```

3. Configure the **slapd** daemon to start automatically when the system is booted
    ```
    systemctl enable slapd
    ```

## OpenLDAP Configuration

1. Reconfigure SLAPD. Follow the images below, changing "DNS domain name", "Organization name", and the administrator password as desired
    ```
    dpkg-reconfigure slapd
    ```
![Screenshot 2024-08-16 at 8 48 47 AM](https://github.com/user-attachments/assets/942615ba-19b3-4857-bcee-f23b715d9f7b)
![Screenshot 2024-08-16 at 8 48 55 AM](https://github.com/user-attachments/assets/8bf646bc-21d2-49b7-9d1c-3db9dc5cb105)
![Screenshot 2024-08-16 at 8 49 02 AM](https://github.com/user-attachments/assets/c3479af3-b9ab-405a-bde6-c1bf50eb9ced)
![Screenshot 2024-08-16 at 8 49 13 AM](https://github.com/user-attachments/assets/33bfe3e5-8de1-4bc6-bd2b-0caca1efb3af)
![Screenshot 2024-08-16 at 8 49 21 AM](https://github.com/user-attachments/assets/cb8fde84-14f6-4a91-9df8-432de7bf8f19)
![Screenshot 2024-08-16 at 8 49 29 AM](https://github.com/user-attachments/assets/15581932-8482-4361-b96b-14bcc5256260)
![Screenshot 2024-08-16 at 8 49 35 AM](https://github.com/user-attachments/assets/264a9bfa-f718-46ef-ab78-57c1644a9cae)

2. Make a directory for LDIF (LDAP Data Interchange Files) files
    ```
    mkdir /etc/ldap/ldif_files
    ```
    
3. Create an LDIF file with the base directory (example contents [here](openldap_base.ldif))
    ```
    nano /etc/ldap/ldif_files/base_config.ldif
    ```
 
> [!Note]
> The example base configuration LDIF file linked results in the following LDAP stucture:
> 
> ```
> local                          # dn: dc=local
> └── lab                        # dn: dc=lab,dc=local
>     ├── disable-users          # dn: ou=disabled-users,dc=lab,dc=local
>     ├── groups                 # dn: ou=groups,dc=lab,dc=local
>     │   └── employees          # dn: cn=employees,ou=groups,dc=lab,dc=local
>     │       ├── jane.doe       # *** membership defined by "employees" entry
>     │       └── john.doe       # *** membership defined by "employees" entry
>     └── users                  # dn: ou=users,dc=lab,dc=local
>         ├── dept1              # dn: ou=dept1,ou=users,dc=lab,dc=local
>         │   └── john.doe       # dn: uid=john.doe,ou=dept1,ou=users,dc=lab,dc=local
>         ├── dept2              # dn: ou=dept2,ou=users,dc=lab,dc=local
>         │   └── jane.doe       # dn: uid=jane.doe,ou=dept2,ou=users,dc=lab,dc=local
>         └── service.account    # dn: uid=service.meraki,ou=users,dc=lab,dc=local
> ```


4. Add the base directory to the LDAP directory database
    ```
    ldapadd -x -D cn=admin,dc=lab,dc=local -W -f /etc/ldap/ldif_files/base_config.ldif
    ```

5. Make directories for the LDAP SSL/TLS certificates and private key
    ```
    mkdir -p /etc/ssl/openldap/certs /etc/ssl/openldap/private
    ```

6. Create copies of the server certificate, CA certificate, and private key (unencrypted)
    ```
    cp /root/ca/intermediate/certs/ca-chain.lab.local.cert.pem /etc/ssl/openldap/certs
    cp /root/ca/intermediate/certs/server.lab.local.cert.pem /etc/ssl/openldap/certs
    ```
    ```
    openssl rsa -in /root/ca/intermediate/private/server.lab.local.key.pem \
        -out /etc/ssl/openldap/private/server.lab.local.key.pem
    ```
    ```
    chmod 400 /etc/ssl/openldap/private/server.lab.local.key.pem
    chown -R openldap:openldap /etc/ssl/openldap
    ```

7. Create an LDIF file to add SSL/TLS certificate configuration (example contents [here](openldap_ssl.ldif))
    ```
    nano /etc/ldap/ldif_files/ldap_ssl.ldif
    ```

8. Add the SSL/TLS certificate configuration
    ```
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /etc/ldap/ldif_files/ldap_ssl.ldif
    ```

9. Enable Secure LDAP (LDAPS)
    ```
    nano /etc/default/slapd
    ```
    ```
    # UPDATE THE FOLLOWING LINES, CHANGING WHERE NEEDED
    SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"
    ```

9. Restart the **slapd** daemon
    ```
    systemctl restart slapd
    ```

## OpenLDAP Validation

1. Validate that the **slapd** daemon is running
    ```
    systemctl status slapd
    ```
    ```
    ps -aux | grep slapd
    ```

2. Validate that the **slapd** daemon is listening on the correct IP address(es) and port(s)
    ```
    netstat -anoptu | grep slapd
    ```

3. Validate SSL/TLS certificate configuration
    ```
    slapcat -b "cn=config" | grep -E "olcTLS"
    ```

> [!Note]
> To view the full LDAP directory database:
> ```
> slapcat
> ```
>
> To view the full LDAP configuration database:
> ```
> slapcat -b "cn=config"
> ```

4. Validate LDAP locally
    ```
    ldapsearch -x -H ldap://["127.0.0.1"]:389 \
        -D "uid=service.account,ou=users,dc=lab,dc=local" \
        -w "password" -b "ou=users,dc=lab,dc=local" --  "(uid=john.doe)" "dn"
    ```
