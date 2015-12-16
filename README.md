# certifidog
 Makes X.509 certificate creation easy, e.g. for a self-signed HTTPS server or a VPN.

## certificate-assembler
Manpage: https://github.com/mbenkmann/certifidog/wiki/certificate-assembler.1

## certificate-disassembler
Manpage: https://github.com/mbenkmann/certifidog/wiki/certificate-disassembler.1

## Example of input file for certificate-assembler
....
{
  "ca-keyfile": "ca.key",
  "keyfile1": "1.key",

  "ca-certfile": "ca.cert",
  "certfile1": "1.cert",
  
  "ca-generatedKey": "$secp256r1 keygen()",
  "generatedKey1": "$secp256r1 keygen()",
  
  "_ca-savekey": "$ca-generatedKey encode(PEM) ca-keyfile write(if-missing)",
  "_savekey1": "$generatedKey1 encode(PEM) keyfile1 write(if-missing)",
  
  "ca-key": "$ca-keyfile key()",
  "key1": "$keyfile1 key()",
  
  "sigAlg": { "algorithm": "$ecdsa-with-SHA256", "parameters": null },
  
  "issuer-id": {
    "rdnSequence": [
      [ { "type": "$id-at-commonName",       "value": "CA" } ]
    ]
  },
  
  ############# CA CERTIFICATE ############################
  "ca-certificate": {
    "pubkey":  "$ca-key",
    "signkey": "$ca-key",
    "certfile": "$ca-certfile",
      
    "certificate": {
      "tbsCertificate": {
        "version": "v3",
        "serialNumber": 1,
        "signature": "$sigAlg",
        "issuer": "$issuer-id",
        "validity": {
          "notBefore": { "utcTime": "151101000000Z" },
          "notAfter":  { "utcTime": "251101000000Z" }
        },
        
        # self-signed => subject is same as issuer
        "subject": "$issuer",
        
        "subjectPublicKeyInfo": "$pubkey subjectPublicKeyInfo()",
        "extensions": [
          {
            "extnID": "$id-ce-basicConstraints",
            "critical": true,
            "extnValue": "$constraints BasicConstraints encode(DER)",
            "constraints": { "cA": true }
          },
          {
            "extnID": "$id-ce-keyUsage",
            "critical": true,
            "extnValue": "$'keyCertSign, cRLSign' KeyUsage encode(DER)"
          }
        ]
      },
      "signatureAlgorithm": "$sigAlg",
      "signature": "$tbsCertificate TBSCertificate encode(DER) signkey sigAlg sign()"
    },
    "output": "$certificate Certificate encode(PEM) certfile write(if-missing)"
  },
  
  ############# CERTIFICATE 1 ############################
  "certificate1": {
    "pubkey":  "$key1",
    "signkey": "$ca-key",
    "certfile": "$certfile1",
      
    "certificate": {
      "tbsCertificate": {
        "version": "v3",
        
        "serialNumber": 2,
        
        "signature": "$sigAlg",
        "issuer": "$issuer-id",
        "validity": {
          "notBefore": { "utcTime": "151101000000Z" },
          "notAfter":  { "utcTime": "251101000000Z" }
        },
        
        "subject": {
          "rdnSequence": [
            [ { "type": "$id-at-commonName",       "value": "Cert1" } ]
          ]
        },
            
        "subjectPublicKeyInfo": "$pubkey subjectPublicKeyInfo()",
        "extensions": [
          {
            "extnID": "$id-ce-subjectAltName",
            "critical": false,
            "extnValue": "$san SubjectAltName encode(DER)",
            "san": [ { "iPAddress": "$192.168.1.2" } ]
          },
          {
            "extnID":"$id-ce-keyUsage",
            "extnValue":"$'digitalSignature' KeyUsage encode(DER)"
          },
          {
            "extnID": "$id-ce-extKeyUsage",
            "critical": false,
            "extnValue": "$extkeyusage ExtKeyUsageSyntax encode(DER)",
            "extkeyusage": [ "$id-kp-serverAuth", "$id-kp-clientAuth" ]
          }
        ]
      },
      "signatureAlgorithm": "$sigAlg",
      "signature": "$tbsCertificate TBSCertificate encode(DER) signkey sigAlg sign()"
    },
    "output": "$certificate Certificate encode(PEM) certfile write(if-missing)"
  }
}

## Example of output file of certificate-disassembler
....
{
  "certificate": {
    "tbsCertificate": {
      "version": "v3",
      "serialNumber": "$6022691278034106891 CertificateSerialNumber",
      "signature": { "algorithm": "$sha256WithRSAEncryption", "parameters": null },
      "issuer": {
        "rdnSequence": [
          [ { "type": "$id-at-countryName", "value": "$'US' PrintableString" } ],
          [
            {
              "type": "$id-at-organizationName",
              "value": "$'Google Inc' PrintableString"
            }
          ],
          [
            {
              "type": "$id-at-commonName",
              "value": "$'Google Internet Authority G2' PrintableString"
            }
          ]
        ]
      },
      "validity": {
        "notBefore": { "utcTime": "150808122751Z" },
        "notAfter": { "utcTime": "151106000000Z" }
      },
      "subject": {
        "rdnSequence": [
          [ { "type": "$id-at-countryName", "value": "$'US' PrintableString" } ],
          [ { "type": "$id-at-stateOrProvinceName", "value": "California" } ],
          [ { "type": "$id-at-localityName", "value": "Mountain View" } ],
          [ { "type": "$id-at-organizationName", "value": "Google Inc" } ],
          [ { "type": "$id-at-commonName", "value": "*.google.com" } ]
        ]
      },
      "subjectPublicKeyInfo": {
        "algorithm": { "algorithm": "$id-ecPublicKey", "parameters": "$secp256r1" },
        "subjectPublicKey": "0x04 5F C1 0B 99 C1 DC 6C 8E DF B9 E7 17 B9 BC 79 63 30 A7 13 65 66 00 CA 12 7B 06 F0 6D 75 22 56 32 13 5A 2A 14 EA 85 E9 20 FC FE 9B 32 B1 D4 8E 70 2F F7 9E F0 A0 49 11 DD C8 68 05 3D 59 1E 76 7E"
      },
      "extensions": [
        {
          "extnID": "$id-ce-extKeyUsage",
          "critical": false,
          "extnValue": "$_temp999999 ExtKeyUsageSyntax encode(DER)",
          "_temp999999": [ "$id-kp-serverAuth", "$id-kp-clientAuth" ]
        },
        {
          "extnID": "$id-ce-subjectAltName",
          "critical": false,
          "extnValue": "$_temp999998 SubjectAltName encode(DER)",
          "_temp999998": [
            { "dNSName": "*.google.com" },
            { "dNSName": "*.android.com" },
            { "dNSName": "*.appengine.google.com" },
            { "dNSName": "*.cloud.google.com" },
            { "dNSName": "*.google-analytics.com" },
            { "dNSName": "*.google.ca" },
            { "dNSName": "*.google.cl" },
            { "dNSName": "*.google.co.in" },
            { "dNSName": "*.google.co.jp" },
            { "dNSName": "*.google.co.uk" },
            { "dNSName": "*.google.com.ar" },
            { "dNSName": "*.google.com.au" },
            { "dNSName": "*.google.com.br" },
            { "dNSName": "*.google.com.co" },
            { "dNSName": "*.google.com.mx" },
            { "dNSName": "*.google.com.tr" },
            { "dNSName": "*.google.com.vn" },
            { "dNSName": "*.google.de" },
            { "dNSName": "*.google.es" },
            { "dNSName": "*.google.fr" },
            { "dNSName": "*.google.hu" },
            { "dNSName": "*.google.it" },
            { "dNSName": "*.google.nl" },
            { "dNSName": "*.google.pl" },
            { "dNSName": "*.google.pt" },
            { "dNSName": "*.googleadapis.com" },
            { "dNSName": "*.googleapis.cn" },
            { "dNSName": "*.googlecommerce.com" },
            { "dNSName": "*.googlevideo.com" },
            { "dNSName": "*.gstatic.cn" },
            { "dNSName": "*.gstatic.com" },
            { "dNSName": "*.gvt1.com" },
            { "dNSName": "*.gvt2.com" },
            { "dNSName": "*.metric.gstatic.com" },
            { "dNSName": "*.urchin.com" },
            { "dNSName": "*.url.google.com" },
            { "dNSName": "*.youtube-nocookie.com" },
            { "dNSName": "*.youtube.com" },
            { "dNSName": "*.youtubeeducation.com" },
            { "dNSName": "*.ytimg.com" },
            { "dNSName": "android.com" },
            { "dNSName": "g.co" },
            { "dNSName": "goo.gl" },
            { "dNSName": "google-analytics.com" },
            { "dNSName": "google.com" },
            { "dNSName": "googlecommerce.com" },
            { "dNSName": "urchin.com" },
            { "dNSName": "youtu.be" },
            { "dNSName": "youtube.com" },
            { "dNSName": "youtubeeducation.com" }
          ]
        },
        {
          "extnID": "$id-ce-keyUsage",
          "critical": false,
          "extnValue": "$'digitalSignature' KeyUsage encode(DER)"
        },
        {
          "extnID": "$id-pe-authorityInfoAccess",
          "critical": false,
          "extnValue": "$_temp999997 AuthorityInfoAccessSyntax encode(DER)",
          "_temp999997": [
            {
              "accessMethod": "$id-ad-caIssuers",
              "accessLocation": { "uniformResourceIdentifier": "http://pki.google.com/GIAG2.crt" }
            },
            {
              "accessMethod": "$id-ad-ocsp",
              "accessLocation": { "uniformResourceIdentifier": "http://clients1.google.com/ocsp" }
            }
          ]
        },
        {
          "extnID": "$id-ce-subjectKeyIdentifier",
          "critical": false,
          "extnValue": "$'0xCB 84 61 37 29 FC 1E 9A 3E 5C 50 47 8B 82 60 AF 13 49 6D 95' decode(hex) SubjectKeyIdentifier encode(DER)"
        },
        {
          "extnID": "$id-ce-basicConstraints",
          "critical": true,
          "extnValue": "$_temp999996 BasicConstraints encode(DER)",
          "_temp999996": { "cA": false }
        },
        {
          "extnID": "$id-ce-authorityKeyIdentifier",
          "critical": false,
          "extnValue": "$_temp999995 AuthorityKeyIdentifier encode(DER)",
          "_temp999995": {
            "keyIdentifier": "$'0x4A DD 06 16 1B BC F6 68 B5 76 F5 81 B6 BB 62 1A BA 5A 81 2F' decode(hex)"
          }
        },
        {
          "extnID": "$id-ce-certificatePolicies",
          "critical": false,
          "extnValue": "$_temp999994 CertificatePolicies encode(DER)",
          "_temp999994": [ { "policyIdentifier": "$1.3.6.1.4.1.11129.2.5.1" } ]
        },
        {
          "extnID": "$id-ce-cRLDistributionPoints",
          "critical": false,
          "extnValue": "$_temp999993 CRLDistributionPoints encode(DER)",
          "_temp999993": [
            {
              "distributionPoint": {
                "fullName": [ { "uniformResourceIdentifier": "http://pki.google.com/GIAG2.crl" } ]
              }
            }
          ]
        }
      ]
    },
    "signatureAlgorithm": { "algorithm": "$sha256WithRSAEncryption", "parameters": null },
    "signature": "0x4C 97 AA 66 EE C2 C7 71 38 D8 2E CC 6C F4 89 F4 90 5F 7A BC 78 84 F7 60 90 B0 13 E1 ED E4 91 BE CA A2 45 30 67 50 5B 0B D3 58 77 D0 44 07 A3 D1 34 7B A4 19 9E 43 37 E8 D2 21 F7 D7 3C 9F B2 D4 32 57 08 E1 05 1E D7 53 D5 CC BF 3A D1 B8 8C 81 BB 39 02 05 8C 62 39 70 28 1D 12 B3 C4 17 C2 B7 6C B9 A1 85 C3 52 63 0A 85 69 70 C1 F1 76 DC 1F F3 D6 97 99 64 43 A6 76 72 2C FF 41 8D 93 02 03 D3 5F F9 AA 14 86 F4 E2 2A BE CD 45 D5 B9 F0 A6 BA 0D DD 58 F5 33 21 CE DD DD 2F 6E 81 2A 90 10 D0 82 E1 8A FA DC 40 C1 E1 B7 76 19 0E B0 80 F4 08 62 FB A6 0A F1 9C 42 C8 52 CD A4 5D EB 9E 2A 41 29 D6 92 13 4F DC 48 D2 36 60 14 CB FE 1E 27 57 E9 D9 E3 2C 6B F0 EA B8 DE 74 5A D4 12 CF C2 2C 32 AC 1C 4F F9 A9 E7 A7 CE B4 F0 FB 7E 89 47 D5 E7 62 9E 51 73 1A D0 5D 20 AC A4 FD 77 DB F8"
  },
  "output": "$certificate Certificate encode(PEM) 'test/googlecom.crt' write()"
}
