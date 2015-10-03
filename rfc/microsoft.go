package rfc
const MicrosoftExtensions = `
DEFINITIONS IMPLICIT TAGS ::= BEGIN
id-microsoft-szOID-CERTSRV-CA-VERSION OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 311 21 1 }
Microsoft-CERTSRV-CA-VERSION ::= INTEGER
id-microsoft-szOID-ENROLL-CERTTYPE-EXTENSION OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 311 20 2 }
Microsoft-ENROLL-CERTTYPE-EXTENSION ::= BMPString
id-microsoft-szOID-CERTIFICATE-TEMPLATE OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 311 21 7 }
MicrosoftCertificateTemplate ::= SEQUENCE {
 templateID OBJECT IDENTIFIER,
 templateMajorVersion TemplateVersion,
 templateMinorVersion TemplateVersion OPTIONAL
}
TemplateVersion ::= INTEGER (0..4294967295)

id-Extension-extnValue-szOID-CERTSRV-CA-VERSION OBJECT IDENTIFIER ::= id-microsoft-szOID-CERTSRV-CA-VERSION
Extension-extnValue-szOID-CERTSRV-CA-VERSION ::= Microsoft-CERTSRV-CA-VERSION

id-Extension-extnValue-szOID-ENROLL-CERTTYPE-EXTENSION OBJECT IDENTIFIER ::= id-microsoft-szOID-ENROLL-CERTTYPE-EXTENSION
Extension-extnValue-szOID-ENROLL-CERTTYPE-EXTENSION ::= Microsoft-ENROLL-CERTTYPE-EXTENSION

id-Extension-extnValue-szOID-CERTIFICATE-TEMPLATE OBJECT IDENTIFIER ::= id-microsoft-szOID-CERTIFICATE-TEMPLATE
Extension-extnValue-szOID-CERTIFICATE-TEMPLATE ::= MicrosoftCertificateTemplate


END
`
