package rfc
const DisassemblerMappings = `
DEFINITIONS IMPLICIT TAGS ::= BEGIN

id-AlgorithmIdentifier-parameters-ecdsa OBJECT IDENTIFIER ::= id-ecPublicKey
AlgorithmIdentifier-parameters-ecdsa ::= ECParameters
id-Extension-extnValue-authorityKeyIdentifier OBJECT IDENTIFIER ::= id-ce-authorityKeyIdentifier
Extension-extnValue-authorityKeyIdentifier ::= AuthorityKeyIdentifier
id-Extension-extnValue-subjectKeyIdentifier OBJECT IDENTIFIER ::= id-ce-subjectKeyIdentifier
Extension-extnValue-subjectKeyIdentifier ::= SubjectKeyIdentifier
id-Extension-extnValue-keyUsage OBJECT IDENTIFIER ::= id-ce-keyUsage
Extension-extnValue-keyUsage ::= KeyUsage
id-Extension-extnValue-privateKeyUsagePeriod OBJECT IDENTIFIER ::= id-ce-privateKeyUsagePeriod
Extension-extnValue-privateKeyUsagePeriod ::= PrivateKeyUsagePeriod
id-Extension-extnValue-certificatePolicies OBJECT IDENTIFIER ::= id-ce-certificatePolicies
Extension-extnValue-certificatePolicies ::= CertificatePolicies
id-Extension-extnValue-policyMappings OBJECT IDENTIFIER ::= id-ce-policyMappings
Extension-extnValue-policyMappings ::= PolicyMappings
id-Extension-extnValue-subjectAltName OBJECT IDENTIFIER ::= id-ce-subjectAltName
Extension-extnValue-subjectAltName ::= SubjectAltName
id-Extension-extnValue-issuerAltName OBJECT IDENTIFIER ::= id-ce-issuerAltName
Extension-extnValue-issuerAltName ::= IssuerAltName
id-Extension-extnValue-subjectDirectoryAttributes OBJECT IDENTIFIER ::= id-ce-subjectDirectoryAttributes
Extension-extnValue-subjectDirectoryAttributes ::= SubjectDirectoryAttributes
id-Extension-extnValue-basicConstraints OBJECT IDENTIFIER ::= id-ce-basicConstraints
Extension-extnValue-basicConstraints ::= BasicConstraints
id-Extension-extnValue-nameConstraints OBJECT IDENTIFIER ::= id-ce-nameConstraints
Extension-extnValue-nameConstraints ::= NameConstraints
id-Extension-extnValue-policyConstraints OBJECT IDENTIFIER ::= id-ce-policyConstraints
Extension-extnValue-policyConstraints ::= PolicyConstraints
id-Extension-extnValue-cRLDistributionPoints OBJECT IDENTIFIER ::= id-ce-cRLDistributionPoints
Extension-extnValue-cRLDistributionPoints ::= CRLDistributionPoints
id-Extension-extnValue-extKeyUsage OBJECT IDENTIFIER ::= id-ce-extKeyUsage
Extension-extnValue-extKeyUsage ::= ExtKeyUsageSyntax
id-Extension-extnValue-inhibitAnyPolicy OBJECT IDENTIFIER ::= id-ce-inhibitAnyPolicy
Extension-extnValue-inhibitAnyPolicy ::= InhibitAnyPolicy
id-Extension-extnValue-freshestCRL OBJECT IDENTIFIER ::= id-ce-freshestCRL
Extension-extnValue-freshestCRL ::= FreshestCRL
id-Extension-extnValue-authorityInfoAccess OBJECT IDENTIFIER ::= id-pe-authorityInfoAccess
Extension-extnValue-authorityInfoAccess ::= AuthorityInfoAccessSyntax
id-Extension-extnValue-subjectInfoAccess OBJECT IDENTIFIER ::= id-pe-subjectInfoAccess
Extension-extnValue-subjectInfoAccess ::= SubjectInfoAccessSyntax
id-Extension-extnValue-cRLNumber OBJECT IDENTIFIER ::= id-ce-cRLNumber
Extension-extnValue-cRLNumber ::= CRLNumber
id-Extension-extnValue-issuingDistributionPoint OBJECT IDENTIFIER ::= id-ce-issuingDistributionPoint
Extension-extnValue-issuingDistributionPoint ::= IssuingDistributionPoint
id-Extension-extnValue-deltaCRLIndicator OBJECT IDENTIFIER ::= id-ce-deltaCRLIndicator
Extension-extnValue-deltaCRLIndicator ::= BaseCRLNumber
id-Extension-extnValue-cRLReasons OBJECT IDENTIFIER ::= id-ce-cRLReasons
Extension-extnValue-cRLReasons ::= CRLReason
id-Extension-extnValue-certificateIssuer OBJECT IDENTIFIER ::= id-ce-certificateIssuer
Extension-extnValue-certificateIssuer ::= CertificateIssuer
id-Extension-extnValue-holdInstructionCode OBJECT IDENTIFIER ::= id-ce-holdInstructionCode
Extension-extnValue-holdInstructionCode ::= HoldInstructionCode
id-Extension-extnValue-invalidityDate OBJECT IDENTIFIER ::= id-ce-invalidityDate
Extension-extnValue-invalidityDate ::= InvalidityDate

id-Extension-extnValue-logotype OBJECT IDENTIFIER ::= id-pe-logotype
Extension-extnValue-logotype ::= LogotypeExtn

id-Extension-extnValue-netscapeCertType OBJECT IDENTIFIER ::= id-netscapeCertType
Extension-extnValue-netscapeCertType ::= NetscapeCertType
id-Extension-extnValue-netscapeBaseURL OBJECT IDENTIFIER ::= id-netscapeBaseURL
Extension-extnValue-netscapeBaseURL ::= NetscapeBaseURL
id-Extension-extnValue-netscapeRevocationURL OBJECT IDENTIFIER ::= id-netscapeRevocationURL
Extension-extnValue-netscapeRevocationURL ::= NetscapeRevocationURL
id-Extension-extnValue-netscapeCArevocationURL OBJECT IDENTIFIER ::= id-netscapeCArevocationURL
Extension-extnValue-netscapeCArevocationURL ::= NetscapeCArevocationURL
id-Extension-extnValue-netscapeCertRenewalURL  OBJECT IDENTIFIER ::= id-netscapeCertRenewalURL
Extension-extnValue-netscapeCertRenewalURL ::= NetscapeCertRenewalURL
id-Extension-extnValue-netscapeCApolicyURL OBJECT IDENTIFIER ::= id-netscapeCApolicyURL
Extension-extnValue-netscapeCApolicyURL ::= NetscapeCApolicyURL
id-Extension-extnValue-netscapeSSLserverName OBJECT IDENTIFIER ::= id-netscapeSSLserverName
Extension-extnValue-netscapeSSLserverName ::= NetscapeSSLserverName
id-Extension-extnValue-netscapeComment OBJECT IDENTIFIER ::= id-netscapeComment
Extension-extnValue-netscapeComment ::= NetscapeComment


END
`
