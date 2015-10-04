package rfc
const SETExtensions = `
DEFINITIONS IMPLICIT TAGS ::= BEGIN
id-set OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) internationalRA(23) set(42) }
id-set-attribute OBJECT IDENTIFIER ::= { id-set 3 }
id-set-certExt OBJECT IDENTIFIER ::= { id-set 7 }
id-set-attribute-cert OBJECT IDENTIFIER ::= { id-set-attribute 0 }
id-set-rootKeyThumb OBJECT IDENTIFIER ::= { id-set-attribute-cert 0 }
id-set-additionalPolicy OBJECT IDENTIFIER ::= { id-set-attribute-cert 1 }
id-set-hashedRootKey OBJECT IDENTIFIER ::= { id-set-certExt 0 }
HashedRootKeySyntax ::= SEQUENCE {
 rootKeyThumbprint  DigestedData
}
    
DigestedData ::= SEQUENCE {
 ddVersion INTEGER { ddVer0(0) },
 digestAlgorithm  AlgorithmIdentifier,
 contentInfo ContentInfo,
 digest Digest
}

ContentInfo ::= SEQUENCE {
 contentType  ContentType,
 content [0] EXPLICIT ANY OPTIONAL
}

ContentType ::= OBJECT IDENTIFIER
Digest ::= OCTET STRING (SIZE(1..20))

id-Extension-extnValue-hashedRootKey OBJECT IDENTIFIER ::= id-set-hashedRootKey
Extension-extnValue-hashedRootKey ::= HashedRootKeySyntax


END
`
