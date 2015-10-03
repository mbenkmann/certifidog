package rfc
const EntrustExtensions = `
DEFINITIONS IMPLICIT TAGS ::= BEGIN
id-entrustVersInfo OBJECT IDENTIFIER ::= { 1 2 840 113533 7 65 0 }
EntrustVersInfoSyntax ::= OCTET STRING
id-Extension-extnValue-entrustVersInfo OBJECT IDENTIFIER ::= id-entrustVersInfo
Extension-extnValue-entrustVersInfo ::= EntrustVersInfoSyntax

END
`
