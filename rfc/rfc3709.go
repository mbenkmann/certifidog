package rfc
const LogotypeCertExtension = `DEFINITIONS IMPLICIT TAGS ::= BEGIN id-pe-logotype OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) id-pe(1) 12 } LogotypeExtn ::= SEQUENCE { communityLogos [0] EXPLICIT SEQUENCE OF LogotypeInfo OPTIONAL, issuerLogo [1] EXPLICIT LogotypeInfo OPTIONAL, subjectLogo [2] EXPLICIT LogotypeInfo OPTIONAL, otherLogos [3] EXPLICIT SEQUENCE OF OtherLogotypeInfo OPTIONAL } LogotypeInfo ::= CHOICE { direct [0] LogotypeData, indirect [1] LogotypeReference } LogotypeData ::= SEQUENCE { image SEQUENCE OF LogotypeImage OPTIONAL, audio [1] SEQUENCE OF LogotypeAudio OPTIONAL } LogotypeImage ::= SEQUENCE { imageDetails LogotypeDetails, imageInfo LogotypeImageInfo OPTIONAL } LogotypeAudio ::= SEQUENCE { audioDetails LogotypeDetails, audioInfo LogotypeAudioInfo OPTIONAL } LogotypeDetails ::= SEQUENCE { mediaType IA5String, logotypeHash SEQUENCE SIZE (1..MAX) OF HashAlgAndValue, logotypeURI SEQUENCE SIZE (1..MAX) OF IA5String } LogotypeImageInfo ::= SEQUENCE { type [0] LogotypeImageType DEFAULT color, fileSize INTEGER, xSize INTEGER, ySize INTEGER, resolution LogotypeImageResolution OPTIONAL, language [4] IA5String OPTIONAL } LogotypeImageType ::= INTEGER { grayScale(0), color(1) } LogotypeImageResolution ::= CHOICE { numBits [1] INTEGER, tableSize [2] INTEGER } LogotypeAudioInfo ::= SEQUENCE { fileSize INTEGER, playTime INTEGER, channels INTEGER, sampleRate [3] INTEGER OPTIONAL, language [4] IA5String OPTIONAL } OtherLogotypeInfo ::= SEQUENCE { logotypeType OBJECT IDENTIFIER, info LogotypeInfo } LogotypeReference ::= SEQUENCE { refStructHash SEQUENCE SIZE (1..MAX) OF HashAlgAndValue, refStructURI SEQUENCE SIZE (1..MAX) OF IA5String } HashAlgAndValue ::= SEQUENCE { hashAlg AlgorithmIdentifier, hashValue OCTET STRING } id-logo OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) 20 } id-logo-loyalty OBJECT IDENTIFIER ::= { id-logo 1 } id-logo-background OBJECT IDENTIFIER ::= { id-logo 2 } id-logo-certImage OBJECT IDENTIFIER ::= { id-logo 3 } END`