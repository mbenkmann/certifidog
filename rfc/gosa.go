package rfc
const GOsaExtensions = `DEFINITIONS IMPLICIT TAGS ::= BEGIN id-msb OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 45753 } id-msb-gosa OBJECT IDENTIFIER ::= { id-msb 1 } gosa-gn-my-server OBJECT IDENTIFIER ::= { id-msb-gosa 1 } gosa-gn-config-file OBJECT IDENTIFIER ::= { id-msb-gosa 2 } gosa-gn-srv-record OBJECT IDENTIFIER ::= { id-msb-gosa 3 } gosa-gn-my-peer OBJECT IDENTIFIER ::= { id-msb-gosa 4 } gosa-ce-connectionLimits OBJECT IDENTIFIER ::= { id-msb-gosa 5 } id-Extension-extnValue-gosa-ce-connectionLimits OBJECT IDENTIFIER ::= gosa-ce-connectionLimits Extension-extnValue-gosa-ce-connectionLimits ::= GosaConnectionLimits GosaConnectionLimits ::= SEQUENCE { totalTime [0] INTEGER OPTIONAL, totalBytes [1] INTEGER OPTIONAL, messageBytes [2] INTEGER OPTIONAL, connPerHour [3] INTEGER OPTIONAL, connParallel [4] INTEGER OPTIONAL, maxLogFiles [5] INTEGER OPTIONAL, maxAnswers [6] INTEGER OPTIONAL, communicateWith [7] SEQUENCE OF UTF8String OPTIONAL } gosa-ce-accessControl OBJECT IDENTIFIER ::= { id-msb-gosa 6 } id-Extension-extnValue-gosa-ce-accessControl OBJECT IDENTIFIER ::= gosa-ce-accessControl Extension-extnValue-gosa-ce-accessControl ::= GosaAccessControl GosaAccessControl ::= SEQUENCE { misc [0] GosaAccessMisc OPTIONAL, query [1] GosaAccessQuery OPTIONAL, jobs [2] GosaAccessJobs OPTIONAL, incoming [3] GosaAccessLDAPIncoming OPTIONAL, ldapUpdate [4] GosaAccessLDAPUpdate OPTIONAL, detectedHw [5] GosaAccessLDAPDetectedHardware OPTIONAL } GosaAccessMisc ::= BIT STRING { debug(0), wake(1), peer(2) } GosaAccessQuery ::= BIT STRING { queryAll(0), queryJobs(1) } GosaAccessJobs ::= BIT STRING { jobsAll(0), lock(1), unlock(2), shutdown(3), wake(4), abort(5), install(6), update(7), modifyJobs(8), newSys(9) } GosaAccessLDAPIncoming ::= SEQUENCE OF UTF8String GosaAccessLDAPUpdate ::= BIT STRING { cn(0), ip(1), mac(2), dh(3) } GosaAccessLDAPDetectedHardware ::= BIT STRING { unprompted(0), template(1), dn(2), cn(3), ipHostNumber(4), macAddress(5) } END`
