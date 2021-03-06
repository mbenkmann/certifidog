package main

import (
         "os"
         "fmt"
         "io/ioutil"
         "encoding/pem"
         "crypto/x509"
         
         "../asn1"
         "../rfc"
       )

var KeyUsageString = map[x509.KeyUsage]string{
  x509.KeyUsageDigitalSignature:  "digital signature",
  x509.KeyUsageContentCommitment: "content commitment",
  x509.KeyUsageKeyEncipherment:   "key encipherment",
  x509.KeyUsageDataEncipherment:  "data encipherment",
  x509.KeyUsageKeyAgreement:      "key agreement",
  x509.KeyUsageCertSign:          "certificate signing",
  x509.KeyUsageCRLSign:           "CRL signing",
  x509.KeyUsageEncipherOnly:      "encipherment ONLY",
  x509.KeyUsageDecipherOnly:      "decipherment ONLY",
}

var ExtKeyUsageString = map[x509.ExtKeyUsage]string {
  x509.ExtKeyUsageAny:        "any",
  x509.ExtKeyUsageServerAuth: "server authentication",
  x509.ExtKeyUsageClientAuth: "client authentication",
  x509.ExtKeyUsageCodeSigning: "code signing",
  x509.ExtKeyUsageEmailProtection: "email protection",
  x509.ExtKeyUsageIPSECEndSystem: "IPSEC end system",
  x509.ExtKeyUsageIPSECTunnel: "IPSEC tunnel",
  x509.ExtKeyUsageIPSECUser: "IPSEC user",
  x509.ExtKeyUsageTimeStamping: "time stamping",
  x509.ExtKeyUsageOCSPSigning: "OCSP signing",
  x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MicrosoftServerGatedCrypto",
  x509.ExtKeyUsageNetscapeServerGatedCrypto: "NetscapeServerGatedCrypto",
}

func main() {
  if len(os.Args) != 2 {
    fmt.Fprintf(os.Stderr, "USAGE: %v <pem.cert>\n", "analysecert")
    os.Exit(1)
  }

  data, err := ioutil.ReadFile(os.Args[1])
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  block, rest := pem.Decode(data)
  if len(rest) != 0 {
    fmt.Fprintf(os.Stderr, "Garbage at end of file:\n%v\n", rest)
    os.Exit(1)
  }
    
  fmt.Fprintf(os.Stdout, "TYPE: %v\n", block.Type)
  if len(block.Headers) > 0 {
    fmt.Fprintf(os.Stdout, "HEADERS: %v\n", block.Headers)
  }

  data = block.Bytes
  cert, err := x509.ParseCertificate(data)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  fmt.Fprintf(os.Stdout, "Version: %v\nSerial no.: %v\nIssuer: %v\nSubject: %v\nNotBefore: %v\nNotAfter: %v\n", cert.Version, cert.SerialNumber, cert.Issuer, cert.Subject, cert.NotBefore, cert.NotAfter)
  for k := range KeyUsageString {
    if cert.KeyUsage & k != 0 {
      fmt.Fprintf(os.Stdout, "KeyUsage: %v\n", KeyUsageString[k])
    }
  }
  
  for _, ext := range cert.Extensions {
    fmt.Fprintf(os.Stdout, "Extension: %v critical=%v  % 02X\n", ext.Id, ext.Critical, ext.Value)
  }
  
  for _, ext := range cert.ExtKeyUsage {
    fmt.Fprintf(os.Stdout, "ExtKeyUsage: %v\n", ExtKeyUsageString[ext])
  }
  
  for _, ext := range cert.UnknownExtKeyUsage {
    fmt.Fprintf(os.Stdout, "ExtKeyUsage: %v\n", ext)
  }
  
  if cert.BasicConstraintsValid {
    fmt.Fprintf(os.Stdout, "IsCA: %v\n", cert.IsCA)
    if cert.MaxPathLen > 0 {
      fmt.Fprintf(os.Stdout, "MaxPathLen: %v\n", cert.MaxPathLen)
    }
  }
  
  fmt.Fprintf(os.Stdout, "SubjectKeyId: % 02X\nAuthorityKeyId: % 02X\n", cert.SubjectKeyId, cert.AuthorityKeyId)
  fmt.Fprintf(os.Stdout, "OCSPServer: %v\nIssuingCertificateURL: %v\n", cert.OCSPServer, cert.IssuingCertificateURL)
  fmt.Fprintf(os.Stdout, "DNSNames: %v\nEmailAddresses: %v\nIPAddresses: %v\n", cert.DNSNames, cert.EmailAddresses, cert.IPAddresses)
  
  fmt.Fprintf(os.Stdout, "PermittedDNSDomainsCritical: %v\nPermittedDNSDomains: %v\n", cert.PermittedDNSDomainsCritical, cert.PermittedDNSDomains)
  
  fmt.Fprintf(os.Stdout, "CRLDistributionPoints: %v\nPolicyIdentifiers: %v\n", cert.CRLDistributionPoints, cert.PolicyIdentifiers)
  
  fmt.Fprintf(os.Stdout, "%v\n", asn1.AnalyseDER(data))
  
  asn1.Debug = false
  unmarshaled := asn1.UnmarshalDER(data, 0)
  if unmarshaled == nil {
    fmt.Fprintf(os.Stderr, "Could not unmarshal DER data\n")
  } else {
    unmarshaled = unmarshaled.Data[asn1.Rawtag([]byte{0x30})].(*asn1.UnmarshalledConstructed)
    //printkeys(unmarshaled,"")
    
    var defs asn1.Definitions
  
    /* parse definitions from RFC 5280 */
    if err := defs.Parse(rfc.PKIX1Explicit88); err != nil { panic(err) }
    if err := defs.Parse(rfc.PKIX1Implicit88); err != nil { panic(err) }
    
    output, err := defs.Instantiate("Certificate", unmarshaled)
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
    }
    
    equal := false
    output_der := output.DER()
    if len(output_der) == len(data) {
      equal = true
      for i := range data {
        if data[i] != output_der[i] { 
          equal = false
          break 
        }
      }
    }
    if equal {
      fmt.Fprintf(os.Stdout, "Round-trip certificate -> UnmarshalDER() -> Instantiate() -> DER() successful!\n")
    } else {
      fmt.Fprintf(os.Stdout, "Round-trip certificate -> UnmarshalDER() -> Instantiate() -> DER() failed!\n%v\n", asn1.AnalyseDER(output.DER()))
    }
  }
   
}

func printkeys(m map[asn1.Rawtag]interface{}, indent string) {
  for key := range m {
    fmt.Printf("%v%x\n", indent, key)
    if m2, ok := m[key].(map[asn1.Rawtag]interface{}); ok {
      printkeys(m2, indent+"  ")
    }
  }
}
