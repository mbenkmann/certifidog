package main

import (
         "os"
         "fmt"
         "crypto/x509"
         "crypto/rsa"
         "crypto/ecdsa"
         
         "../asn1"
       )


func main() {
  if len(os.Args) != 2 {
    fmt.Fprintf(os.Stderr, "USAGE: %v <keyfile>\n", "analysekey")
    os.Exit(1)
  }

  file, err := os.Open(os.Args[1])
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  data, err := asn1.ReadNextSEQUENCE(file)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  fmt.Fprintf(os.Stdout, "%v\n", asn1.AnalyseDER(data))
  
  key1, err1 := x509.ParseECPrivateKey(data)
  key2, err2 := x509.ParsePKCS1PrivateKey(data)
  key3, err3 := x509.ParsePKCS8PrivateKey(data)
  
  var pub interface{}
  if err1 == nil && key1 != nil { 
    fmt.Fprintf(os.Stdout, "ParseECPrivateKey OK\n") 
    pub = key1.Public()
  }
  if err2 == nil && key2 != nil { 
    fmt.Fprintf(os.Stdout, "ParsePKCS1PrivateKey OK\n") 
    pub = key2.Public()
  }
  if err3 == nil && key3 != nil {
    fmt.Fprintf(os.Stdout, "ParsePKCS8PrivateKey OK => %T\n", key3) 
    switch key := key3.(type){
      case *rsa.PrivateKey: pub = key.Public()
      case *ecdsa.PrivateKey: pub = key.Public()
    }
  }
  
  if pub != nil {
    pubkeybytes, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
    }
    
    fmt.Fprintf(os.Stdout, "\nCORRESPONDING PUBLIC KEY: %v\n", asn1.AnalyseDER(pubkeybytes))
  }
}

