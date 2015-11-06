/*
Copyright (c) 2015 Matthias S. Benkmann

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; version 3
of the License (ONLY this version).

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

/*
  Low-level tool for creating certificates that gives you almost the same
  level of control as writing binary DER output in a hex editor but allows
  you to specify the certificate data in a readable JSON file using symbolic
  names for types and constants.
*/

package main

import (
         "os"
         "fmt"
         "crypto"
         "crypto/x509"
         "crypto/rand"
         "crypto/rsa"
         "crypto/ecdsa"
         "crypto/elliptic"
         "hash"
         "strings"
         "io/ioutil"
         "encoding/json"
         "encoding/pem"
         "math/big"
         
         "../asn1"
         "../rfc"
)


func encodeDER(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vencode(DER) called on empty stack", location)
  }
  
  switch data := stack[len(stack)-1].Value.(type) {
    case *asn1.Instance: *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: data.DER()})
    case *ecdsa.PrivateKey: derbytes, err := x509.MarshalECPrivateKey(data)
                            if err != nil { panic(err) } // should never happen
                            *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: derbytes})
    case *rsa.PrivateKey: *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: x509.MarshalPKCS1PrivateKey(data)})
    default: return fmt.Errorf("%vencode(DER) called with argument of unsupported type \"%T\"", location, data)
  }
  
  return nil
}

func encodePEM(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vencode(PEM) called on empty stack", location)
  }
  
  var derbytes []byte
  var err error
  pemType := ""
  
  switch data := stack[len(stack)-1].Value.(type) {
    case *asn1.Instance: 
        derbytes = data.DER()
        switch data.Type() {
          case "Certificate": pemType = "CERTIFICATE"
        }
    
    case *ecdsa.PrivateKey: 
        derbytes, err = x509.MarshalECPrivateKey(data)
        if err != nil { panic(err) } // should never happen
        pemType = "EC PRIVATE KEY"
        
    case *rsa.PrivateKey: 
        derbytes = x509.MarshalPKCS1PrivateKey(data)
        pemType = "RSA PRIVATE KEY"
        
    default: return fmt.Errorf("%vencode(PEM) called with argument of unsupported type \"%T\"", location, data)
  }
  
  pemBlock := &pem.Block{Type: pemType, Bytes: derbytes}
  *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: pem.EncodeToMemory(pemBlock)})
  return nil
}

func decodeHex(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vdecode(hex) called on empty stack", location)
  }
  str, ok := stack[len(stack)-1].Value.(string)
  if !ok {
    return fmt.Errorf("%vdecode(hex) requires top element of stack to be a string", location)
  }

  improper := fmt.Errorf("%vdecode(hex): argument is not a proper hex string: %v", location, str)

  // remove whitespace and convert to lower case
  str = strings.ToLower(strings.Join(strings.Fields(str),""))
  
  // remove optional "0x" prefix
  if strings.HasPrefix(str, "0x") {
    str = str[2:]
  }
  
  // reject strings with odd number of hex digits
  // we intentionally accept empty strings because they produce a valid []byte
  if len(str) & 1 != 0 {
    return improper
  }
  
  data := []byte(str)
  bytes := make([]byte, len(data) >> 1)
  for i, hexdigit := range data {
    if hexdigit < '0' || (hexdigit > '9' && hexdigit < 'a') || hexdigit > 'f' {
      return improper
    }
    if hexdigit > '9' { 
      hexdigit = hexdigit - 'a' + 10 
    } else {
      hexdigit -= '0'
    }
    bytes[i >> 1] <<= 4
    bytes[i >> 1] |= hexdigit
  }
  
  *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: bytes})
  return nil
}

func write(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) < 2 {
    return fmt.Errorf("%vwrite() called on stack with fewer than 2 elements", location)
  }
  data1, ok1 := stack[len(stack)-1].Value.([]byte)
  data2, ok2 := stack[len(stack)-2].Value.([]byte)
  file2, ok3 := stack[len(stack)-1].Value.(string)
  file1, ok4 := stack[len(stack)-2].Value.(string)
  if !((ok1 && ok4) || (ok2 && ok3)) {
    return fmt.Errorf("%vwrite() called, but top 2 elements of stack are not a byte-array and a file name", location)
  }
  
  if ok2 { data1, file1 = data2, file2 }
  
  err := ioutil.WriteFile(file1, data1, 0644)
  if err != nil {
    return fmt.Errorf("%vwrite() error: %v", location, err)
  }
  
  // Result value is the byte array. We need a result because cook() expects one.
  *stack_ = append(stack[0:len(stack)-2], &asn1.CookStackElement{Value: data1})
  return nil
}

func key(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vkey() called on empty stack", location)
  }

  fname, ok := stack[len(stack)-1].Value.(string)
  if !ok {
    return fmt.Errorf("%vkey() called, but top element of stack is not a file name", location)
  }

  var signer crypto.Signer
  file, err := os.Open(fname)
  if err == nil {
    defer file.Close()
    signer, err = asn1.ReadNextKey(file)
  }

  if err != nil {
    return fmt.Errorf("%vkey() error: %v", location, err)
  }
  
  *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: signer})
  return nil
}

func keygen(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vkeygen() called on empty stack", location)
  }

  var signer crypto.Signer
  var err error

  switch parm := stack[len(stack)-1].Value.(type) {
    case *big.Int: bits := parm.Int64()
                   if bits < 128 || bits > 16384 {
                     return fmt.Errorf("%vkeygen() error: Illegal number of key bits requested: %v", location, parm)
                   }
                   signer, err = rsa.GenerateKey(rand.Reader, int(bits))
                   if err != nil {
                     return fmt.Errorf("%vkeygen() error: %v", location, err)
                   }
    
    case *asn1.Instance: if parm.Type() != "OBJECT_IDENTIFIER" {
                      return fmt.Errorf("%vkeygen() called with parameter of unsupported type \"%v\"", location, parm.Type())
                    }
                    curveoid := parm.JSON()
                    curveoid = curveoid[2:len(curveoid)-1] // remove "$ and "
                    
                    var curve elliptic.Curve
                    switch curveoid {
                      // secp224r1
                      case "1.3.132.0.33": curve = elliptic.P224()
                      
                      // secp256r1
                      case "1.2.840.10045.3.1.7": curve = elliptic.P256()
                      
                      // secp384r1
                      case "1.3.132.0.34": curve = elliptic.P384()
                      
                      // secp521r1
                      case "1.3.132.0.35": curve = elliptic.P521()
                          
                      default: return fmt.Errorf("%vkeygen() called with unsupported OBJECT IDENTIFIER \"%v\"", location, curveoid)
                    }
                    
                    signer, err = ecdsa.GenerateKey(curve, rand.Reader)
                    if err != nil {
                      return fmt.Errorf("%vkeygen() error: %v", location, err)
                    }
                    
    default: return fmt.Errorf("%vkeygen() called with parameter of unsupported type \"%T\"", location, parm)
  }
  
  *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: signer})
  return nil
}


func subjectPublicKeyInfo(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vsubjectPublicKeyInfo() called on empty stack", location)
  }

  signer, ok := stack[len(stack)-1].Value.(crypto.Signer)
  if !ok {
    return fmt.Errorf("%vsubjectPublicKeyInfo() called, but top element of stack is not a key. Use the key() function!", location)
  }

  pubkeybytes, err := x509.MarshalPKIXPublicKey(signer.Public())
  if err != nil {
    return fmt.Errorf("%vsubjectPublicKeyInfo() error: %v", location, err)
  }
  
  unmarshaled := asn1.UnmarshalDER(pubkeybytes, 0)
  unmarshaled = unmarshaled.Data[asn1.Rawtag([]byte{0x30})].(*asn1.UnmarshalledConstructed)
  
  *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: unmarshaled})
  return nil
}

func sign(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) < 3 {
    return fmt.Errorf("%vsign() called on stack with fewer than 3 elements", location)
  }
  data1, ok1 := stack[len(stack)-1].Value.([]byte)
  data2, ok2 := stack[len(stack)-2].Value.([]byte)
  data3, ok3 := stack[len(stack)-3].Value.([]byte)
  key1, ok4 := stack[len(stack)-1].Value.(crypto.Signer)
  key2, ok5 := stack[len(stack)-2].Value.(crypto.Signer)
  key3, ok6 := stack[len(stack)-3].Value.(crypto.Signer)
  algo1, ok7 := stack[len(stack)-1].Value.(map[string]interface{})
  algo2, ok8 := stack[len(stack)-2].Value.(map[string]interface{})
  algo3, ok9 := stack[len(stack)-3].Value.(map[string]interface{})
  if !((ok1||ok2||ok3) && (ok4||ok5||ok6) && (ok7||ok8||ok9)) {
    return fmt.Errorf("%vsign() requires the top 3 elements of the stack to be a byte-array, a key and a signatureAlgorithm structure", location)
  }
  
  var data []byte
  if ok1 { data = data1 }
  if ok2 { data = data2 }
  if ok3 { data = data3 }
  
  var key crypto.Signer
  if ok4 { key = key1 }
  if ok5 { key = key2 }
  if ok6 { key = key3 }
  
  var algo map[string]interface{}
  if ok7 { algo = algo1 }
  if ok8 { algo = algo2 }
  if ok9 { algo = algo3 }
  
  
  algorithm, ok := algo["algorithm"]
  if !ok {
    return fmt.Errorf("%vsign() error: signatureAlgorithm has no \"algorithm\" member", location)
  }
  
  ok = false
  algooid := ""
  switch al := algorithm.(type) {
    case *asn1.Instance: ok = (al.Type() == "OBJECT_IDENTIFIER")
                         if ok { 
                           algooid = al.JSON()
                           algooid = algooid[2:len(algooid)-1] // remove "$ and "
                         }
  }
  
  if !ok {
    return fmt.Errorf("%vsign() error: \"algorithm\" not of type OBJECT IDENTIFIER", location)
  }

  var cryptohash crypto.Hash
  switch algooid {
    //md2WithRSAEncryption
    //case "1.2.840.113549.1.1.2": cryptohash = crypto.MD2

    // md5WithRSAEncryption
    case "1.2.840.113549.1.1.4": cryptohash = crypto.MD5

    // sha1WithRSAEncryption
    case "1.2.840.113549.1.1.5": cryptohash = crypto.SHA1

    // id-dsa-with-sha1
    case "1.2.840.10040.4.3": cryptohash = crypto.SHA1

    // id-dsa-with-sha224
    case "2.16.840.1.101.3.4.3.1": cryptohash = crypto.SHA224

    // id-dsa-with-sha256
    case "2.16.840.1.101.3.4.3.2": cryptohash = crypto.SHA256

    // ecdsa-with-SHA1
    case "1.2.840.10045.4.1": cryptohash = crypto.SHA1

    // ecdsa-with-SHA224
    case "1.2.840.10045.4.3.1": cryptohash = crypto.SHA224

    // ecdsa-with-SHA256
    case "1.2.840.10045.4.3.2": cryptohash = crypto.SHA256

    // ecdsa-with-SHA384
    case "1.2.840.10045.4.3.3": cryptohash = crypto.SHA384

    // ecdsa-with-SHA512
    case "1.2.840.10045.4.3.4": cryptohash = crypto.SHA512
    
    // sha224WithRSAEncryption
    case "1.2.840.113549.1.1.14": cryptohash = crypto.SHA224

    // sha256WithRSAEncryption
    case "1.2.840.113549.1.1.11": cryptohash = crypto.SHA256

    // sha384WithRSAEncryption
    case "1.2.840.113549.1.1.12": cryptohash = crypto.SHA384

    // sha512WithRSAEncryption
    case "1.2.840.113549.1.1.13": cryptohash = crypto.SHA512

    default: return fmt.Errorf("%vsign() error: Unknown signature algorithm OID \"%v\"", location, algooid)
  }
  
  var hashhash hash.Hash
  hashhash = cryptohash.New()
  hashhash.Write(data)
  sig, err := key.Sign(rand.Reader, hashhash.Sum(nil), cryptohash)
  if err != nil {
    return fmt.Errorf("%vsign() error: %v", location, err)
  }
  
  // Result value is the byte array. We need a result because cook() expects one.
  *stack_ = append(stack[0:len(stack)-3], &asn1.CookStackElement{Value: sig})
  return nil
}

var funcs = map[string]asn1.CookStackFunc{"encode(DER)":encodeDER, "encode(PEM)":encodePEM, "decode(hex)":decodeHex, "write()": write, "key()": key, "subjectPublicKeyInfo()": subjectPublicKeyInfo, "sign()":sign, "keygen()": keygen}

func main() {
  if len(os.Args) < 2 {
    fmt.Fprintf(os.Stderr, "USAGE: %v [<syntax.asn1> ...] input.json \n", "certificate-assembler")
    os.Exit(1)
  }
  
  asn1.Debug = false
  var defs asn1.Definitions
  
  /* parse definitions from RFC 5280 */
  if err := defs.Parse(rfc.PKIX1Explicit88); err != nil { panic(err) }
  if err := defs.Parse(rfc.PKIX1Implicit88); err != nil { panic(err) }
  if err := defs.Parse(rfc.KeyPurposeObsolete); err != nil { panic(err) }
  if err := defs.Parse(rfc.PKIX1Algorithms2008); err != nil { panic(err) }
  if err := defs.Parse(rfc.PKIX1_PSS_OAEP_Algorithms); err != nil { panic(err) }
  if err := defs.Parse(rfc.LogotypeCertExtension); err != nil { panic(err) }
  if err := defs.Parse(rfc.NetscapeExtensions); err != nil { panic(err) }
  if err := defs.Parse(rfc.EntrustExtensions); err != nil { panic(err) }
  if err := defs.Parse(rfc.MicrosoftExtensions); err != nil { panic(err) }
  if err := defs.Parse(rfc.SETExtensions); err != nil { panic(err) }
  
  /* parse additional ASN.1 files */
  for _, arg := range os.Args[1:len(os.Args)-1] {
    data, err := ioutil.ReadFile(arg)
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v: %v\n", arg, err)
      os.Exit(1)
    }
    
    err = defs.Parse(string(data))
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v %v\n", arg, err)
      os.Exit(1)
    }
  }
  
  /* parse JSON input */ 
  jsondata, err := ioutil.ReadFile(os.Args[len(os.Args)-1])
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  var input map[string]interface{}
  err = json.Unmarshal(jsondata, &input)
  if err != nil { 
    switch err := err.(type) {
      case *json.SyntaxError:
          col := 0
          line := 1
          for i := range jsondata {
            col++
            if int64(i) == err.Offset { break }
            if jsondata[i] == '\n' {
              col = 0
              line++
            }
          }
          fmt.Fprintf(os.Stderr, "%v: Line %v column %v: %v\n", os.Args[len(os.Args)-1], line, col, err)
      default: fmt.Fprintf(os.Stderr, "%v: %v\n", os.Args[len(os.Args)-1], err)
    }
    
    os.Exit(1)
  }
  
  _, err = asn1.Cook(&defs, nil, funcs, input)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
}
