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
         "strings"
         "io/ioutil"
         "encoding/json"
         "encoding/pem"
         
         "../asn1"
         "../rfc"
)


func encodeDER(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vencode(DER) called on empty stack", location)
  }
  inst, ok := stack[len(stack)-1].Value.(*asn1.Instance)
  if !ok {
    return fmt.Errorf("%vencode(DER) called, but top element of stack is not an instance of an ASN.1 type", location)
  }
  *stack_ = append(stack[0:len(stack)-1], &asn1.CookStackElement{Value: inst.DER()})
  return nil
}

func encodePEM(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) == 0 {
    return fmt.Errorf("%vencode(PEM) called on empty stack", location)
  }
  inst, ok := stack[len(stack)-1].Value.(*asn1.Instance)
  if !ok {
    return fmt.Errorf("%vencode(PEM) called, but top element of stack is not an instance of an ASN.1 type", location)
  }
  
  pemType := ""
  switch inst.Type() {
    case "Certificate": pemType = "CERTIFICATE"
  }
  
  pemBlock := &pem.Block{Type: pemType, Bytes: inst.DER()}
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
  
  *stack_ = stack[0:len(stack)-1]
  return nil
}



var funcs = map[string]asn1.CookStackFunc{"encode(DER)":encodeDER, "encode(PEM)":encodePEM, "decode(hex)":decodeHex, "write()": write}

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
