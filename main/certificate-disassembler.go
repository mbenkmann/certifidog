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
         "io/ioutil"
         "encoding/pem"
         
         "../asn1"
         "../rfc"
)


func main() {
  if len(os.Args) < 2 {
    fmt.Fprintf(os.Stderr, "USAGE: %v [<syntax.asn1> ...] input.cert \n", "certificate-disassembler")
    os.Exit(1)
  }
  
  asn1.Debug = false
  var defs asn1.Definitions
  
  /* parse definitions from RFC 5280 */
  if err := defs.Parse(rfc.PKIX1Explicit88); err != nil { panic(err) }
  if err := defs.Parse(rfc.PKIX1Implicit88); err != nil { panic(err) }
  if err := defs.Parse(rfc.PKIX1Algorithms2008); err != nil { panic(err) }
  if err := defs.Parse(rfc.PKIX1_PSS_OAEP_Algorithms); err != nil { panic(err) }
  if err := defs.Parse(rfc.DisassemblerMappings); err != nil { panic(err) }
  
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
  
  /* parse PEM input */
  data, err := ioutil.ReadFile(os.Args[len(os.Args)-1])
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  block, rest := pem.Decode(data)
  if len(rest) != 0 {
    fmt.Fprintf(os.Stderr, "Could not decode PEM: Garbage at end of file:\n%v\n", string(rest))
    os.Exit(1)
  }
    
  data = block.Bytes
  unmarshaled := asn1.UnmarshalDER(data, 0)
  if unmarshaled == nil {
    fmt.Fprintf(os.Stderr, "Could not unmarshal DER data\n")
    os.Exit(1)
  }
  unmarshaled = unmarshaled.Data[asn1.Rawtag([]byte{0x30})].(*asn1.UnmarshalledConstructed)

  output, err := defs.Instantiate("Certificate", unmarshaled)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  fmt.Fprintf(os.Stdout, "%v\n", output.JSON(asn1.InlineStructMax(70),defs.OIDNames(), defs.DERinDER()))
}
