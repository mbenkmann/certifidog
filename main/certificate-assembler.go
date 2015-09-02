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
         "encoding/json"
         
         "../asn1"
         "../rfc"
)

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
  
  _, err = defs.Instantiate("Certificate", input)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
}
