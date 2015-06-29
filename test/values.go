package main

import (
         "os"
         "fmt"
         "sort"
         "io/ioutil"
         
         "../asn1"
)

func main() {
  if len(os.Args) < 2 {
    fmt.Fprintf(os.Stderr, "USAGE: %v <syntax.asn1> [<syntax2.asn1> ...] \n", "parse-test")
    os.Exit(1)
  }
  
  asn1.Debug = true
  var defs asn1.Definitions
  
  for _, arg := range os.Args[1:] {
    data, err := ioutil.ReadFile(arg)
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
    }
    
    err = defs.Parse(string(data))
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
    }
  }
   
  names := defs.ValueNames()
  sort.Strings(names)
  for _, valuename := range names {
    v, err := defs.Value(valuename)
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
    }
    
    fmt.Fprintf(os.Stdout, "%v = %v\n", valuename, v.String())
  }
}
