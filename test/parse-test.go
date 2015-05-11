package main

import (
         "os"
         "fmt"
         "io/ioutil"
         
         "../asn1"
)

func main() {
  if len(os.Args) < 2 {
    fmt.Fprintf(os.Stderr, "USAGE: %v <syntax.asn1>\n", "parse-test")
    os.Exit(1)
  }
  
  data, err := ioutil.ReadFile(os.Args[1])
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  asn1.Debug = true
  
  tree, err := asn1.Parse(string(data))
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    os.Exit(1)
  }
  
  fmt.Fprintf(os.Stdout, "%v\n", tree.String())
}
