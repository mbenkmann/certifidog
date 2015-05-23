package main

import (
         "os"
         "fmt"
         "strings"
         "io/ioutil"
         "path/filepath"
         
         "../asn1"
       )

func main() {
  matches1, err := filepath.Glob("*.asn1")
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v", err)
    os.Exit(1)
  }
  matches2, err := filepath.Glob("test/*.asn1")
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v", err)
    os.Exit(1)
  }
  
  matches := append(matches1, matches2...)
  for _,f := range matches {
    src := ""
    output := ""
    var err error
    var data []byte
    data, err = ioutil.ReadFile(f)
    if err == nil {
      src = string(data)
      i := strings.Index(src, "END")
      for i < len(src) && src[i] != '\n' { i++ }
      i++
      for i < len(src) && src[i] != '\n' { i++ }
      i++
      output = src[i:]
      src = src[0:i]
      defs, err := asn1.Parse(src)
      if err != nil {
        src = fmt.Sprintf("%v\n", err)
      } else {
        src = defs.String()
      }
  
    } else {
      src = fmt.Sprintf("%v\n", err)
    }
    
    if strings.Join(strings.Fields(strings.TrimSpace(src)), " ") == strings.Join(strings.Fields(strings.TrimSpace(output)), " ") {
      fmt.Printf("OK %v\n", f)
    } else {
      fmt.Printf("FAIL %v\n--------------------------\n%v\n--------------------------\n", f, src)
    }
  }
}
