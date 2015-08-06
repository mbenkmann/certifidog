package main

import (
         "os"
         "fmt"
         "strings"
         "io/ioutil"
         "path/filepath"
         
         "../asn1"
       )

func asn1tests() {
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
      var defs asn1.Definitions
      err = defs.Parse(src)
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

func instancestring() {
  x := asn1.TestInstanceOmni
  xstr := x.String()
  if xstr == `SEQUENCE [TRUE, 11, dozen, { 1 2 3 }, "Hallo\nWelt!\x00", (), (0b1), (0b10), (first, third), (third, 0b101), (second, third, 0xE3 7F 00, 0b100), SET { god: FALSE }, SET { god: FALSE, flyingSpaghettiMonster: TRUE }]` {
    fmt.Printf("OK Instance.String()\n")
  } else {
    fmt.Printf("FAIL Instance.String()\n--------------------------\n%v\n--------------------------\n", xstr)
  }
}

func main() {
  asn1tests()
  instancestring()
}
