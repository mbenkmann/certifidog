package main

import (
         "fmt"
         
         "../asn1"
       )

func main() {
  x := asn1.TestInstanceOmni
  fmt.Println(x.String())
}
