package main

import (
         "io"
         "os"
         "fmt"
         "crypto/x509"
         "crypto/rsa"
         "crypto/ecdsa"
         
         "../asn1"
         "github.com/mbenkmann/golib/util"
         "github.com/mbenkmann/golib/deque"
       )

type eater interface {
  Data() []byte
  Eat(byte) int
}

type base64Eater struct {
  status int
  carry int
  daisy eater
}

func (e *base64Eater) Eat(b byte) int {
  if b <= ' ' || e.status != 0 { // ignore control characters; also exit if we have a status
    return e.status
  }
  carry_old := e.carry
  decoded := util.Base64DecodeString(string([]byte{b}), &e.carry)
  if len(decoded) == 0 {
    if carry_old == e.carry {  // no result and no state change => garbage
      e.status = -1
    }
  } else {
    for _, dec := range decoded {
      e.status = e.daisy.Eat(dec)
    }
  }
  
  return e.status
}

func (e *base64Eater) Data() []byte {
  return e.daisy.Data()
}

func newBase64Eater() eater {
  return &base64Eater{daisy:newRawEater()}
}

type rawEater struct {
  status int
  data []byte
  state int
  constructed bool
  length []int
  length_count int
  length_buffer int
}

func (e *rawEater) Data() []byte { return e.data }

func newRawEater() eater { return &rawEater{} }

func (e *rawEater) Eat(b byte) int {
  if e.status != 0 { return e.status }
  if e.state == 0 { // waiting for the initial 0x30
    if b != 0x30 {
      e.status = -1 // error
    } else {
      e.state = 1
      e.constructed = true
    }
  } else if e.state == 1 { // tag has been read, now read 1st length byte
    if b <= 127 { // short form length
      if len(e.length) > 0 && int(b) > e.length[len(e.length)-1]-1 { // -1 because the length byte we just parsed has not been subtracted yet
        // if new object doesn't fit into surrounding structure
        e.status = -1 // error
      } else {
        e.length = append(e.length, int(b) + 1) // + 1 because it will be decremented further below
        if e.constructed { 
          e.state = 3
        } else {
          e.state = 4
        }
      }
    } else {
      e.length_count = int(b) & 127
      if e.length_count == 0 || e.length_count > 2 {
        // illegal length: 0 or more than 64K
        e.status = -1
      }
      e.length_buffer = 0
      e.state = 2
    }
  } else if e.state == 2 { // reading long form length octets
    e.length_buffer <<= 8
    e.length_buffer  += int(b)
    e.length_count--
    if e.length_count == 0 {
      if len(e.length) > 0 && e.length_buffer > e.length[len(e.length)-1]-1 { // -1 because the length byte we just parsed has not been subtracted yet
        // if new object doesn't fit into surrounding structure
        e.status = -1 // error
      } else {
        e.length = append(e.length, e.length_buffer + 1) // + 1 because it will be decremented further below
        if e.constructed { 
          e.state = 3
        } else {
          e.state = 4
        }
      }
    }
  } else if e.state == 3 { // inside constructed, expecting tag byte
    if (b & 64) != 0 ||  // the structures we're interested in do not contain APPLICATION or PRIVATE tags
       (b & 31) == 31 {  // the structures we're interested in do not have tags >= 31
      e.status = -1
    }
    e.constructed = (b & 32 != 0)
    e.state = 1
  } else if e.state == 4 { // inside primitive, expecting data byte
    // nothing to do
  }
  
  e.data = append(e.data, b)
  
  for i := range e.length {
    e.length[i]--
  }
  
  for len(e.length) > 0 && e.length[len(e.length)-1] == 0 {
    e.length = e.length[0:len(e.length)-1]
    e.constructed = true
    e.state = 3
  }
  
  if len(e.length) == 0 {
    switch e.state {
      case 3: e.status = 1
      case 1,2: {} // still waiting for length of outermost SEQUENCE
      default: e.status = -1 // error
    }
  }
  
  return e.status
}

func ReadNextSEQUENCE(r io.Reader) ([]byte, error) {
  b := []byte{0}
  var err error
  var n int
  space := true
  var eaters deque.Deque
  for {
    n, err = r.Read(b)
    if err != nil {
      return nil, err
    }
    if n == 0 { 
      return nil, io.EOF
    }
    if b[0] == 0x30 { // SEQUENCE
      eaters.Push(newRawEater())
    } 
    if b[0] > ' ' {
      if space {
        eaters.Push(newBase64Eater())
      }
      space = false
    } else {
      space = true
    }
    
    for i:=0; i < eaters.Count(); {
      result := eaters.At(i).(eater).Eat(b[0])
      switch result {
        case -1: // error
          eaters.RemoveAt(i)
        case 0:  // ok, need more data
          i++
        case 1:  // done
          return eaters.At(i).(eater).Data(), nil
      }
    }
  }
}

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
  
  data, err := ReadNextSEQUENCE(file)
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

