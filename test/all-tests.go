package main

import (
         "os"
         "fmt"
         "strings"
         "io/ioutil"
         "path/filepath"
         "encoding/json"
         
         "../asn1"
       )

func fun_equals(stack_ *[]*asn1.CookStackElement, location string) error {
  stack := *stack_
  if len(stack) < 2 {
    return fmt.Errorf("%vFewer than 2 elements on stack when calling fun_equals", location)
  }
  ele1 := stack[len(stack)-1]
  ele2 := stack[len(stack)-2]
  *stack_ = append(stack[0:len(stack)-2], &asn1.CookStackElement{Value: ele1.Value == ele2.Value})
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




var exampleFuncs = map[string]asn1.CookStackFunc{"equals":fun_equals, "decode(hex)":decodeHex}

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
      
      output = strings.TrimSpace(src[i:])
      src = src[0:i]
      var data map[string]interface{}
      
      if strings.HasPrefix(output, "INSTANTIATE") {
        istart  := strings.Index(output, "{")
        i = istart
        level := 0
        for i < len(output) {
          if output[i] == '{' { level++ }
          if output[i] == '}' { level-- }
          i++
          if level == 0 { break }
        }
        instancejson := output[istart:i]
        output = strings.TrimSpace(output[i:])
        
        err = json.Unmarshal([]byte(instancejson), &data)
        if err != nil { panic(err) }
      }
      
      var defs asn1.Definitions
      err = defs.Parse(src)
      if err != nil {
        src = fmt.Sprintf("%v\n", err)
      } else {
        src = defs.String()
        
        if data != nil {
          var inst *asn1.Instance
          
          // use last key in JSON data as typename
          var typename string
          for typename = range data {}
          
          // Cook the JSON data
          data[typename], err = asn1.Cook(&defs, nil, exampleFuncs, data[typename])
          if err == nil {
            inst, err = defs.Instantiate(typename, data[typename])
          }
          
          if err != nil {
            src = fmt.Sprintf("%v\n", err)
          } else {
            if strings.HasPrefix(output, "DER:") {
              src = "DER:\n" + asn1.AnalyseDER(inst.DER())
            } else if strings.HasPrefix(output, "JSON(") {
              idx := strings.Index(output,"\n")
              jsonPrefix := output[0:idx+1]
              for jsonPrefix[idx] != ')' { idx-- }
              jsonParams := []interface{}{}
              for _, p := range strings.Fields(jsonPrefix[5:idx]) { jsonParams = append(jsonParams, p) }
              src = jsonPrefix + inst.JSON(jsonParams...)
            } else {
              src = inst.String()
            }
          }
        }
      }
  
    } else {
      src = fmt.Sprintf("%v\n", err)
    }
    
    if strings.Join(strings.Fields(strings.TrimSpace(src)), " ") == strings.Join(strings.Fields(output), " ") {
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

func bitstring() {
  var defs asn1.Definitions
  defs.Parse(`DEFINITIONS EXPLICIT TAGS ::= BEGIN B ::= BIT STRING END`)
  inst, err := defs.Instantiate("B", []byte{0xE2,0xC1,0x07})
  if err != nil { panic(err) }
  xstr := inst.String()
  if xstr == "(0xE2 C1 07)" {
    fmt.Printf("OK bitstring\n")
  } else {
    fmt.Printf("FAIL bitstring\n--------------------------\n%v\n--------------------------\n", xstr)
  }
}

func main() {
  asn1tests()
  instancestring()
  bitstring()
}
