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
  This file contains the code to create an instance of a type from asn1.Definitions.
*/

package asn1

import (
         "fmt"
         "math"
         "regexp"
         "strings"
         "strconv"
       )

func instantiateTypeError(p *pathNode) error {
  return fmt.Errorf("%vAttempt to instantiate ASN.1 type from incompatible Go type", p)
}

// Returns an instance of the value called valuename whose definition has to be
// parsed from ASN.1 source by the Parse() method.
func (d *Definitions) Value(valuename string) (*Instance, error) {
  v, ok := d.valuedefs[valuename]
  if !ok {
    return nil, fmt.Errorf("Value %v is undefined", valuename)
  }
  // children are not handled because compound value definitions are not supported, so no value can have children.
  return &Instance{nodetype:instanceNode, tag:v.tag, implicit:v.implicit, name:valuename, typename:v.typename, basictype:v.basictype, value:v.value, namedints:v.namedints, src:v.src, pos:v.pos}, nil
}

// Creates an instance of the type called typename whose definition has to be
// parsed from ASN.1 source by the Parse() method.
// data is the value to be filled into the instance. The value's type must correspond to
// the ASN.1 definition of typename according to the following rules:
// SEQUENCE/SET/CHOICE => map[string]interface{} where the keys match the ASN.1 field names
// SEQUENCE_OF/SET_OF => []interface{}
// OCTET_STRING => string or []byte
// BOOLEAN => bool or string that compares (case-insensitive) to "false" or "true"
// INTEGER => int, float64 or string that either parses as an integer or compares (CASE-SENSITIVE) to
//            one of the named numbers for from the ASN.1 source for the respective context.
//            A float64 must not have a fractional part.
// ENUMERATED => like INTEGER above, but it is an error if the number does not match one of
//               the named numbers from the ASN.1 source for the respective context.
// BIT_STRING => Option 1: a string of the form "0b..." where "..." is composed of "0" and "1"
//                         characters. Spaces are permitted anywhere in the string.
//               Option 2: (string) list of words from the bit names from the ASN.1 source where
//                         the words may be separated by any sequence of characters not from the
//                         set [0-9a-zA-Z-].
//               Option 3: a string of the form "0x..." where "..." is composed of hex digits.
//                         Spaces are permitted anywhere in the string. Each hex digit yields
//                         4 bits (MSB left, LSB right). E.g. 0x8 => 0b0100
//               Option 4: a []byte. This is limited to bit strings that are a multiple of
//                         8 bits long. The corresponding bit string is obtained by converting
//                         the bytes from index 0 to index len(..)-1 into binary with MSB
//                         to the left and concatenating all these binary strings.
//                         E.g. []byte{0xF5,0x62} => 0b1111010101100010
//               Option 5: a []bool, this corresponds to the bit string where each entry in
//                         the slice is converted to 0(false) or 1(true) in order and concatenated.
//                         E.g. []bool{true,false,false} => 0b100
// OBJECT_IDENTIFIER => []int or a string of integers separated by arbitrary sequences of
//                      non-digit characters, e.g. "1.2.3" or "1 2 3" or even "{1 foo(2) 3}"
// ANY => bool (encoded as BOOLEAN), int (encoded as INTEGER), []int (encoded as OBJECT IDENTIFIER),
//        []byte (encoded as OCTET STRING), []interface{} (encoded as SEQUENCE OF ANY),
//        string (encoded as OCTET STRING),
//        []bool (encoded as BIT STRING)
//        float64 (encoded as INTEGER if an integral number)
func (d *Definitions) Instantiate(typename string, data interface{}) (*Instance, error) {
  t, ok := d.typedefs[typename]
  if !ok {
    return nil, fmt.Errorf("Type %v is undefined", typename)
  }
  
  return t.instantiate(data,&pathNode{})
}

type pathNode struct {
  parent *pathNode
  name string
}

func (p *pathNode) String() string {
  s := p.str()
  if s != "" { return s+": " }
  return s
}

func (p *pathNode) str() string {
  if p == nil { return "" }
  return p.parent.str()+p.name
}

func (t *Tree) instantiate(data interface{}, p *pathNode) (*Instance, error) {
  inst := &Instance{nodetype:instanceNode, tag:t.tag, implicit:t.implicit, name:t.name, typename:t.typename, basictype:t.basictype, namedints:t.namedints, src:t.src, pos:t.pos}
  switch inst.basictype {
    case SEQUENCE, SET: return instantiateSEQUENCE(BasicTypeTag[inst.basictype], inst, t.children, data, p)
    case CHOICE: inst2, err := instantiateSEQUENCE(-1, inst, t.children, data, p)
                 if err == nil {
                   if len(inst2.children) != 1 { 
                     err = fmt.Errorf("%vCHOICE must be instantiated with exactly one data element", p)
                     inst2 = nil
                   } else {
                     inst2 = (*Instance)(inst2.children[0])
                   }
                 }
                 return inst2, err
    case SEQUENCE_OF, SET_OF: return instantiateSEQUENCE_OF(BasicTypeTag[inst.basictype], inst, t.children[0], data, p)
    case OCTET_STRING: return instantiateOCTET_STRING(inst, data, p)
    case BOOLEAN: return instantiateBOOLEAN(inst, data, p)
    case INTEGER: return instantiateINTEGER(inst, data, p)
    case ENUMERATED: inst2, err := instantiateINTEGER(inst, data, p)
                     if err != nil { return inst2, err }
                     val := inst2.value.(int)
                     for _, i := range inst2.namedints {
                       if i == val { return inst2, nil }
                     }
                     return nil, fmt.Errorf("%vAttempt to instantiate ENUMERATED with number not from allowed set: %v", p, val)
    case OBJECT_IDENTIFIER: return instantiateOBJECT_IDENTIFIER(inst, data, p)
    case BIT_STRING: return instantiateBIT_STRING(inst, data, p)
    case ANY: return instantiateANY(inst, data, p)
    default: return nil, fmt.Errorf("%vUnhandled case in instantiate()", p)
  }
}

var nonIdentifier = regexp.MustCompile(`[^0-9a-zA-Z-]+`)

func instantiateANY(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case bool: inst.basictype = BOOLEAN
               return instantiateBOOLEAN(inst, data, p)
    case int, float64:  inst.basictype = INTEGER
               return instantiateINTEGER(inst, data, p)
    case []int: inst.basictype = OBJECT_IDENTIFIER 
               return instantiateOBJECT_IDENTIFIER(inst, data, p)
    case []byte: inst.basictype = OCTET_STRING
               return instantiateOCTET_STRING(inst, data, p)
    case string: inst.basictype = OCTET_STRING
                 return instantiateOCTET_STRING(inst, data, p)
    case []bool: inst.basictype = BIT_STRING
                 return instantiateBIT_STRING(inst, data, p)
    case []interface{}: 
                 inst.basictype = SEQUENCE_OF
                 return instantiateSEQUENCE_OF(16, inst, &Tree{nodetype:instanceNode, tag:-1, implicit:false, basictype:ANY, src:inst.src, pos:inst.pos} , data, p)
    default: return nil, instantiateTypeError(p)
  }
}

func instantiateBIT_STRING(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  if inst.tag < 0 { 
    inst.tag = BasicTypeTag[BIT_STRING]
    inst.implicit = true
  }
  switch data := data.(type) {
    case []bool: inst.value = data
    case []byte: bits := make([]bool, len(data)*8)
                 inst.value = bits
                 for i, b := range data {
                   for k := 0; k < 8; k++ {
                     bits[i*8+k] = (b & (128 >> uint(k))) != 0
                   }
                 }
    case string: data = strings.TrimSpace(data)
                 if strings.HasPrefix(data, "0x") {
                   // remove whitespace
                   data = strings.Join(strings.Fields(data),"")
                   // convert to lower case and remove "0x" prefix
                   data = strings.ToLower(data[2:])
                   bits := make([]bool, len(data)*4)
                   inst.value = bits
                   for i, hexdigit := range data {
                     if hexdigit < '0' || (hexdigit > '9' && hexdigit < 'a') || hexdigit > 'f' {
                       return nil, fmt.Errorf("%vIllegal character in hex string: 0x%v", p, data)
                     }
                     if hexdigit > '9' { 
                       hexdigit = hexdigit - 'a' + 10 
                     } else {
                       hexdigit -= '0'
                     }
                     for k := 0; k < 4; k++ {
                       bits[i*4+k] = (hexdigit & (8 >> uint(k))) != 0
                     }
                   }
                 } else if strings.HasPrefix(data, "0b") {
                   // remove whitespace
                   data = strings.Join(strings.Fields(data),"")
                   // remove "0b" prefix
                   data = data[2:]
                   bits := make([]bool, len(data))
                   inst.value = bits
                   for i, d := range data {
                     if d != '0' && d != '1' {
                       return nil, fmt.Errorf("%vIllegal character in binary string: 0b%v", p, data)
                     }
                     bits[i] = (d == '1')
                   }
                 } else {
                   f := strings.Fields(strings.TrimSpace(nonIdentifier.ReplaceAllString(data, " ")))
                   bits := []bool{}
                   inst.value = bits
                   for _, name := range f {
                     bitno, defined := inst.namedints[name]
                     if !defined {
                       return nil, fmt.Errorf("%vBIT STRING initializer is not a known bit name: %v", p, name)
                     }
                     if len(bits) <= bitno {
                       bits2 := make([]bool, bitno+1)
                       copy(bits2, bits)
                       bits = bits2
                       inst.value = bits2
                     }
                     bits[bitno] = true
                   }
                 }
    default: return nil, instantiateTypeError(p)
  }
  return inst, nil
}


var nonDigits = regexp.MustCompile(`[^[:digit:]]+`)

func instantiateOBJECT_IDENTIFIER(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  if inst.tag < 0 { 
    inst.tag = BasicTypeTag[OBJECT_IDENTIFIER]
    inst.implicit = true
  }
  switch data := data.(type) {
    case []int: inst.value = data
    case string: f := strings.Fields(strings.TrimSpace(nonDigits.ReplaceAllString(data, " ")))
                 if len(f) == 0 {
                   return nil, fmt.Errorf("%vNo digits found in OBJECT IDENTIFIER initializer string: %v", p, data)
                 }
                 oid := make([]int, len(f))
                 for i, s := range f {
                   oid[i], _ = strconv.Atoi(s)
                 }
                 inst.value = oid
    default: return nil, instantiateTypeError(p)
  }
  return inst, nil
}

func instantiateINTEGER(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  if inst.tag < 0 { 
    inst.tag = BasicTypeTag[INTEGER]
    inst.implicit = true
  }
  switch data := data.(type) {
    case int: inst.value = data
    case float64: if math.Floor(data) != data {
                    return nil, fmt.Errorf("%vAttempt to instantiate INTEGER with non-integral float64: %v", p, data)
                  }
                  inst.value = int(data)
    case string: if i, found := inst.namedints[data]; found {
                   inst.value = i
                 } else {
                   i, err := strconv.Atoi(data)
                   if err != nil { 
                     return nil, fmt.Errorf("%vAttempt to instantiate INTEGER/ENUMERATED from illegal string: %v", p, data)
                   }
                   inst.value = i
                 }
    default: return nil, instantiateTypeError(p)
  }
  return inst, nil
}

func instantiateBOOLEAN(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  if inst.tag < 0 { 
    inst.tag = BasicTypeTag[BOOLEAN]
    inst.implicit = true
  }
  switch data := data.(type) {
    case bool: inst.value = data
    case string: data = strings.ToLower(data)
                 if data == "false" {
                   inst.value = false
                 } else if data == "true" {
                   inst.value = true
                 } else {
                   return nil, fmt.Errorf("%vAttempt to instantiate BOOLEAN from string that's neither \"true\" nor \"false\": %v", p, data)
                 }
    default: return nil, instantiateTypeError(p)
  }
  return inst, nil
}


func instantiateOCTET_STRING(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  if inst.tag < 0 { 
    inst.tag = BasicTypeTag[OCTET_STRING]
    inst.implicit = true
  }
  switch data := data.(type) {
    case string: inst.value = []byte(data)
    case []byte: inst.value = data
    default: return nil, instantiateTypeError(p)
  }
  return inst, nil
}

func instantiateSEQUENCE(deftag int, inst *Instance, children []*Tree, data interface{}, p *pathNode) (*Instance, error) {
  if inst.tag < 0 { 
    inst.tag = deftag 
    inst.implicit = true
  }
  switch data := data.(type) {
    case map[string]interface{}:
      for _, c := range children {
        if d, present := data[c.name]; present {
          child, err := c.instantiate(d, &pathNode{parent:p, name:"/"+c.name})
          if err != nil { return nil, err }
          inst.children = append(inst.children, (*Tree)(child))
          child.isDefaultValue = c.optional && equalValues(c.value, child.value)
        } else {
          if !c.optional { return nil, fmt.Errorf("%vMissing data for non-optional field %v", p, c.name) }
          if c.value != nil {
            child := &Instance{nodetype:instanceNode, tag:c.tag, implicit:c.implicit, name:c.name, typename:c.typename, basictype:c.basictype, value:c.value, namedints:c.namedints, src:c.src, pos:c.pos}
            inst.children = append(inst.children, (*Tree)(child))
            child.isDefaultValue = equalValues(c.value, child.value)
          }
        }
      }
      return inst, nil
    default: 
      return nil, instantiateTypeError(p)
  }
}

// Returns false if both are nil!!
func equalValues(a,b interface{}) bool {
  if a == nil || b == nil { return false }
  switch a := a.(type) {
    case int:   return a == b.(int)
    case bool:  return a == b.(bool)
    case []int: if len(a) != len(b.([]int)) { return false }
                for i := range a { 
                  if a[i] != (b.([]int))[i] { return false }
                }
                return true
    case []bool:if len(a) != len(b.([]bool)) { return false }
                for i := range a { 
                  if a[i] != (b.([]bool))[i] { return false }
                }
                return true
    case []byte:if len(a) != len(b.([]byte)) { return false }
                for i := range a { 
                  if a[i] != (b.([]byte))[i] { return false }
                }
                return true
  }
  return false
}

func instantiateSEQUENCE_OF(deftag int, inst *Instance, eletype *Tree, data interface{}, p *pathNode) (*Instance, error) {
  if inst.tag < 0 { 
    inst.tag = deftag 
    inst.implicit = true
  }
  switch data := data.(type) {
    case []interface{}:
      for idx, c := range data {
        child, err := eletype.instantiate(c, &pathNode{parent:p, name:fmt.Sprintf("[%d]", idx)})
        if err != nil { return nil, err }
        inst.children = append(inst.children, (*Tree)(child))
      }
      return inst, nil
    default: 
      return nil, instantiateTypeError(p)
  }
}
