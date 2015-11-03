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
         "os"
         "fmt"
         "math"
         "regexp"
         "strings"
         "strconv"
         "math/big"
         "unicode/utf8"
       )

func instantiateTypeError(p *pathNode, asn1type string, gotyp interface{}) error {
  return fmt.Errorf("%vAttempt to instantiate ASN.1 type %v from incompatible Go type %T", p, asn1type, gotyp)
}

// Returns an instance of the value called valuename whose definition has to be
// parsed from ASN.1 source by the Parse() method.
func (d *Definitions) Value(valuename string) (*Instance, error) {
  v, ok := d.valuedefs[valuename]
  if !ok {
    return nil, fmt.Errorf("Value %v is undefined", valuename)
  }
  // children are not handled because compound value definitions are not supported, so no value can have children.
  return &Instance{nodetype:instanceNode, tags:v.tags, source_tag:v.source_tag, implicit:v.implicit, name:valuename, typename:v.typename, basictype:v.basictype, value:v.value, namedints:v.namedints, src:v.src, pos:v.pos}, nil
}

// Creates an instance of the type called typename whose definition has to be
// parsed from ASN.1 source by the Parse() method.
// data is the value to be filled into the instance. The value's type must correspond to
// the ASN.1 definition of typename according to the following rules:
// 
// All types can be instantiated from a compatible *Instance or Unmarshalled.
//
// SEQUENCE/SET/CHOICE => map[string]interface{} where the keys match the ASN.1 field names
// SEQUENCE_OF/SET_OF => []interface{}
// OCTET_STRING => string or []byte or []int (if all elements are 0<=i<=255)
// BOOLEAN => bool or string that compares (case-insensitive) to "false" or "true"
// NULL => nil or string that compares (case-insensitive) to "null"
// INTEGER => int, float64, *big.Int or string that either parses as an integer or compares (CASE-SENSITIVE) to
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
// ANY => bool (encoded as BOOLEAN),
//        int or *big.Int (encoded as INTEGER), 
//        []int (encoded as OBJECT IDENTIFIER),
//        []byte (encoded as OCTET STRING),
//        []interface{} (encoded as SEQUENCE OF ANY),
//        string (encoded as UTF8String),
//        []bool (encoded as BIT STRING)
//        float64 (encoded as INTEGER if an integral number)
//        nil (encoded as NULL)
func (d *Definitions) Instantiate(typename string, data interface{}) (*Instance, error) {
  t, ok := d.typedefs[typename]
  if !ok {
    return nil, fmt.Errorf("Type %v is undefined", typename)
  }

  // Fill in typename, because t does not have typename set (see comment in tree.go)
  inst := &Tree{nodetype:t.nodetype, tags:t.tags, source_tag:t.source_tag, implicit:t.implicit, typename:t.name, basictype:t.basictype, value:t.value, children:t.children, namedints:t.namedints, src:t.src, pos:t.pos}
  return inst.instantiate(data,&pathNode{})
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
  inst := &Instance{nodetype:instanceNode, tags:t.tags, source_tag:t.source_tag, implicit:t.implicit, name:t.name, typename:t.typename, basictype:t.basictype, namedints:t.namedints, src:t.src, pos:t.pos}
  
  var inst2 *Tree
  switch d := data.(type) {
    case *UnmarshalledConstructed:
        var d2 Unmarshalled
        if t.basictype == ANY || t.basictype == CHOICE {
          // strip away all constructed shells (i.e. one per tag)
          for _, b := range t.tags {
            if b == 0 {
              dx, _ := d2.(*UnmarshalledConstructed)
              if dx == nil { dx = d }
              // take the first element
              for _, ele := range dx.Data {
                d2 = ele
                break
              }
            }
          }
        } else { // if the type is something other than ANY or CHOICE
          // strip away all constructed shells that match t.tags
          d2 = stripTags(d, t.tags)
        }
        
        // If the above code has stripped at least one constructed shell,
        // continue with the result.
        if d2 != nil {
          data = d2
        }
    case *Instance: inst2 = (*Tree)(d)
    case *Tree: if d.nodetype == instanceNode {
                  // if we're dealing with an Instance, cast it so that it goes into the
                  // correct type switch case
                  return t.instantiate((*Instance)(d), p)
                } else {
                  // if it's a *Tree that is not an *Instance, just let it go through. It will
                  // be reported as an error somewhere.
                  inst2 = d
                }
  }
  if inst2 != nil {
    if inst.basictype != ANY && inst2.basictype != inst.basictype {
      return nil, fmt.Errorf("%vAttempt to instantiate type %v from Instance of type %v", p, BasicTypeName[inst.basictype], BasicTypeName[inst2.basictype])
    }
  }
  
  switch inst.basictype {
    case SEQUENCE, SET: return instantiateSEQUENCE(BasicTypeTag[inst.basictype], inst, t.children, data, p)
    case CHOICE: 
                 // If the data is Unmarshalled, we check if the CHOICE has one child whose
                 // tag matches the one from the Unmarshalled. In that case we just wrap it with
                 // the proper name and call instantiate() recursively. If we don't find a proper
                 // child we just proceed the same as when the data is not Unmarshalled. The
                 // Unmarshalled will then cause an error somewhere down the line.
                 if d, ok := data.(Unmarshalled); ok {
                   for _, c := range t.children {
                     if len(c.tags) > 0 && c.tags[0] == byte(d.Tag()) {
                       return t.instantiate(map[string]interface{}{c.name:data}, p)
                     }
                   }
                 }
                 inst2, err := instantiateSEQUENCE(-1, inst, t.children, data, p)
                 if err == nil {
                   if len(inst2.children) != 1 { 
                     err = fmt.Errorf("%vCHOICE must be instantiated with exactly one data element", p)
                     inst2 = nil
                   }
                 }
                 return inst2, err
    case SEQUENCE_OF, SET_OF: return instantiateSEQUENCE_OF(BasicTypeTag[inst.basictype], inst, t.children[0], data, p)
    case OCTET_STRING: return instantiateOCTET_STRING(inst, data, p)
    case BOOLEAN: return instantiateBOOLEAN(inst, data, p)
    case NULL: return instantiateNULL(inst, data, p)
    case INTEGER: return instantiateINTEGER(inst, data, p)
    case ENUMERATED: inst2, err := instantiateINTEGER(inst, data, p)
                     if err != nil { return inst2, err }
                     switch val := inst2.value.(type) {
                       case int:
                         for _, i := range inst2.namedints {
                           if i == val { return inst2, nil }
                         }
                      }
                     return nil, fmt.Errorf("%vAttempt to instantiate ENUMERATED with number not from allowed set: %v", p, data)
    case OBJECT_IDENTIFIER: return instantiateOBJECT_IDENTIFIER(inst, data, p)
    case BIT_STRING: return instantiateBIT_STRING(inst, data, p)
    case ANY: return instantiateANY(inst, data, p)
    default: return nil, fmt.Errorf("%vUnhandled case in instantiate()", p)
  }
}

var nonIdentifier = regexp.MustCompile(`[^0-9a-zA-Z-]+`)

func instantiateANY(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  inst.isAny = true
  inst.typename = "" // clear potential alias for ANY because it bears no useful information and would pollute JSON output
  tags := make([]byte, len(inst.tags))
  copy(tags, inst.tags)
  inst.tags = tags
  switch data := data.(type) {
    case Unmarshalled:
                switch data.Tag() {
                  case 1: // BOOLEAN
                          inst.basictype = BOOLEAN
                          inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
                          return instantiateBOOLEAN(inst, data, p)
                  case 2: // INTEGER
                          inst.basictype = INTEGER
                          inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
                          return instantiateINTEGER(inst, data, p)
                  case 3: // BIT STRING
                          inst.basictype = BIT_STRING
                          inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
                          return instantiateBIT_STRING(inst, data, p)
                  case 5: // NULL
                          inst.basictype = NULL
                          inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
                          return instantiateNULL(inst, data, p)
                  case 6: // OBJECT IDENTIFIER
                          inst.basictype = OBJECT_IDENTIFIER 
                          inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
                          return instantiateOBJECT_IDENTIFIER(inst, data, p)
                  case 10:// ENUMERATED
                          inst.basictype = ENUMERATED
                          inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
                          return instantiateINTEGER(inst, data, p)
                  case 4,12,18,19,20,21,22,25,26,27,28,29,30: // *String
                          inst.basictype = OCTET_STRING
                          if data.Tag() != 4 && data.Tag() != 29 {
                            inst.typename = UniversalTagName[data.Tag()]
                          }
                          inst.tags = append(inst.tags, byte(data.Tag()), 0)
                          return instantiateOCTET_STRING(inst, data, p)
                  default: 
                          return nil, fmt.Errorf("%vUnsupported unmarshalled type (tag %x) to instantiate ANY with", p, data.Tag())
                }
    case *Instance:
                inst.tags = append(inst.tags, data.tags...)
                inst.basictype = data.basictype
                inst.typename = data.typename
                inst.value = data.value
                inst.children = data.children
                inst.namedints = data.namedints
                inst.src = data.src
                inst.pos = data.pos
                return inst, nil
    case bool: inst.basictype = BOOLEAN
               inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
               return instantiateBOOLEAN(inst, data, p)
    case nil: inst.basictype = NULL
              inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
              return instantiateNULL(inst, data, p)
    case int, float64, *big.Int:  inst.basictype = INTEGER
               inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
               return instantiateINTEGER(inst, data, p)
    case []int: inst.basictype = OBJECT_IDENTIFIER 
               inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
               return instantiateOBJECT_IDENTIFIER(inst, data, p)
    case []byte: inst.basictype = OCTET_STRING
               inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
               return instantiateOCTET_STRING(inst, data, p)
    case string: inst.basictype = OCTET_STRING
                 inst.typename = "UTF8String"
                 inst.tags = append(inst.tags, 12, 0) // UTF8String
                 return instantiateOCTET_STRING(inst, data, p)
    case []bool: inst.basictype = BIT_STRING
                 inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype]), 0)
                 return instantiateBIT_STRING(inst, data, p)
    case []interface{}: 
                 inst.basictype = SEQUENCE_OF
                 inst.tags = append(inst.tags, byte(BasicTypeTag[inst.basictype])|32, 0) // 32 => constructed
                 return instantiateSEQUENCE_OF(16, inst, &Tree{nodetype:instanceNode, tags:[]byte{}, source_tag:-1, implicit:false, basictype:ANY, src:inst.src, pos:inst.pos} , data, p)
    default: return nil, instantiateTypeError(p, "ANY", data)
  }
}

func instantiateBIT_STRING(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *Instance: inst.value = data.value
    case []bool: inst.value = data
    case []byte: bits := make([]bool, len(data)*8)
                 inst.value = bits
                 for i, b := range data {
                   for k := 0; k < 8; k++ {
                     bits[i*8+k] = (b & (128 >> uint(k))) != 0
                   }
                 }
    case *UnmarshalledPrimitive:
                 if len(data.Data) == 0 {
                     return nil, fmt.Errorf("%vAttempt to instantiate BIT STRING from empty DER data", p)
                  }
                 unused_bits_count := int(data.Data[0])
                 if (unused_bits_count > 0 && len(data.Data) == 1) || unused_bits_count > 7 {
                     return nil, fmt.Errorf("%vAttempt to instantiate BIT STRING with illegal DER data (incorrect unused bits count: %v)", p, unused_bits_count)
                 }
                 inst, err := instantiateBIT_STRING(inst, data.Data[1:], p)
                 if err != nil { return inst, err }
                 bits := inst.value.([]bool)
                 inst.value = bits[0:len(bits)-unused_bits_count]
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
    default: return nil, instantiateTypeError(p, "BIT STRING", data)
  }
  return inst, nil
}


var nonDigits = regexp.MustCompile(`[^[:digit:]]+`)

func instantiateOBJECT_IDENTIFIER(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *UnmarshalledPrimitive: return instantiateOBJECT_IDENTIFIER(inst, oidString(data.Data), p)
    case *Instance: inst.value = data.value
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
    default: return nil, instantiateTypeError(p, "OBJECT IDENTIFIER", data)
  }
  return inst, nil
}

func instantiateINTEGER(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *UnmarshalledPrimitive: if len(data.Data) == 0 {
                     return nil, fmt.Errorf("%vAttempt to instantiate INTEGER from empty DER data", p)
                   }
                   var b big.Int
                   b.SetBytes(data.Data)
                   if data.Data[0] & 128 != 0 { // negative number
                     var x big.Int
                     x.SetBit(&x, len(data.Data)*8, 1)
                     x.Sub(&x, &b)
                     b.Neg(&x)
                   }
                   return instantiateINTEGER(inst, &b, p)
    case *Instance: inst.value = data.value
    case *big.Int: i := int(data.Int64())
                  if big.NewInt(int64(i)).Cmp(data) == 0 {
                    inst.value = i // store as int if possible
                  } else {
                    inst.value = data // use *big.Int if necessary
                  }
    case int: inst.value = data
    case float64: if math.Floor(data) != data {
                    return nil, fmt.Errorf("%vAttempt to instantiate INTEGER with non-integral float64: %v", p, data)
                  }
                  inst.value = int(data)
    case string: if i, found := inst.namedints[data]; found {
                   inst.value = i
                 } else {
                   bi := new(big.Int)
                   _, ok := bi.SetString(data, 10)
                   if ok {
                     return instantiateINTEGER(inst, bi, p)
                   } else {
                     return nil, fmt.Errorf("%vAttempt to instantiate INTEGER/ENUMERATED from illegal string: %v", p, data)
                   }
                 }
    default: return nil, instantiateTypeError(p, "INTEGER", data)
  }
  return inst, nil
}

func instantiateBOOLEAN(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *Instance: inst.value = data.value
    case *UnmarshalledPrimitive:
         inst.value = (len(data.Data) == 1 && data.Data[0] == 255)
    case bool: inst.value = data
    case string: data = strings.ToLower(data)
                 if data == "false" {
                   inst.value = false
                 } else if data == "true" {
                   inst.value = true
                 } else {
                   return nil, fmt.Errorf("%vAttempt to instantiate BOOLEAN from string that's neither \"true\" nor \"false\": %v", p, data)
                 }
    default: return nil, instantiateTypeError(p, "BOOLEAN", data)
  }
  return inst, nil
}

func instantiateNULL(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *Instance: inst.value = data.value
    case *UnmarshalledPrimitive:
                   if len(data.Data) != 0 {
                     return nil, fmt.Errorf("%vAttempt to instantiate NULL from non-empty DER data", p)
                   }
                   inst.value = nil
    case nil: inst.value = data
    case string: data = strings.ToLower(data)
                 if data == "null" {
                   inst.value = nil
                 } else {
                   return nil, fmt.Errorf("%vAttempt to instantiate NULL from string that's not \"null\": %v", p, data)
                 }
    default: return nil, instantiateTypeError(p, "NULL", data)
  }
  return inst, nil
}

func instantiateOCTET_STRING(inst *Instance, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *Instance: inst.value = data.value
    case string: inst.value = []byte(data)
    case []byte: inst.value = data
    case []int: d := make([]byte, len(data))
                for idx, i := range data {
                  if i < 0 || i > 255 {
                    return nil, fmt.Errorf("%vWhile instantiating OCTET STRING from []int, element [%v] out of range: %v", p, idx, i)
                  }
                  d[idx] = byte(i)
                }
                inst.value = d
    
    case *UnmarshalledPrimitive: 
                if inst.tags[len(inst.tags)-2] == 30 { // BMPString; -2 because the last byte is 0
                   inst.value = decodeUTF16(data.Data)
                 } else {
                   inst.value = data.Data
                 }
    default: return nil, instantiateTypeError(p, "OCTET STRING", data)
  }
  return inst, nil
}

func instantiateSEQUENCE(deftag int, inst *Instance, children []*Tree, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *Instance: 
      if inst.typename == "" || inst.typename != data.typename {
        return nil, fmt.Errorf("%vCannot instantiate complex type named \"%v\" from complex type named \"%v\". Both types must have the same name and that name must be non-empty.", p, inst.typename, data.typename)
      }
      inst.children = data.children
      inst.src = data.src
      inst.pos = data.pos
      return inst, nil
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
            child := &Instance{nodetype:instanceNode, tags:c.tags, source_tag:c.source_tag, implicit:c.implicit, name:c.name, typename:c.typename, basictype:c.basictype, value:c.value, namedints:c.namedints, src:c.src, pos:c.pos}
            inst.children = append(inst.children, (*Tree)(child))
            child.isDefaultValue = equalValues(c.value, child.value)
          }
        }
      }
      return inst, nil
    case *UnmarshalledConstructed:
      return instantiateSEQUENCE(deftag, inst, children, mapRawtagsToNames(children, data) ,p)
    default: 
      return nil, instantiateTypeError(p, "SEQUENCE/SET/CHOICE", data)
  }
}

func instantiateSEQUENCE_OF(deftag int, inst *Instance, eletype *Tree, data interface{}, p *pathNode) (*Instance, error) {
  switch data := data.(type) {
    case *Instance: 
      children := make([]interface{}, len(data.children))
      for i := range data.children {
        children[i] = data.children[i]
      }
      return instantiateSEQUENCE_OF(deftag, inst, eletype, children, p)
    case []interface{}:
      for idx, c := range data {
        child, err := eletype.instantiate(c, &pathNode{parent:p, name:fmt.Sprintf("[%d]", idx)})
        if err != nil { return nil, err }
        inst.children = append(inst.children, (*Tree)(child))
      }
      return inst, nil
    case *UnmarshalledConstructed:
      // extract type 2) keys (see doc of Rawtag type)
      // and sort them by increasing key length
      keys := make([]Rawtag, 0, len(data.Data))
      for key := range data.Data {
        if key[len(key)-1] == 0 {
          idx := len(keys)-1
          keys = append(keys, "")
          for idx >= 0 && len(key) < len(keys[idx]) {
            keys[idx+1] = keys[idx]
            idx--
          }
          keys[idx+1] = key
        }
      }
      // create an array of the children in order of the length of
      // the keys. This recreates the original order in the DER bytes that were unmarshalled.
      children := make([]interface{}, len(keys))
      for i, key := range keys {
        children[i] = data.Data[key]
      }
      return instantiateSEQUENCE_OF(deftag, inst, eletype, children, p)
    default: 
      return nil, instantiateTypeError(p, "SEQUENCE/SET OF", data)
  }
}

// In the *Tree, a single node may have multiple tags, but in the DER-encoding
// this looks like multiple nested SEQUENCEs with just one member. When such
// a DER encoding is decoded with UnmarshalDER(), the result is a structure
// with multiple nested *UnmarshalledConstructed. This function realigns the
// two representations by stripping away (you could also say "entering") one
// *UnmarshalledConstructed for each of the tags.
//
// Technically: If tags contains t1,t2,...,tN, then this function returns
// data.Data[t2]...[tN] if all those keys exist. Otherwise returns nil.
//
// Note: The reason why the tags that are stripped are t2..tN (i.e. not including
//       t1) is that t1 is the key that maps to data.
func stripTags(data *UnmarshalledConstructed, tags []byte) Unmarshalled {
  var result Unmarshalled
  tagstart := 0
  for tagstart < len(tags) && tags[tagstart] != 0 { tagstart++ }
  tagstart++
  for i := tagstart; i < len(tags); i++ {
    if tags[i] == 0 {
      r := Rawtag(tags[tagstart:i])
      tagstart = i+1
      if result == nil { result = data }
      switch res := result.(type) {
        case *UnmarshalledConstructed:
          var found bool
          result, found = res.Data[r]
          if !found {
            return nil
          }
        default:
          return nil
      }
    }
  }
  return result
}

// For each child in children, this function tries to find a matching child from in.
// With the result it will create a new map that maps the name of the child from children
// to the child from in.
// In order to find the matching child the function will first look for an entry whose
// key exactly matches the tag of the child. If no such child is found it will use the
// non-optional preceding children in the children list as context and will try to find
// a key from in that contains all of the proper tags (see imperfectKeyMatch()).
func mapRawtagsToNames(children []*Tree, in *UnmarshalledConstructed) map[string]interface{} {
  if Debug {
    fmt.Fprintf(os.Stderr, "Mapping ")
    for n := range in.Data {
      fmt.Fprintf(os.Stderr, "%x ", n)
    }
    fmt.Fprintf(os.Stderr, "to ")
    for _,n := range children {
      fmt.Fprintf(os.Stderr, "%v ", n.name)
    }
    fmt.Fprintf(os.Stderr,"\n")
  }
  
  used_unique_tags := map[int]bool{}
  
  altkeys := [][]byte{}
  for key := range in.Data {
    if key[len(key)-1] == 0 {
      altkeys = append(altkeys, []byte(key))
    }
  }
  
  out := map[string]interface{}{}
  non_optional := []byte{}
  optional := 0 // just counts the length of optional tags
  for _, c := range children {
    first_tag_bytes := []byte{}
    found := false
    var child Unmarshalled
    child_tag_bytes := []byte{}
    
    if len(c.tags) > 0 {  // a 0-length c.tags is possible for a CHOICE or ANY with no tag of its own
      ft := 0
      for c.tags[ft] != 0 { ft++ } // find end of first tag
      // We only need the first tag. The others are modelled as sub-maps and will be handled by stripTags()
      first_tag := Rawtag(c.tags[0:ft])
      first_tag_bytes = c.tags[0:ft+1]
      if Debug {
        fmt.Fprintf(os.Stderr, "Looking for %v as %x\n",c.name, c.tags[0:ft])
      }
        
      child, found = in.Data[first_tag]
      child_tag_bytes = first_tag_bytes
      if found && used_unique_tags[child.Tag()] {
        found = false // do not reuse elements
      }
      if found {
        used_unique_tags[child.Tag()] = true
      } else if Debug {
        fmt.Fprintf(os.Stderr, "%v not found as %x =>",c.name, c.tags[0:ft])
      }
    } else {
      if Debug {
        fmt.Fprintf(os.Stderr, "%v is %v with no tag =>",c.name, BasicTypeName[c.basictype])
      }
    }
    
    if !found {
      alternative_key := append(non_optional, first_tag_bytes...)
      if Debug {
        fmt.Fprintf(os.Stderr, " Trying to find by context as %x\n", alternative_key)
      }
      best := 999999
      best_i := 0
      for i := range altkeys {
        if Debug {
          fmt.Fprintf(os.Stderr, "%x, %d >= %d, %d <= %d, %d < %d\n", altkeys[i], len(altkeys[i]), len(alternative_key), len(alternative_key)+optional, len(altkeys[i]), len(altkeys[i]), best)
        }
        if len(altkeys[i]) >= len(alternative_key) && 
           len(alternative_key)+optional <= len(altkeys[i]) &&
           len(altkeys[i]) < best &&
           imperfectKeyMatch(alternative_key, altkeys[i], len(first_tag_bytes)) {
             child2 := in.Data[Rawtag(altkeys[i])]
             if !used_unique_tags[child2.Tag()] { // do not use an already used unique tag via altkeys
               child = child2
               best = len(altkeys[i])
               best_i = i
               found = true
               if len(first_tag_bytes) == 0 {
                 // extract last tag from altkeys[i]
                 child_tag_bytes = altkeys[i]
                 k := 0
                 for k < len(child_tag_bytes)-1 {
                   if child_tag_bytes[k] == 0 {
                     child_tag_bytes = child_tag_bytes[k+1:]
                     k = 0
                   } else {
                     k++
                   }
                 }
               }
             }
           }
      }
      
      if found {
        if Debug {
          fmt.Fprintf(os.Stderr, "Found %v as %x", c.name, altkeys[best_i])
          if ccc, ok := child.(*UnmarshalledConstructed); ok {
            fmt.Fprintf(os.Stderr, " containing %v elements", len(ccc.Data))
          }
          fmt.Fprintf(os.Stderr, "\n")
        }
        
        altkeys[best_i] = nil // don't use the same element twice
        if _, is_unique := in.Data[Rawtag(child_tag_bytes[0:len(child_tag_bytes)-1])]; is_unique {
          used_unique_tags[child.Tag()] = true
        }
      }
    }
      
    if found {
      if Debug { fmt.Fprintf(os.Stderr, "Found %v\n", c.name) }
      out[c.name] = child
    } else {
      if Debug { fmt.Fprintf(os.Stderr, "Not Found %v\n", c.name) }
    }
    
    if !c.optional {
      non_optional = append(non_optional, child_tag_bytes...)
    } else {
      if found { // we must only count optional tags that are actually present
        optional += len(child_tag_bytes)
      }
    }
  }
  return out
}


// Both alternative_key and key are concatenated DER encoded tags with a 0-byte following
// each tag. taglen is the either 0 which means that there is assumed a wild card tag after
// alternative_key; or taglen is the number of bytes of the last tag in alternative_key 
// (including the 0-byte following the tag).
// This function returns true iff alternative_key and key end in the same tag (which is
// always assumed to be true if taglen==0) and all tags from alternative_key occur in
// the same order within key.
func imperfectKeyMatch(alternative_key []byte, key []byte, taglen int) bool {
  // First check if key and alternative_key end in the same tag of length taglen
  if len(alternative_key) < taglen || len(key) < taglen { return false }
  for i := 1; i <= taglen; i++ {
    if alternative_key[len(alternative_key)-i] != key[len(key)-i] { return false }
  }
  
  // make sure there's a tag boundary
  if len(key) > taglen && key[len(key)-1-taglen] != 0 { return false }
  
  // Now check if all other tags in alternative key are found somewhere in the same order within key
  
  // First chop off the last tag of alternative_key which has already been verified above
  alternative_key = alternative_key[0:len(alternative_key)-taglen]
  
  // Now chop off the last tag of key. We CAN NOT simply chop off the last taglen characters
  // as we did above for alternative_key because there is the special case of
  // taglen == 0 which means that the last tag in alternative_key is missing because we're dealing with
  // an ANY or CHOICE whose tag depends on the contents. In that case the last tag is a wildcard.
  // So we need to chop off the last tag of key without referring to taglen
  i := len(key)-2
  for ; i >= 0; i-- {
    if key[i] == 0 {
      key = key[0:i+1]
      break
    }
  }
  if i < 0 { key = key[0:0] }
  
  a := 0
  k := 0
  for a < len(alternative_key) && k < len(key) {
    i := 0
    for a+i < len(alternative_key) && k+i < len(key) && alternative_key[a+i] == key[k+i] {
      if alternative_key[a+i] == 0 {
        a = a+i+1
        break
      }
      i++
    }
    
    // advance k to start of next tag
    for k < len(key) && key[k] != 0 { k++ }
    k++
  }
  
  if a == len(alternative_key) {
    return true
  }
  
  return false
}


// Returns false if both are nil!!
func equalValues(a,b interface{}) bool {
  if a == nil || b == nil { return false }
  switch a := a.(type) {
    case int:   switch b := b.(type) {
                  case int: return a == b
                }
    case *big.Int: switch b := b.(type) {
                    case *big.Int: return a.Cmp(b) == 0
                  }
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

func decodeUTF16(data []byte) []byte {
  if len(data) & 1 == 1 { // odd number of bytes => no proper UTF16 sequence
    return data
  }
  output := make([]byte,0,len(data)>>1)
  buf := make([]byte, 8)
  for i := 0; i < len(data); i += 2 {
    b := buf[0:utf8.EncodeRune(buf[:],(rune(data[i]) << 8) + rune(data[i+1]))]
    output = append(output, b...)
  }
  return output
}

func encodeUTF16(data []byte) []byte {
  output := make([]byte,0,len(data)<<1)
  for len(data) > 0 {
    r, sz := utf8.DecodeRune(data)
    data = data[sz:]
    output = append(output, byte(r >> 8), byte(r & 255))
  }
  return output
}
