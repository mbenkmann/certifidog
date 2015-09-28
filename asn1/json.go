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
  This file contains the code to convert *asn1.Instance to JSON.
*/

package asn1

import (
         "fmt"
         "sort"
         "strings"
         "math/big"
         "encoding/json"
       )

// flags:
// useIntNames => represent integer and enumerated fields as strings when they contain a named value.
// oidsAsArray => represent oids as arrays of integers (default is string of ints separated by ".")
// wrapNonObject => if the JSON representation of the type would not be enclosed in "{...}", 
//                 wrap it as "{value:...}" where ... is the ordinary representation of the instance.
// wrapAlways => implies wrapNonObject, but also applies a wrapper if the JSON encoding is already an object.
// no-int-names => INTEGER and ENUMERATED will always be output as numbers even when a value has a name.
// no-bit-names => BIT STRING will always be output as binary or hex, even if all set bits have names.
func (i *Instance) JSON(params ...interface{}) string {
  jp := &jsonParams{}
  for _, p := range params {
    switch p := p.(type) {
      case string: switch p {
        case "no-int-names": jp.NoIntNames = true
      }
    }
  }
  var s []string
  jsonInstance(&s, (*Tree)(i), jp)
  return strings.Join(s, "")
}


func jsonInstance(s *[]string, t *Tree, jp *jsonParams) {
  switch t.basictype {
    case SEQUENCE, SET, CHOICE:
      *s = append(*s, "{\n")
      jp.Indent = append(jp.Indent, "  ")
      for _, c := range t.children {
        *s = append(*s, jp.Indent...)
        *s = append(*s, "\"", c.name, "\": ")
        jsonInstance(s, c, jp)
        *s = append(*s, ",\n")
      }
      if len(t.children) > 0 {
        *s = (*s)[0:len(*s)-1] // remove last ",\n" added in the loop above
      }
      jp.Indent = jp.Indent[0:len(jp.Indent)-1]
      *s = append(*s, "\n")
      *s = append(*s, jp.Indent...)
      *s = append(*s, "}")
      
    case SEQUENCE_OF, SET_OF:
      *s = append(*s, "[\n")
      jp.Indent = append(jp.Indent, "  ")
      for _, c := range t.children {
        *s = append(*s, jp.Indent...)
        jsonInstance(s, c, jp)
        *s = append(*s, ",\n")
      }
      if len(t.children) > 0 {
        *s = (*s)[0:len(*s)-1] // remove last ",\n" added in the loop above
      }
      jp.Indent = jp.Indent[0:len(jp.Indent)-1]
      *s = append(*s, "\n")
      *s = append(*s, jp.Indent...)
      *s = append(*s, "]")
    
    case OCTET_STRING, BOOLEAN, OBJECT_IDENTIFIER, INTEGER, ENUMERATED, BIT_STRING: jsonValue(s, t, jp)
    case NULL: *s = append(*s, "null")
    default: panic("Unhandled case in jsonInstance()")
  }
}

func jsonValue(s *[]string, t *Tree, jp *jsonParams) {
  switch v := t.value.(type) {
    case bool:   // BOOLEAN
                 *s = append(*s, strings.ToUpper(fmt.Sprintf("%v", v)))
    case []byte: // OCTET_STRING
                 enc, _ := json.Marshal(string(v))
                 var dec string
                 err := json.Unmarshal(enc, &dec)
                 if err != nil { panic(err) }
                 if string(v) == dec {
                   *s = append(*s, string(enc))
                 } else { // if the data contains invalid UTF-8 sequences and cannot be marshalled losslessly
                   *s = append(*s, "\"$'0x")
                   space := ""
                   for _, b := range v {
                     *s = append(*s, fmt.Sprintf("%v%02X", space, b))
                     space = " "
                   }
                   *s = append(*s, "' decode(hex)\"")
                 }
    case *big.Int: // big INTEGER
                 *s = append(*s, fmt.Sprintf("\"$%v INTEGER\"", v))
    case int:    // INTEGER, ENUMERATED
                 if !jp.NoIntNames {
                   for name, i := range t.namedints {
                     if i == v {
                       *s = append(*s, fmt.Sprintf("\"%v\"", name))
                       return
                     }
                   }
                 }
                 *s = append(*s, fmt.Sprintf("%v", v))
    case []int:  // OBJECT_IDENTIFIER
                 *s = append(*s, "\"")
                 for x, i := range v {
                   if x != 0 {
                     *s = append(*s, ".")
                   }
                   *s = append(*s, fmt.Sprintf("%v", i))
                 }
                 *s = append(*s, "\"")
    case []bool: // BIT_STRING
                 *s = append(*s, "\"")
                 temp := []string{}
                 comma := false
                 
                 // first try to represent all set bits as names
                 // this can only work if the last bit of v is set because otherwise we
                 // need more bits in order to reproduce the proper length of the BIT STRING
                 have_all := len(v) > 0 && v[len(v)-1]
                 
                 if have_all {
                   int2name := map[int]string{}
                   ints := make([]int, 0, len(t.namedints))
                   for name,i := range t.namedints { 
                     int2name[i] = name 
                     ints = append(ints, i)
                   }
                   sort.Ints(ints)
                   for _, i := range ints {
                     if i < len(v) && v[i] {
                       if comma { temp = append(temp, ", ") } else { comma = true }
                       temp = append(temp, int2name[i])
                     } 
                   }
                   
                   // check if all set bits have been output as names
                   for i, set := range v {
                     if set && int2name[i] == "" {
                       have_all = false
                       break
                     }
                   }
                 }

                 if have_all { // if we could represent all bits as names, do so
                   *s = append(*s, temp...)
                 } else { // otherwise ...
                   ofs := 0
                   // if there are more than 16 bits and the number is a multiple of 4, output hex digits
                   if len(v) > 16 && (len(v) % 4 == 0) {
                     *s = append(*s, "0x")
                     b := 0
                     count := 0
                     space := false
                     for ofs < len(v) {
                       b <<= 1
                       if v[ofs] { b += 1 }
                       ofs++
                       count++
                       if count == 4 {
                         *s = append(*s, fmt.Sprintf("%X", b))
                         if space && ofs < len(v) { *s = append(*s, " ") }
                         space = !space
                         count = 0
                         b = 0
                       }
                     }
                   } else {
                     if len(v) > 0 { *s = append(*s, "0b") }
                     for ;ofs < len(v); ofs++ {
                       if v[ofs] { *s = append(*s, "1") } else { *s = append(*s, "0") }
                     }
                   }
                 }
                 *s = append(*s, "\"")
    default:    
                 panic("Unhandled case in jsonValue()")
  }
}

type jsonParams struct {
  Indent []string
  NoIntNames bool
}
