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

// Converts the *Instance to JSON code. params controls various aspects of
// the output. The following params are supported at this time:
//
//  "no-int-names" (string) => INTEGER and ENUMERATED will always be output
//                             as numbers even when a value has a name.
//  "no-bit-names" (string) => BIT STRING will always be output as binary or hex,
//                             even if all set bits have names.
//  "with-types" (string) => Output type information as if all fields were ANY.
//                           This means that almost all values will get type
//                           information. The expection are those values where
//                           the default type assumed by Instantiate() matches
//                           the actual type. For instance a BOOLEAN or NULL will
//                           not get type information even with this flag.
func (i *Instance) JSON(params ...interface{}) string {
  jp := &jsonParams{}
  withTypes := false
  for _, p := range params {
    switch p := p.(type) {
      case string: switch p {
        case "no-int-names": jp.NoIntNames = true
        case "no-bit-names": jp.NoBitNames = true
        case "with-types": withTypes = true
      }
    }
  }
  var s []string
  jsonInstance(&s, (*Tree)(i), jp, withTypes)
  if len(jp.Spill) > 0 {
    return strings.Join(*jp.Spill[0].Data, "")
  } else {
    return strings.Join(s, "")
  }
}


// withType => output type information for proper ANY instantiation
func jsonInstance(s *[]string, t *Tree, jp *jsonParams, withType bool) {
  withTypeOrAny := withType || t.isAny
  switch t.basictype {
    case SEQUENCE, SET, CHOICE:
      tempvar := ""
      if withTypeOrAny {
        tempvar = jp.NextTemp()
        *s = append(*s, "\"$", tempvar, " ", typeName(t), "\"")
        var stemp []string
        s = &stemp
      }
      *s = append(*s, "{\n")
      jp.Indent = append(jp.Indent, "  ")
      for _, c := range t.children {
        *s = append(*s, jp.Indent...)
        *s = append(*s, "\"", c.name, "\": ")
        jsonInstance(s, c, jp, withType)
        *s = append(*s, ",\n")
        for _, spill := range jp.Spill {
          *s = append(*s, jp.Indent...)
          *s = append(*s, "\"", spill.Name, "\": ")
          *s = append(*s, (*spill.Data)...)
          *s = append(*s, ",\n")
        }
        jp.Spill = nil
      }
      if len(t.children) > 0 {
        *s = (*s)[0:len(*s)-1] // remove last ",\n" added in the loop above
      }
      jp.Indent = jp.Indent[0:len(jp.Indent)-1]
      *s = append(*s, "\n")
      *s = append(*s, jp.Indent...)
      *s = append(*s, "}")
      
      if tempvar != "" {
        jp.Spill = append(jp.Spill, tempVar{Name:tempvar, Data:s})
      }
      
    case SEQUENCE_OF, SET_OF:
      if withTypeOrAny {
        tempvar := jp.NextTemp()
        *s = append(*s, "\"$", tempvar, " ", typeName(t), "\"")
        var stemp []string
        s = &stemp
        jp.Spill = append(jp.Spill, tempVar{Name:tempvar, Data:s})
      }
      
      *s = append(*s, "[\n")
      jp.Indent = append(jp.Indent, "  ")
      for _, c := range t.children {
        *s = append(*s, jp.Indent...)
        jsonInstance(s, c, jp, withType)
        *s = append(*s, ",\n")
      }
      if len(t.children) > 0 {
        *s = (*s)[0:len(*s)-1] // remove last ",\n" added in the loop above
      }
      jp.Indent = jp.Indent[0:len(jp.Indent)-1]
      *s = append(*s, "\n")
      *s = append(*s, jp.Indent...)
      *s = append(*s, "]")
    
    case OCTET_STRING, BOOLEAN, OBJECT_IDENTIFIER, INTEGER, ENUMERATED, BIT_STRING: jsonValue(s, t, jp, withType)
    case NULL: *s = append(*s, "null")
    default: panic("Unhandled case in jsonInstance()")
  }
}

func jsonValue(s *[]string, t *Tree, jp *jsonParams, withType bool) {
  withTypeOrAny := withType || t.isAny
  switch v := t.value.(type) {
    case bool:   // BOOLEAN
                 tn := typeName(t)
                 if withTypeOrAny && tn != "BOOLEAN" {
                   *s = append(*s, fmt.Sprintf("\"$'%v' %v\"", v, typeName(t)))
                 } else {
                   *s = append(*s, fmt.Sprintf("%v", v))
                 }
    case []byte: // OCTET_STRING
                 enc, _ := json.Marshal(string(v))
                 var dec string
                 err := json.Unmarshal(enc, &dec)
                 if err != nil { panic(err) }
                 if string(v) == dec {
                   if withTypeOrAny {
                     // remove the quotes surrounding enc
                     enc = enc[1:len(enc)-1]
                     *s = append(*s, "\"$'")
                     // replace ' with '' (the escape mechanism used by Cook())
                     *s = append(*s, strings.Replace(string(enc), "'", "''", -1))
                     *s = append(*s, "' ",typeName(t),"\"")
                   } else {
                     *s = append(*s, string(enc))
                   }
                 } else { // if the data contains invalid UTF-8 sequences and cannot be marshalled losslessly
                   *s = append(*s, "\"$'0x")
                   space := ""
                   for _, b := range v {
                     *s = append(*s, fmt.Sprintf("%v%02X", space, b))
                     space = " "
                   }
                   *s = append(*s, "' decode(hex)")
                   if withTypeOrAny {
                     *s = append(*s, " ", typeName(t))
                   }
                   *s = append(*s, "\"")
                 }
    case *big.Int: // big INTEGER
                 *s = append(*s, fmt.Sprintf("\"$%v %v\"", v, typeName(t)))
    case int:    // INTEGER, ENUMERATED
                 if !jp.NoIntNames {
                   for name, i := range t.namedints {
                     if i == v {
                       *s = append(*s, "\"")
                       if withTypeOrAny {
                         *s = append(*s, "$'", name, "' ", typeName(t))
                       } else {
                         *s = append(*s, name)
                       }
                       *s = append(*s, "\"")
                       return
                     }
                   }
                 }

                 tn := typeName(t)
                 if withTypeOrAny && tn != "INTEGER" {
                   *s = append(*s, fmt.Sprintf("\"$%v %v\"", v, typeName(t)))
                 } else {
                   *s = append(*s, fmt.Sprintf("%v", v))
                 }
    case []int:  // OBJECT_IDENTIFIER
                 *s = append(*s, "\"")
                 if withTypeOrAny {
                   *s = append(*s, "$")
                 }
                 for x, i := range v {
                   if x != 0 {
                     *s = append(*s, ".")
                   }
                   *s = append(*s, fmt.Sprintf("%v", i))
                 }
                 if withTypeOrAny {
                   *s = append(*s, " ", typeName(t))
                 }
                 *s = append(*s, "\"")
    case []bool: // BIT_STRING
                 *s = append(*s, "\"")
                 if withTypeOrAny {
                   *s = append(*s, "$'")
                 }
                 temp := []string{}
                 comma := false
                 
                 // first try to represent all set bits as names
                 // this can only work if the last bit of v is set because otherwise we
                 // need more bits in order to reproduce the proper length of the BIT STRING
                 have_all := len(v) > 0 && v[len(v)-1]
                 have_all = have_all && !jp.NoBitNames
                 // If there is no non-generic type name, we can't use bit names
                 have_all = have_all && t.typename != ""
                 
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
                 if withTypeOrAny {
                   *s = append(*s, "' ", typeName(t))
                 }
                 *s = append(*s, "\"")
    default:    
                 panic("Unhandled case in jsonValue()")
  }
}

func typeName(t *Tree) string {
  if t.typename != "" { return t.typename }
  return strings.Replace(BasicTypeName[t.basictype]," ","_",-1)
}

type jsonParams struct {
  Indent []string
  NoIntNames bool
  NoBitNames bool
  Spill []tempVar
  tempCount int
}

func (jp *jsonParams) NextTemp() string {
  if jp.tempCount == 0 { jp.tempCount = 1000000 }
  jp.tempCount--
  return fmt.Sprintf("_temp%06d", jp.tempCount)
}

type tempVar struct {
  Name string
  Data *[]string
}
