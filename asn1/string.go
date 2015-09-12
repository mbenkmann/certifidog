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
  This file contains the code for converting asn1.Definitions and
  asn1.Instance to a string.
*/

package asn1

import (
         "fmt"
         "sort"
         "strings"
         "strconv"
)

// Maps basic type integer constants to human readable strings.
var BasicTypeName = map[int]string{
  UNKNOWN: "UNKNOWN",
  SEQUENCE: "SEQUENCE",
  SEQUENCE_OF: "SEQUENCE OF",
  SET_OF: "SET OF",
  SET: "SET",
  CHOICE: "CHOICE",
  OCTET_STRING: "OCTET STRING",
  BIT_STRING: "BIT STRING",
  OBJECT_IDENTIFIER: "OBJECT IDENTIFIER",
  INTEGER: "INTEGER",
  ENUMERATED: "ENUMERATED",
  BOOLEAN: "BOOLEAN",
  NULL: "NULL",
  ANY: "ANY",
}

// Maps standard UNIVERSAL tags to their names
var UniversalTagName = map[int]string{
  0: "END-OF-CONTENTS",
  1: "BOOLEAN",
  2: "INTEGER",
  3: "BIT STRING",
  4: "OCTET STRING",
  5: "NULL",
  6: "OBJECT IDENTIFIER",
  7: "ObjectDescriptor",
  8: "INSTANCE OF, EXTERNAL",
  9: "REAL",
 10: "ENUMERATED",
 11: "EMBEDDED PDV",
 12: "UTF8String",
 13: "RELATIVE-OID",
 14: "UNKNOWN-14",
 15: "UNKNOWN-15",
 16: "SEQUENCE, SEQUENCE OF",
 17: "SET, SET OF",
 18: "NumericString",
 19: "PrintableString",
 20: "TeletexString, T61String",
 21: "VideotexString",
 22: "IA5String",
 23: "UTCTime",
 24: "GeneralizedTime",
 25: "GraphicString",
 26: "VisibleString, ISO646String",
 27: "GeneralString",
 28: "UniversalString",
 29: "CHARACTER STRING",
 30: "BMPString",
}

// Maps ASN.1 tag&(128+64) to a human-readable string of the class.
var TagClass = map[int]string{0:"UNIVERSAL ", 128: "", 64: "APPLICATION ", 128+64: "PRIVATE "}

func (i *Instance) String() string {
  var s []string
  stringInstance(&s, (*Tree)(i))
  return strings.Join(s, "")
}

func (t *Definitions) String() string {
  if t == nil || t.tree == nil { return "DEFINITIONS IMPLICIT TAGS ::= BEGIN END" }
  var s []string
  stringDEFINITIONS(&s, t.tree)
  return strings.Join(s, "")
}

func stringInstance(s *[]string, t *Tree) {
  switch t.basictype {
    case CHOICE:
      stringInstance(s, t.children[0])
    case SEQUENCE, SET:
      *s = append(*s, BasicTypeName[t.basictype], " { ")
      for _, c := range t.children {
        *s = append(*s, c.name, ": ")
        stringInstance(s, c)
        *s = append(*s, ", ")
      }
      if len(t.children) > 0 {
        *s = (*s)[0:len(*s)-1] // remove last ", " added in the loop above
      }
      *s = append(*s, " }")
      
    case SEQUENCE_OF, SET_OF:
      if t.basictype == SEQUENCE_OF {
        *s = append(*s, "SEQUENCE [")
      } else {
        *s = append(*s, "SET [")
      }
      for _, c := range t.children {
        stringInstance(s, c)
        *s = append(*s, ", ")
      }
      if len(t.children) > 0 {
        *s = (*s)[0:len(*s)-1] // remove last ", " added in the loop above
      }
      *s = append(*s, "]")
    
    case OCTET_STRING, BOOLEAN, OBJECT_IDENTIFIER, INTEGER, ENUMERATED, BIT_STRING: stringValue(s, t)
    case NULL: *s = append(*s, "NULL")
    default: panic("Unhandled case in stringInstance()")
  }
}

func stringDEFINITIONS(s *[]string, t *Tree) {
  if t.implicit {
    *s = append(*s, "DEFINITIONS IMPLICIT TAGS ::=\n\nBEGIN\n\n")
  } else {
    *s = append(*s, "DEFINITIONS EXPLICIT TAGS ::=\n\nBEGIN\n\n")
  }
  
  for _, c := range t.children {
    if c.nodetype == typeDefNode { 
      stringTypeDefinition(s, c)
      *s = append(*s, "\n\n")
    } else {
      stringValueDefinition(s, c) 
      *s = append(*s, "\n\n")
    }
  }
  
  *s = append(*s, "\nEND\n")
}

func stringTypeDefinition(s *[]string, t *Tree) {
  *s = append(*s, t.name)
  *s = append(*s, " ::= ")
  stringType("", s, t)
}

func stringType(indent string, s *[]string, t *Tree) {
  if t.source_tag != -1 {
    *s = append(*s, "[")
    *s = append(*s, TagClass[t.source_tag & (128+64)])
    *s = append(*s, "")
    *s = append(*s, strconv.Itoa(t.source_tag & 63))
    *s = append(*s, "]")
    if t.implicit {
      *s = append(*s, " IMPLICIT ")
    } else {
      *s = append(*s, " EXPLICIT ")
    }
  }
  
  if t.typename != "" {
    *s = append(*s, t.typename)
  } else {
    *s = append(*s, BasicTypeName[t.basictype])
    if t.basictype == SET_OF || t.basictype == SEQUENCE_OF {
      *s = append(*s, " ")
      stringType(indent, s, t.children[0])
    } else if t.basictype == SET || t.basictype == SEQUENCE || t.basictype == CHOICE  {
      *s = append(*s, " ")
      stringStructure(indent, s, t)
    } else if len(t.namedints) > 0 {
      *s = append(*s, " ")
      stringLabelledInts(indent, s, t)
    }
  }
  
  if t.optional {
    if t.value != nil {
      *s = append(*s, " DEFAULT ")
      stringValue(s, t)
    } else {
      *s = append(*s, " OPTIONAL")
    }
  }
}

func stringValueDefinition(s *[]string, t *Tree) {
  *s = append(*s, t.name)
  *s = append(*s, " ")
  if t.typename != "" {
    *s = append(*s, t.typename)
  } else {
    *s = append(*s, BasicTypeName[t.basictype])
  }
  *s = append(*s, " ::= ")
  stringValue(s, t)
}

func stringStructure(indent string, s *[]string, t *Tree) {
  *s = append(*s, "{\n")
  for i, c := range t.children {
    *s = append(*s, indent+"    ")
    *s = append(*s, c.name)
    *s = append(*s, " ")
    stringType(indent+"    ", s, c)
    if i < len(t.children)-1 {
      *s = append(*s, ",")
    }
    *s = append(*s, "\n")
  }
  *s = append(*s, indent)
  *s = append(*s, "}")
}

func stringLabelledInts(indent string, s *[]string, t *Tree) {
  *s = append(*s, "{\n")
  values := make([]int, 0, len(t.namedints))
  intnames := map[int]string{}
  for name, i := range t.namedints { 
    values = append(values, i) 
    intnames[i] = name
  }
  sort.Ints(values)
  for i := range values {
    *s = append(*s, indent+"    ")
    *s = append(*s, intnames[values[i]])
    *s = append(*s, " (")
    *s = append(*s, fmt.Sprintf("%v", values[i]))
    *s = append(*s, ")")
    if i < len(values)-1 {
      *s = append(*s, ",")
    }
    *s = append(*s, "\n")
  }
  *s = append(*s, indent)
  *s = append(*s, "}")
}

func stringValue(s *[]string, t *Tree) {
  switch v := t.value.(type) {
    case bool:   // BOOLEAN
                 *s = append(*s, strings.ToUpper(fmt.Sprintf("%v", v)))
    case []byte: // OCTET_STRING
                 *s = append(*s, fmt.Sprintf("%q", v))
    case int:    // INTEGER, ENUMERATED
                 for name, i := range t.namedints {
                   if i == v {
                     *s = append(*s, fmt.Sprintf("%v", name))
                     return
                   }
                 }
                 *s = append(*s, fmt.Sprintf("%v", v))
    case []int:  // OBJECT_IDENTIFIER
                 *s = append(*s, "{")
                 for _, i := range v {
                   *s = append(*s, fmt.Sprintf(" %v", i))
                 }
                 *s = append(*s, " }")
    case []interface{}: // semi-resolved OBJECT_IDENTIFIER (only during post-processing of parsing)
                 if len(v) == 1 {
                   *s = append(*s, fmt.Sprintf("%v", v[0].(*Tree).name))
                 } else {
                   *s = append(*s, fmt.Sprintf("{ %v", v[0].(*Tree).name))
                   for _, i := range v[1].([]int) {
                     *s = append(*s, fmt.Sprintf(" %v", i))
                   }
                   *s = append(*s, " }")
                 }
    case []bool: // BIT_STRING
                 *s = append(*s, "(")
                 comma := false
                 // first output names of named bits that are set
                 int2name := map[int]string{}
                 ints := make([]int, 0, len(t.namedints))
                 for name,i := range t.namedints { 
                   int2name[i] = name 
                   ints = append(ints, i)
                 }
                 sort.Ints(ints)
                 for _, i := range ints {
                   if i < len(v) && v[i] {
                     if comma { *s = append(*s, ", ") } else { comma = true }
                     *s = append(*s, fmt.Sprintf("%v", int2name[i]))
                   } 
                 }
                 
                 // check if all set bits have been output as names or if we need to output more
                 have_all := true
                 for i, set := range v {
                   if set && int2name[i] == "" {
                     have_all = false
                     break
                   }
                 }
                 if !have_all {
                   ofs := 0
                   // if there are more than 16 bits, output octets as hex
                   if len(v) > 16 {
                     if comma { *s = append(*s, ", ") } else { comma = true }
                     *s = append(*s, "0x")
                     b := 0
                     count := 0
                     space := false
                     for ofs < len(v) & ^7 {
                       b <<= 1
                       if v[ofs] { b += 1 }
                       ofs++
                       count++
                       if count == 8 {
                         if space { *s = append(*s, " ") }
                         space = true
                         *s = append(*s, fmt.Sprintf("%02X", b))
                         count = 0
                         b = 0
                       }
                     }
                   }
                   // if there are remaining bits not output as octets, output as 0s and 1s
                   if ofs < len(v) {
                     if comma { *s = append(*s, ", ") } else { comma = true }
                     *s = append(*s, "0b")
                     for ;ofs < len(v); ofs++ {
                       if v[ofs] { *s = append(*s, "1") } else { *s = append(*s, "0") }
                     }
                   }
                 }
                 *s = append(*s, ")")
    case *Tree:  // semi-resolved reference to a named value (only during post-processing)
                 *s = append(*s, fmt.Sprintf("%v", v.name))
    default:     // unresolved, raw value from parsing (i.e. a string)
                 *s = append(*s, fmt.Sprintf("%v", v))
  }
}
