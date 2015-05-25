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
  This file contains the code for converting asn1.Definitions to a string.
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
  ANY: "ANY",
}

// Maps ASN.1 tag&(128+64) to a human-readable string of the class.
var TagClass = map[int]string{0:"UNIVERSAL ", 128: "", 64: "APPLICATION ", 128+64: "PRIVATE "}

func (t *Definitions) String() string {
  if t == nil || t.tree == nil { return "DEFINITIONS IMPLICIT TAGS ::= BEGIN END" }
  var s []string
  stringDEFINITIONS(&s, t.tree)
  return strings.Join(s, "")
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
  if t.tag != -1 {
    *s = append(*s, "[")
    *s = append(*s, TagClass[t.tag & (128+64)])
    *s = append(*s, "")
    *s = append(*s, strconv.Itoa(t.tag & 63))
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
    case bool:   *s = append(*s, strings.ToUpper(fmt.Sprintf("%v", v)))
    case []byte: *s = append(*s, fmt.Sprintf("\"%s\"", v))
    case int:    for name, i := range t.namedints {
                   if i == v {
                     *s = append(*s, fmt.Sprintf("%v", name))
                     return
                   }
                 }
                 *s = append(*s, fmt.Sprintf("%v", v))
    case []int:  *s = append(*s, "{")
                 for _, i := range v {
                   *s = append(*s, fmt.Sprintf(" %v", i))
                 }
                 *s = append(*s, " }")
    case []interface{}:
                 if len(v) == 1 {
                   *s = append(*s, fmt.Sprintf("%v", v[0].(*Tree).name))
                 } else {
                   *s = append(*s, fmt.Sprintf("{ %v", v[0].(*Tree).name))
                   for _, i := range v[1].([]int) {
                     *s = append(*s, fmt.Sprintf(" %v", i))
                   }
                   *s = append(*s, " }")
                 }
    case *Tree:  *s = append(*s, fmt.Sprintf("%v", v.name))
    default:     *s = append(*s, fmt.Sprintf("%v", v))
  }
}
