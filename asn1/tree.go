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


package asn1

import (
         "strings"
         "strconv"
         "unicode"
)

const (
  UNKNOWN = iota
  DEFINITIONS
  SEQUENCE
  SEQUENCE_OF
  SET_OF
  SET
  CHOICE
  OCTET_STRING
  BIT_STRING
  OBJECT_IDENTIFIER
  INTEGER
  ENUMERATED
  ANY
)

var BasicTypeName = map[int]string{
  UNKNOWN: "UNKNOWN",
  DEFINITIONS: "!!ERROR!!",
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
  ANY: "ANY",
}

var TagClass = map[int]string{0:"UNIVERSAL ", 128: "", 64: "APPLICATION ", 128+64: "PRIVATE "}

type Tree struct {
  tag int
  implicit bool
  optional bool
  typename string
  basictype int
  name string
  value []byte
  default_value []byte
  children []*Tree
}

func (t* Tree) Type() string {
  if t.typename != "" { return t.typename }
  return BasicTypeName[t.basictype]
}

func (t *Tree) String() string {
  var s []string
  switch(t.basictype) {
    case DEFINITIONS: stringDEFINITIONS(&s, t)
    default: return "<???asn1.Tree???>"
  }
  
  return strings.Join(s, "")
}

func stringDEFINITIONS(s *[]string, t *Tree) {
  if t.implicit {
    *s = append(*s, "DEFINITIONS IMPLICIT TAGS ::=\n\nBEGIN\n\n")
  } else {
    *s = append(*s, "DEFINITIONS EXPLICIT TAGS ::=\n\nBEGIN\n\n")
  }
  
  for _, c := range t.children {
    if unicode.IsUpper(rune(c.name[0])) { 
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
    } else if len(t.children) > 0 {
      *s = append(*s, " ")
      stringLabelledInts(indent, s, t)
    }
  }
  
  if t.optional {
    if len(t.default_value) > 0 {
      *s = append(*s, " DEFAULT ")
      *s = append(*s, string(t.default_value))
    } else {
      *s = append(*s, " OPTIONAL")
    }
  }
}

func stringValueDefinition(s *[]string, t *Tree) {
  *s = append(*s, t.name)
  *s = append(*s, " ")
  *s = append(*s, t.Type())
  *s = append(*s, " ::= ")
  *s = append(*s, string(t.value))
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
  for i, c := range t.children {
    *s = append(*s, indent+"    ")
    *s = append(*s, c.name)
    *s = append(*s, " (")
    *s = append(*s, string(c.value))
    *s = append(*s, ")")
    if i < len(t.children)-1 {
      *s = append(*s, ",")
    }
    *s = append(*s, "\n")
  }
  *s = append(*s, indent)
  *s = append(*s, "}")
}

