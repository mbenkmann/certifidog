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
  This file contains the tree structure that is used both for storing
  the parsed ASN.1 data structure definitions as well as concrete instances of these
  data structures.
*/

package asn1

import (
         "fmt"
         "sort"
         "regexp"
         "strings"
         "strconv"
)

// set this to true to get debug output to stderr
var Debug = false

// Integer constants for ASN.1 basic types (field Tree.basictype).
const (
  UNKNOWN = iota
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
  BOOLEAN
  ANY
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

// Constants for node types within Tree.
const (
  // Uninitialized node.
  undefinedNode = iota
  
  // The root node of the parsed ASN.1 Tree. The children of this node are
  // typeDefNode and valueDefNode nodes.
  rootNode
  
  // A type definition (upper case identifier). These nodes only occur as immediate
  // children of rootNode. In particular structures within structures do not
  // have this type. They have type fieldNode.
  typeDefNode
  
  // A value definition (lower case identifier). These nodes only occur as
  // immediate children of rootNode. In particular named integers within
  // an INTEGER type are not nodes of this type. They aren't nodes at all but
  // instead are stored in the namedints map.
  valueDefNode
  
  // A node with basic type SEQUENCE_OF (which may be a typeDefNode, fieldNode or ofNode)
  // has exactly one ofNode child.
  ofNode
  
  // Children of a node with basic type SEQUENCE (which may be a typeDefNode, fieldNode or ofNode)
  // are of type fieldNode.
  fieldNode
  
  // In an instance of an ASN.1 data structure all nodes have type instanceNode.
  instanceNode
)

// Maps ASN.1 tag&(128+64) to a human-readable string of the class.
var TagClass = map[int]string{0:"UNIVERSAL ", 128: "", 64: "APPLICATION ", 128+64: "PRIVATE "}

// The main data structure to store both ASN.1 definitions (type and value) as well as
// instances of such definitions.
type Tree struct {
  // See the constants above (rootNode, typeDefNode,...)
  nodetype int
  
  // The ASN.1 tag of the node. This includes the class bits.
  // For nodes of type instanceNode this is always properly set. For other
  // nodes this is -1 if the ASN.1 source does not explicitly specify a tag.
  // When an instanceNode is created from a node with tag==-1 the tag is
  // determined from the basictype field.
  tag int
  
  // If false, the DER representation of this node is prefixed with an extra tag byte (that
  // is then followed by the tag derived from basictype). If true, there is only one tag byte
  // that is either the tag field or (if tag==-1) derived from basictype.
  implicit bool
  
  // Only meaningful for fieldNode. If true, the field may be omitted when instantiating
  // the SEQUENCE that contains the field. In this case, if value!=nil, that value is
  // the default value to use when the field is omitted.
  optional bool
  
  // typeDefNode: the (upper-case) name of the type being defined
  // valueDefNode: the (lower-case) name of the value being defined
  // fieldNode: the (lower-case) name of the field within the sequence
  // other nodes: unspecified
  name string
  
  // This is "" if the ASN.1 source defines the node directly as a
  // basic type, or the name of the non-basic type the ASN.1 source defines this node as.
  // When instantiating a node with non-"" typename, the definition of that type has
  // to be instantiated.
  // Recursive definitions are possible and even useful when fields are marked optional.
  // This is why type definitions are not inlined at parse time and left as typename references
  // until instantiation.
  // ATTENTION!! For a typeDefNode this is NOT the name of the type being defined (that's
  // found in the 'name' field). It's the name of the non-basic type the new type is an
  // alias for, or "" if the new type is defined as a basic type.
  typename string
  
  // One of the constants defined further above (SEQUENCE, INTEGER,...).
  // Post-processing performed after parsing the ASN.1 source fills in this field
  // for nodes that use non-basic types in the source code. This means that this
  // field is valid even if typename != "" and specifies the resolved basic type.
  basictype int
  
  // valueDefNode: the value being named
  // fieldNode: if optional==true, this is the DEFAULT value
  // instanceNode: if the node is of a non-compound basic type, this is the value
  // NOTE ON Go TYPE: During parsing of the ASN.1 source this is always a string.
  //                  In the post-processing step when references to named values
  //                  are resolved, this is replaced by one of the following types:
  //                  int: for ENUMERATED and INTEGER
  //                  string: for OBJECT IDENTIFIER. The string has the form "1.2.3.4..."
  //                  bool: for BOOLEAN
  //                  string: for OCTET STRING
  value interface{}
  
  // If the basictype is one of the compound types (SEQUENCE, SEQUENCE_OF, CHOICE, SET, SET_OF)
  // this contains the list of nodes within the compound. The type of the child nodes is
  // instanceNode, ofNode or fieldNode.
  children []*Tree
  
  // If basictype is BIT_STRING, INTEGER or ENUMERATED and there are named bits/ints defined
  // this map contains them. During post processing after parsing this field is filled in
  // for nodes that are defined as a non-basic type that (directly or indirectly) resolves
  // to BIT_STRING, INTEGER or ENUMERATED. So it is never necessary to follow a typename
  // reference to find a named bit/int.
  // NOTE: This does NOT included named components of OBJECT_IDENTIFIERs.
  namedints map[string]int
  
  // The complete ASN.1 source whose parsing created this node.
  src string
  
  // The character index in src of the tokens that resulted in this node.
  pos int
}

// Contains ASN.1 DEFINITIONS of types and values.
type Definitions struct {
  // The rootNode whose children are the typeDefNodes and valueDefNodes for the
  // defined types and values.
  tree *Tree
  // For quick access this maps the name of a type to its node.
  typedefs  map[string]*Tree
  // For quick access this maps the name of a value to its node.
  valuedefs map[string]*Tree
}

// An instance of an ASN.1 defined data type.
// All nodes are of type instanceNode.
// All tag fields are filled in (either from the source or the basictype).
// All non-optional fields have a non-nil value, unless they are of a compound
//     type (in which case the children array is non-empty).
// Optional fields may still be present and have a nil value.
type Instance Tree

func foo(tree *Tree) (*Definitions, error) {  
  typedefs := map[string]*Tree{}
  valuedefs := map[string]*Tree{}
  resolved := map[string]bool{}
  for _, c := range tree.children {
    if c.nodetype == typeDefNode {
      if _, exists := typedefs[c.name]; exists {
        return nil, NewParseError(c.src, c.pos, "Type '%v' redefined", c.name)
      }
      typedefs[c.name] = c
      if c.typename == "" { resolved[c.name] = true }
    } else {
      if _, exists := valuedefs[c.name]; exists {
        return nil, NewParseError(c.src, c.pos, "Value '%v' redefined", c.name)
      }
      valuedefs[c.name] = c
    }
  }
  
  newinfo := true
  for newinfo {
    newinfo = false
    for _, c := range typedefs {
      if !resolved[c.name] && resolved[c.typename] {
        d := typedefs[c.typename]
        c.basictype = d.basictype
        c.children = d.children
        c.namedints = d.namedints
        resolved[c.name] = true
        newinfo = true
      }
    }
  }
  
  for _, c := range typedefs {
    if !resolved[c.name] {
      if _, ok := typedefs[c.typename]; !ok {
        return nil, NewParseError(c.src, c.pos, "Definition of type '%v' refers to unknown type '%v'", c.name, c.typename)
      } else {
        return nil, NewParseError(c.src, c.pos, "Type definition loop '%v' -> '%v' -> ... -> '%v'", c.name, c.typename, c.name)
      }
    }
  }
  
  resolved = map[string]bool{}
  for _, v := range valuedefs {
    if v.typename != "" {
      t, ok := typedefs[v.typename]
      if !ok {
        return nil, NewParseError(v.src, v.pos, "Definition of value '%v' refers to unknown type '%v'", v.name, v.typename)
      }
      v.basictype = t.basictype
      if len(v.namedints) == 0 {
        v.namedints = t.namedints
      }
      if v.tag < 0 {
        v.tag = t.tag
        v.implicit = t.implicit
      }
    }
    
    var res bool
    var err error
    res, v.value, err = resolveValue(v)
    if err != nil {
      return nil, err
    }
    
    if res {
      resolved[v.name] = true
    }
  }

  newinfo = true
  for newinfo {
    newinfo = false
    for _, v := range valuedefs {
      if !resolved[v.name] {
        ref := strings.Fields(v.value.(string))[0]
        var w *Tree
        if resolved[ref] { 
          w = valuedefs[ref] 
        }
        
        res, err := resolveReference(v, w)
        if err != nil {
          return nil, err
        }
        
        if res {
          resolved[v.name] = true
          newinfo = true
        }
      }
    }
  }
  
  for _, v := range valuedefs {
    if !resolved[v.name] {
      if _, ok := valuedefs[v.value.(string)]; !ok {
        return nil, NewParseError(v.src, v.pos, "Definition of value '%v' refers to unknown value '%v'", v.name, v.value)
      } else {
        return nil, NewParseError(v.src, v.pos, "Value definition loop '%v' -> '%v' -> ... -> '%v'", v.name, v.value, v.name)
      }
    }
  }
    
  for _, t := range typedefs {
    err := recursiveResolve(t, typedefs, valuedefs)
    if err != nil {
      return nil, err
    }
  }
  
  return &Definitions{tree, typedefs, valuedefs}, nil
}

func resolveReference(v,w *Tree) (resolved bool, err error) {
  if v.basictype == OBJECT_IDENTIFIER {
    parts := strings.Fields(v.value.(string))
    if len(parts) == 2 && w.basictype == OBJECT_IDENTIFIER {
      v.value = w.value.(string) + "." + parts[1]
      return true, nil
    }
  } else if v.basictype == INTEGER || v.basictype == ENUMERATED {
    if len(v.namedints) > 0 {
      if i, ok := v.namedints[v.value.(string)]; ok {
        v.value = i
        return true, nil
      }
    }
  }
  
  if w == nil {
    return false, nil
  }
  
  if w.basictype != v.basictype {
    return false, NewParseError(w.src, w.pos, "Attempt to initialize value '%v' with value '%v' of incompatible type", v.name, w.name)
  }
  
  v.value = w.value
  return true, nil
}
    

func resolveValue(v *Tree) (res bool, resval interface{}, err error) {
  if tokValueName.Regex.MatchString(v.value.(string)) {
    return false, v.value, nil
  }

  switch(v.basictype) {
    case OCTET_STRING:      resval, res, err = parseString(v)
    case OBJECT_IDENTIFIER: resval, res, err = parseOID(v)
    case INTEGER:           resval, res, err = parseInt(v)
    case ENUMERATED:        resval, res, err = parseInt(v)
    case BOOLEAN:           resval, res, err = parseBool(v)
    default: return false, v.value, NewParseError(v.src, v.pos, "Unhandled case in resolveValue(): %v", v.basictype)
  }
  return res, resval, err
}

func parseString(v *Tree) (resval interface{}, resolved bool, err error) {
  str := v.value.(string)
  if !tokValueString.Regex.MatchString(str) {
    return v.value, false, NewParseError(v.src, v.pos, "Initializer for %v is not a valid %v", v.name, tokValueString.HumanReadable)
  }
  
  return str[1:len(str)-1], true, nil
}

func parseInt(v *Tree) (resval interface{}, resolved bool, err error) {
  i, err := strconv.Atoi(v.value.(string))
  if err != nil {
    return v.value, false, err
  }
  
  return i, true, nil
}

func parseBool(v *Tree) (resval interface{}, resolved bool, err error) {
  str := strings.ToLower(v.value.(string))
  if str == "true" {
    return true, true, nil
  } else if str == "false" {
    return false, true, nil
  }
  
  return v.value, false, NewParseError(v.src, v.pos, "Initializer for %v is not a valid %v", v.name, tokValueBoolean.HumanReadable)
}

var cleanupOID = regexp.MustCompile(`(`+lowerCaseIdentifier+`\s*\()|([){}])`)

func parseOID(v *Tree) (resval interface{}, resolved bool, err error) {
  str := strings.TrimSpace(cleanupOID.ReplaceAllString(v.value.(string), ""))
  parts := strings.Fields(str)
  if tokValueName.Regex.MatchString(parts[0]) {
    return parts[0]+" "+strings.Join(parts[1:], "."), false, nil
  } else {
    return strings.Join(parts, "."), true, nil
  }
}


func recursiveResolve(t *Tree, typedefs, valuedefs map[string]*Tree) error {
  if t.basictype == UNKNOWN {
    typ, ok := typedefs[t.typename]
    if !ok {
      // Note: The object has to be a field because top level type and value definitions have already been
      // resolved (or error message returned).
      return NewParseError(t.src, t.pos, "Definition of field '%v' refers to unknown type '%v'", t.name, t.typename)
    }
    
    t.basictype = typ.basictype
    t.namedints = typ.namedints
  }
  
  // resolve DEFAULT value if present
  if t.value != nil {
    var res bool
    var err error
    res, t.value, err = resolveValue(t)
    if err != nil {
      return err
    }
    
    if !res {
      ref := strings.Fields(t.value.(string))[0]
      res, err := resolveReference(t, valuedefs[ref])
      if err != nil {
        return err
      }
      
      if !res {
        return NewParseError(t.src, t.pos, "DEFAULT value of field '%v' refers to unknown value '%v'", t.name, ref)
      }
    }
  }
  
  for _, c := range t.children {
    recursiveResolve(c, typedefs, valuedefs)
  }
  
  return nil
}

func (d *Definitions) Value(name string) *Instance {return nil}

func (d *Definitions) Instantiate(typename string, data map[string]interface{}) *Instance {return nil}

func (i *Instance) DeclaredType() string {
  if i.typename != "" { return i.typename }
  return BasicTypeName[i.basictype]
}

func (i *Instance) BasicType() int {return i.basictype}

// flags:
// useIntNames => represent integer and enumerated fields as strings when they contain a named value.
// oidsAsArray => represent oids as arrays of integers (default is string of ints separated by ".")
// wrapNonObject => if the JSON representation of the type would not be enclosed in "{...}", 
//                 wrap it as "{value:...}" where ... is the ordinary representation of the instance.
// wrapAlways => implies wrapNonObject, but also applies a wrapper if the JSON encoding is already an object.
func (i *Instance) JSON(flags map[string]bool) []byte {return nil}

func (i *Instance) String() string {return ""}

func (i *Instance) DER() []byte {return nil}

func (t *Definitions) String() string {
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
      *s = append(*s, fmt.Sprintf("%v", t.value))
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
  *s = append(*s, fmt.Sprintf("%v", t.value))
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

