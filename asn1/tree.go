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

import "os"
import "fmt"
import "regexp"

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
  NULL
  ANY
)

// Maps basic type integer constants to default tags.
var BasicTypeTag = map[int]int{
  SEQUENCE: 16,
  SEQUENCE_OF: 16,
  SET_OF: 17,
  SET: 17,
  OCTET_STRING: 4,
  BIT_STRING: 3,
  OBJECT_IDENTIFIER: 6,
  INTEGER: 2,
  ENUMERATED: 10,
  BOOLEAN: 1,
  NULL: 5,
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

// The main data structure to store both ASN.1 definitions (type and value) as well as
// instances of such definitions.
type Tree struct {
  // See the constants above (rootNode, typeDefNode,...)
  nodetype int
  
  // The DER encoding of the ASN.1 tag(s) of the node. This list may be empty
  // in the case of CHOICE.
  // During resolve phase, this is filled in with the basic type tags for all
  // nodes that do not have a tag declared in the source.
  // Each tag is followed by a 0 byte as placeholder for the length (and
  // to easily separate the tags without having to parse them). During
  // DER-encoding the length will be filled in (together with additional bytes
  // if the 1 byte is not enough).
  tags []byte
  
  // The tag the node has in the ASN.1 source, or -1 if there is none.
  // The tag includes the class bits 7 and 8. This means that the tag must be in the
  // range 0..63.
  // This field is only used to be able to produce string output that matches
  // the input from which the node was parsed. For DER-encoding, the tags field
  // above is used.
  source_tag int
  
  // True if the node is declared with an IMPLICIT tag or inherits the IMPLICIT from
  // DEFINITIONS. This is only used for producing string output that matches
  // the input. The effect of the IMPLICIT is already contained in the tags field.
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
  // to be instantiated (except for typeDefNodes which are inlined after parsing).
  // Recursive definitions are possible and even useful when fields are marked optional.
  // This is why custom type references are not inlined at parse time (except for typeDefNodes)
  // and left as typename references until instantiation.
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
  //
  // NOTE ON Go TYPE: During parsing of the ASN.1 source this is always a
  //                  string.
  //                  
  //                  In the post-processing step when references to named values
  //                  are resolved, this is replaced by one of the following types:
  //                  int: for ENUMERATED and INTEGER
  //                  *big.Int: for very large INTEGERs (not supported for ENUMERATED)
  //                  []int: for OBJECT IDENTIFIER.
  //                  bool: for BOOLEAN
  //                  []byte: for OCTET STRING
  //                  []bool: for BIT STRING
  //                  nil: for NULL
  //
  //                  temporarily between post-processing phases the following
  //                  types are also used
  //                  *Tree: a semi-resolved reference to a named value
  //                  []interface{}: a semi-resolved OBJECT IDENTIFIER.
  //                                 Element [0] is a *Tree
  //                                 Element [1] (if present) is a []int
  value interface{}
  
  // For instanceNodes this is true if the node is instantiated from a fieldNode that
  // is optional and has a DEFAULT value and the value of the instance is equal to
  // the DEFAULT value. Note that this applies no matter if the value has been manually
  // set in the instance or has been set to DEFAULT through omission. 
  isDefaultValue bool
  
  // This is only set for an instanceNode that is the result of instantiating an ANY.
  // This flag is necessary because when an ANY is instantiated, the resulting instanceNode
  // has the basictype of whatever was used to instantiate the ANY. The information that
  // an ANY was involved would be lost. Normally that information is not relevant.
  // However when producing JSON output for an *Instance, fields that are typed ANY in the
  // ASN.1 definition need to be output with type information. E.g. the untyped 
  // string "1.2.3.4" is fine when used for a field of type OBJECT IDENTIFIER. But when
  // used for a field of type ANY, the JSON needs to be something like
  // "$'1.2.3.4' OBJECT IDENTIFIER".
  isAny bool
  
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
  // For quick access this maps the name of a type to its node. The map may have
  // entries that are not part of this.tree but are imported from elsewhere.
  typedefs  map[string]*Tree
  // For quick access this maps the name of a value to its node. The map may have
  // entries that are not part of this.tree but are imported from elsewhere.
  valuedefs map[string]*Tree
}

// Returns the names of all values that are defined.
func (defs *Definitions) ValueNames() []string {
  names := make([]string, 0, len(defs.valuedefs))
  for n := range defs.valuedefs {
    names = append(names, n)
  }
  return names
}

// Returns an OIDNames map for all values of type OBJECT IDENTIFIER that are
// defined.
func (defs* Definitions) OIDNames() OIDNames {
  o := OIDNames{}
  for n, v := range defs.valuedefs {
    if v.basictype == OBJECT_IDENTIFIER {
      elems := v.value.([]int)
      oid := fmt.Sprintf("%d", elems[0])
      for _, i := range elems[1:] {
        oid = fmt.Sprintf("%v.%d", oid, i)
      }
      if o[oid] == "" || len(n) < len(o[oid]) {
        o[oid] = n
      }
    }
  }
  return o
}

var id_Foo_bar_wusel = regexp.MustCompile(`^id-([A-Z][a-zA-Z0-9]*)-([a-z][a-zA-Z0-9]*)-.*$`)


// For all defined values of type OBJECT IDENTIFIER with name like
// "id-Foo-bar-wusel", if "Foo" is a defined SEQUENCE or SET type and
// type "Foo" has a field named "bar", if there exists a type alias
// named "Foo-bar-wusel", then an entry will be created in the
// returned DERinDER map that maps from "Foo" -> "bar" -> oid -> fun
// where oid is the value of id-Foo-bar-wusel and fun is a function to
// decode DER-encoded data in field bar that is of type Foo-bar-wusel
// (actually using the aliased name).
func (defs* Definitions) DERinDER() DERinDER {
  derInDER := DERinDER{}
  for n, v := range defs.valuedefs {
    if v.basictype == OBJECT_IDENTIFIER {
      s := id_Foo_bar_wusel.FindStringSubmatch(n)
      if s != nil {
        typename := s[1]
        fieldname := s[2]
        aliasname := s[0][3:]
        if t := defs.typedefs[typename]; t != nil {
          if t.basictype == SEQUENCE || t.basictype == SET {
            for _, c := range t.children {
              if c.name == fieldname {
                if t2 := defs.typedefs[aliasname]; t2 != nil {
                  if aliased_name := t2.typename; aliased_name != "" {
                    elems := v.value.([]int)
                    oid := fmt.Sprintf("%d", elems[0])
                    for _, i := range elems[1:] {
                      oid = fmt.Sprintf("%v.%d", oid, i)
                    }
                    if derInDER[typename] == nil {
                      derInDER[typename] = map[string]map[string]func([]byte)*Instance{}
                    }
                    if derInDER[typename][fieldname] == nil {
                      derInDER[typename][fieldname] = map[string]func([]byte)*Instance{}
                    }
                    if Debug {
                      fmt.Fprintf(os.Stderr, "DERinDER: %v -> %v -> %v -> %v\n", typename, fieldname, oid, aliased_name)
                    }
                    derInDER[typename][fieldname][oid] = func(data []byte)*Instance{
                      unmarshaled := UnmarshalDER(data, 0)
                      if unmarshaled != nil {
                        for _, unm := range unmarshaled.Data {
                          output, err := defs.Instantiate(aliased_name, unm)
                          if err == nil {
                            return output
                          } else if Debug {
                            fmt.Fprintf(os.Stderr, "DERinDER: Failed to interpret %v bytes as %v: %v\n", len(data), aliased_name, err)
                          }
                          break // only test the first entry; the 2nd will just be an alias for the first
                        }
                      }
                      return nil
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return derInDER
}



// Returns true iff type name is defined.
func (defs *Definitions) HasType(name string) bool {
  _, have_type := defs.typedefs[name]
  return have_type
}

// Returns true iff value name is defined.
func (defs *Definitions) HasValue(name string) bool {
  _, have_val := defs.valuedefs[name]
  return have_val
}

// An instance of an ASN.1 defined data type.
// All nodes are of type instanceNode.
// All tag fields are filled in (either from the source or the basictype).
// All non-optional fields have a non-nil value, unless they are of a compound
//     type (in which case the children array is non-empty).
// Optional fields may still be present and have a nil value.
type Instance Tree

// Returns the name ASN.1 type of this instance. This may be either a user-defined
// type or one of the basic types such as "INTEGER". If it is a basic type that
// includes a space in its standard name, such as "OCTET STRING", the space
// will be replaced with "_", so that the returned string never contains spaces.
func (i *Instance) Type() string {
  return typeName((*Tree)(i))
}
