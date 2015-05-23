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
  // NOTE: For typeDefNodes with typename != "" this is fully resolved. For other types
  // of nodes, the typename reference has to be following when instantiating.
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

func (d *Definitions) Value(name string) *Instance {return nil}

func (d *Definitions) Instantiate(typename string, data map[string]interface{}) *Instance {return nil}

// flags:
// useIntNames => represent integer and enumerated fields as strings when they contain a named value.
// oidsAsArray => represent oids as arrays of integers (default is string of ints separated by ".")
// wrapNonObject => if the JSON representation of the type would not be enclosed in "{...}", 
//                 wrap it as "{value:...}" where ... is the ordinary representation of the instance.
// wrapAlways => implies wrapNonObject, but also applies a wrapper if the JSON encoding is already an object.
func (i *Instance) JSON(flags map[string]bool) []byte {return nil}

func (i *Instance) String() string {return ""}

func (i *Instance) DER() []byte {return nil}

