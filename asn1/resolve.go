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
  ASN.1 definitions may contain forward and backward references.
  After parsing, these need to be resolved. This file contains the code
  for doing this. It is called from parse.go:Parse().
*/

package asn1

import (
         "os"
         "fmt"
         "regexp" 
         "strings"
         "strconv"
)

// Fills in d.valuedefs and d.typedefs maps for quick access via type/value name.
func (d *Definitions) makeIndex() error {  
  for _, c := range d.tree.children {
    if c.nodetype == typeDefNode {
      if _, exists := d.typedefs[c.name]; exists {
        return NewParseError(c.src, c.pos, "Type '%v' redefined (%v: earlier definition is here)", c.name, lineCol(d.typedefs[c.name].src, d.typedefs[c.name].pos))
      }
      if Debug {
        fmt.Fprintf(os.Stderr, "%v: TYPE %v\n", lineCol(c.src, c.pos), c.name)
      }
      d.typedefs[c.name] = c
    } else {
      if _, exists := d.valuedefs[c.name]; exists {
        return NewParseError(c.src, c.pos, "Value '%v' redefined (%v: earlier definition is here)", c.name, lineCol(d.valuedefs[c.name].src, d.valuedefs[c.name].pos))
      }
      if Debug {
        fmt.Fprintf(os.Stderr, "%v: VALUE %v\n", lineCol(c.src, c.pos), c.name)
      }
      d.valuedefs[c.name] = c
    }
  }
  
  return nil
}

var universalTypes = []*Tree{
&Tree{nodetype:typeDefNode, tag:12, implicit:true, name:"UTF8String", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:18, implicit:true, name:"NumericString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:19, implicit:true, name:"PrintableString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:20, implicit:true, name:"TeletexString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:20, implicit:true, name:"T61String", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:21, implicit:true, name:"VideotexString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:22, implicit:true, name:"IA5String", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:23, implicit:true, name:"UTCTime", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:24, implicit:true, name:"GeneralizedTime", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:25, implicit:true, name:"GraphicString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:26, implicit:true, name:"VisibleString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:26, implicit:true, name:"ISO646String", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:27, implicit:true, name:"GeneralString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:28, implicit:true, name:"UniversalString", basictype: OCTET_STRING},
&Tree{nodetype:typeDefNode, tag:30, implicit:true, name:"BMPString", basictype: OCTET_STRING},
}

// Adds standard UNIVERSAL types, unless they are already defined.
func (d *Definitions) addUniversalTypes(src string, pos int)  {
  for _, t := range universalTypes {
    if _, exists := d.typedefs[t.name]; !exists {
      if Debug {
        s := []string{"STANDARD "}
        stringTypeDefinition(&s, t)
        fmt.Fprintf(os.Stderr, "%v: %v\n", lineCol(src, pos), strings.Join(s,""))
      }
      d.typedefs[t.name] = t
    }
  }
}

// After this, typeDefNodes are fully resolved, i.e. their basictype, children and namedints fields
// are copied over from the resolved type. 
// NOTE: children of typeDefNodes (i.e. ofNodes and fieldNodes) are not yet resolved.
func (d *Definitions) resolveTypes() error {  
  resolved := map[string]bool{}
  for _, c := range d.typedefs {
    if c.typename == "" { 
      resolved[c.name] = true
      if Debug {
        fmt.Fprintf(os.Stderr, "%v: BASIC %v\n", lineCol(c.src, c.pos), c.name)
      }
    }
  }
  
  newinfo := true
  for newinfo {
    newinfo = false
    for _, c := range d.typedefs {
      if !resolved[c.name] && resolved[c.typename] {
        t := d.typedefs[c.typename]
        c.basictype = t.basictype
        c.children = t.children
        c.namedints = t.namedints
        resolved[c.name] = true
        newinfo = true
        if Debug {
          fmt.Fprintf(os.Stderr, "%v: RESOLVED %v -> %v\n", lineCol(c.src, c.pos), c.name, t.name)
        }
      }
    }
  }
  
  for _, c := range d.typedefs {
    if !resolved[c.name] {
      if _, ok := d.typedefs[c.typename]; !ok {
        return NewParseError(c.src, c.pos, "Definition of type '%v' refers to unknown type '%v'", c.name, c.typename)
      }
    }
  }
  
  // NOTE: THE FOLLOWING LOOP CAN NOT BE MERGED WITH THE PRECEDING LOOP, BECAUSE
  // WE NEED TO DIAGNOSE UNKNOWN TYPE ERRORS FIRST, OR WE MAY PRODUCE INCORRECT ERRORS
  // ABOUT DEFINITION LOOPS!
  for _, c := range d.typedefs {
    if !resolved[c.name] {
      return NewParseError(c.src, c.pos, "Type definition loop '%v' -> '%v' -> ... -> '%v'", c.name, c.typename, c.name)
    }
  }

  return nil 
}

// After this, the type information of valueDefNodes is fully resolved, 
// i.e. their basictype, children and namedints fields are copied over from the resolved type.
func (d *Definitions) resolveValueTypes() error {  
  for _, v := range d.valuedefs {
    if v.typename != "" {
      t, ok := d.typedefs[v.typename]
      if !ok {
        return NewParseError(v.src, v.pos, "Definition of value '%v' refers to unknown type '%v'", v.name, v.typename)
      }
      v.basictype = t.basictype
      if len(v.namedints) == 0 {
        v.namedints = t.namedints
      }
      if v.tag < 0 {
        v.tag = t.tag
        v.implicit = t.implicit
      }
      if Debug {
        fmt.Fprintf(os.Stderr, "%v: RESOLVED %v -> %v\n", lineCol(v.src, v.pos), v.name, BasicTypeName[v.basictype])
      }
    } else if Debug {
      fmt.Fprintf(os.Stderr, "%v: BASIC %v\n", lineCol(v.src, v.pos), v.name)
    }
  } 
  
  return nil
}

func unknownValueReference(v *Tree, unk string) error {
  what := "value"
  if v.nodetype != valueDefNode {
    what = "DEFAULT value of field"
  }
  return NewParseError(v.src, v.pos, "Definition of %v '%v' references unknown value '%v'", what, v.name, unk)
}

func invalidInitializer(v *Tree, typ string) error {
  what := "value"
  if v.nodetype != valueDefNode {
    what = "DEFAULT value of field"
  }
  return NewParseError(v.src, v.pos, "Initializer for %v '%v' is not a valid %v", what, v.name, typ)
}

var cleanupOID = regexp.MustCompile(`(`+lowerCaseIdentifier+`\s*\()|([){}])`)

// Parses v.value (a string) according to v.basictype (the necessity to know
// the basictype is the reason why this is not done during the main recursive
// descent parser run). v.value is replaced with the parsed value of the
// appropriate type (e.g. int for basictype==INTEGER).
// References to v.namedints are resolved.
// References to other values are NOT resolved, but are pre-processed in
// the following manner:
//   for everything that's NOT of type OBJECT IDENTIFIER:
//      the value is set to a *Tree that points to the referenced valueDefNode
//   for OBJECT IDENTIFIER:
//      the value is set to a []interface{} with 1 or 2 elements. The first
//      element is a *Tree that points to the referenced valueDefNode.
//      The 2nd element is a []int that contains the suffix of the OID
//      if present. E.g. "{ foo 1 2 3 }" becomes [valuedefs["foo"], [1,2,3]]
//                       "{ foo }" or just "foo" becomes  [valuedefs["foo"]]
//   NOTE: TYPE CHECKING IS NOT PERFORMED ON THE REFERENCED valueDefNode, i.e.
//         IT MAY NOT BE COMPATIBLE WITH v's TYPE.
func (d *Definitions) parseValue(v *Tree) error {
  val, unresolved := v.value.(string)
  if !unresolved { 
    return nil
  }
  
  // If the value is a reference to another value or named int
  if tokValueReference.Regex.MatchString(val) {
    if i, found := v.namedints[val]; found {
      v.value = i
      return nil
    }
    
    if ref_v, found := d.valuedefs[val]; found {
      if v.basictype == OBJECT_IDENTIFIER {
        v.value = []interface{}{ref_v}
      } else {
        v.value = ref_v
      }
      return nil
    }
    
    return unknownValueReference(v, val)
  }

  switch(v.basictype) {
    case OCTET_STRING:
          if !tokValueString.Regex.MatchString(val) {
            return invalidInitializer(v, tokValueString.HumanReadable)
          }
          v.value = []byte(val[1:len(val)-1]) // cut off quotes around string literal
         
    case INTEGER, ENUMERATED:
          i, err := strconv.Atoi(val)
          if err != nil {
            return invalidInitializer(v, tokValueInteger.HumanReadable)
          }
          v.value = i

    case BOOLEAN:
          val = strings.ToLower(val)
          if val == "true" {
            v.value = true
          } else if val == "false" {
            v.value = false
          } else {
            return invalidInitializer(v, tokValueBoolean.HumanReadable)
          }
    
    case OBJECT_IDENTIFIER:
          val = strings.TrimSpace(cleanupOID.ReplaceAllString(val, ""))
          parts := strings.Fields(val)
        
          var oida []interface{}
        
          if tokValueReference.Regex.MatchString(parts[0]) {
            if ref_v, found := d.valuedefs[parts[0]]; found {
              oida = append(oida, ref_v)
            } else {
              return unknownValueReference(v, parts[0])
            }
          }
          
          oidsuffix := []int{}
          for p:=len(oida); p < len(parts); p++ {
            if tokValueReference.Regex.MatchString(parts[p]) {
              return NewParseError(v.src, v.pos, "Only the first component of an OBJECT IDENTIFIER definition may be a reference to another value")
            }
            i, err := strconv.Atoi(parts[p])
            if err != nil || i < 0 {
              return invalidInitializer(v, tokValueOID.HumanReadable)
            }
            oidsuffix = append(oidsuffix, i)
          }

          if len(oida) == 0 {
            v.value = oidsuffix
          } else {
            if len(parts) > 1 {
              oida = append(oida, oidsuffix)
            }
            v.value = oida
          }
    
    default: 
          return NewParseError(v.src, v.pos, "Literals of type %v are not supported", BasicTypeName[v.basictype])
  }
  
  return nil
}

// After this, all valueDefNodes whose value is a reference to another valueDefNode
// are resolved to the final value.
func (d *Definitions) resolveValues() error {
  newinfo := true
  for newinfo {
    newinfo = false
    for _, v := range d.valuedefs {
      newly_resolved, err := resolveValue(v)
      if err != nil {
        return err
      }
      newinfo = newinfo || newly_resolved
    }
  }
  
  for _, v := range d.valuedefs {
    ref1, unresolved1 := v.value.(*Tree)
    ref2, unresolved2 := v.value.([]interface{})
    if unresolved1 || unresolved2 {
      var ref *Tree
      if unresolved1 { ref = ref1 } else { ref = ref2[0].(*Tree) }
      return NewParseError(v.src, v.pos, "Value definition loop '%v' -> '%v' -> ... -> '%v'", v.name, ref.name, v.name)
    }
  }
  
  return nil
}

func resolveValue(v *Tree) (bool, error) {
  ref1, unresolved1 := v.value.(*Tree)
  ref2, unresolved2 := v.value.([]interface{})
  
  if !(unresolved1 || unresolved2) { return false, nil }
  
  var ref *Tree
  if unresolved1 { ref = ref1 } else { ref = ref2[0].(*Tree) }
  
  _, unresolved1 = ref.value.(*Tree)
  _, unresolved2 = ref.value.([]interface{})
  
  if unresolved1 || unresolved2 { return false, nil }
  
  if Debug {
    fmt.Fprintf(os.Stderr, "%v: Resolving %v -> %v\n", lineCol(v.src, v.pos), v.name, ref.name)
  }
  
  err := resolveReference(v, ref)
  if err != nil {
    return false, err
  }
  
  if Debug {
    s := []string{}
    stringValue(&s, v)
    fmt.Fprintf(os.Stderr, "%v: %v %v -> %v\n", lineCol(v.src, v.pos), v.name, BasicTypeName[v.basictype], strings.Join(s,""))
  }
  
  return true, nil
}

func resolveReference(v,w *Tree) error {
  if w.basictype != v.basictype {
    if v.nodetype == fieldNode {
      return NewParseError(v.src, v.pos, "Cannot use value '%v' as DEFAULT for field '%v' because it has an incompatible type", w.name, v.name)
    } else {
      return NewParseError(v.src, v.pos, "Attempt to initialize value '%v' with value '%v' of incompatible type", v.name, w.name)
    }
  }
  
  if v.basictype == OBJECT_IDENTIFIER {
    parts := v.value.([]interface{})
    if len(parts) == 2 {
      v.value = append([]int{}, w.value.([]int)...)
      v.value = append(v.value.([]int), parts[1].([]int)...)
      return nil
    }
  } 
  
  v.value = w.value
  return nil
}

// Given a typeDefNode t, this (recursively) resolves the children (if any),
// regarding types as well as (DEFAULT) values. The resolution applies to namedints
// and basictype, but NOT the children, because of the possibility of recursive
// data structures.
func (d *Definitions) resolveFields(t *Tree) error {
  if t.typename != "" {
    typ, ok := d.typedefs[t.typename]
    if !ok {
      if t.nodetype == ofNode {
        return NewParseError(t.src, t.pos, "SEQUENCE/SET OF unknown type '%v'", t.typename)
      } else {
        return NewParseError(t.src, t.pos, "Definition of field '%v' refers to unknown type '%v'", t.name, t.typename)
      }
    }
    
    t.basictype = typ.basictype
    t.namedints = typ.namedints
    // do NOT t.children = typ.children (see func comment above)
  }
  
  // resolve DEFAULT value if present
  if t.value != nil {
    err := d.parseValue(t)
    if err != nil {
      return err
    }
    
    _, err = resolveValue(t)
    if err != nil {
      return err
    }
  }
  
  for _, c := range t.children {
    err := d.resolveFields(c)
    if err != nil {
      return err
    }
  }
  
  return nil
}

