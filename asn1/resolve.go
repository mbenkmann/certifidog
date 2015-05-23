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

func foo(tree *Tree,valuedefs, typedefs map[string]*Tree, resolved map[string]bool) (*Definitions, error) {
  for _, v := range valuedefs {
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

  newinfo := true
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

