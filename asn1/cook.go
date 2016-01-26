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
  This file contains code for taking a data structure as produced by
  json.Unmarshal() when unmarshaling into a nil interface{}, together
  with a set of variables and functions, and inserting the variables
  and applying the functions to the data structure wherever it has
  string elements that refer to variables/functions.
  Most importantly this allows DER encoding of variables according to
  ASN.1 data structure definitions.
*/

package asn1

import "fmt"
import "strings"
import "sort"
import "unicode"
import "strconv"
import "regexp"
import "math/big"

/* An element of the stack CookStackFunc functions operate on.*/
type CookStackElement struct {
  Value interface{}
}

/* A function that modifies a stack of CookStackElements, typically by
taking elements from the top (the end of the slice), processing them
and replacing them with result elements. 
The location string should be used to prefix any error messages returned, with
no space or ":" in between. Location will end in ": " if non-empty.
*/
type CookStackFunc func(stack *[]*CookStackElement, location string) error

/*
  Takes a tree structure data, that is usually obtained by means of json.Unmarshal() and
  recursively processes it using defs, vars and funcs in the following manner:
  
  * All elements of a map[string]interface{} or []interface{} is recursively processed.
  * Strings that start with "$" are taken as programs that are executed.
    The result of the execution (which may have a different
    type than string) replaces the program string. The result will NOT be processed recursively,
    even if it is of type map[string]interface{} or []interface{}.
  * Each value that doesn't match any of the previous cases is left untouched.
  
  Programs operate on a stack that starts out empty. Each word in the program is interpreted
  from left to right and applied to the stack. A proper program leaves exactly 1 element
  on the stack at the end. That is the program's result.
  The following words may be used in a program:
  
  * Sequence of at least 3 integers separated by "." with no whitespace
    anywhere within the word. Puts a corresponding []int onto the stack. This can be used
    to initialize ANY-typed fields with OBJECT IDENTIFIERs (strings wouldn't work because
    they would put an OCTET STRING into the ANY).
  * An integer of arbitrary size. Puts a *big.Int onto the stack. This can be used to
    initialize ANY-typed fields with INTEGERs (strings wouldn't work because
    they would put an OCTET STRING into the ANY).
  * ASN.1 value name found in defs. The value is instantiated with Definitions.Value(name)
    and pushed on the stack.
  * ASN.1 type name found in defs. The top element of the stack is used to instantiate the type
    using Definitions.Instantiate(name, top) and the instance replaces the stack top.
  * Variable name found in vars[i]. vars[i][name] is pushed on the stack. The vars[i] maps
    are searched from the last (i.e. i=len(vars)-1) to the first. So they represent nested
    scopes of variables.
  * Function name found in funcs. The function is called on the stack.
  * String literal enclosed in single-quotes '...'. To include a single quote in the string,
    double it (i.e. write ''). Note that within the program '' is the empty string.
    '''' is a string consisting of only a single single-quote.
  * Key of a map entry. The value for that key will be pushed onto the stack.
    The key can be within the same map as the program being processed or any of the
    ancestor maps in the recursive map structure.
    In case multiple maps contain the same key, the closer ancestor takes precedence (and the
    map that contains the program takes precedence over all ancestors). Effectively maps
    work as new variable scopes and their keys hide entries from vars.
    Ordinarily all elements of a map are processed in lexicographic order of their keys.
    However if a program depends on a map entry that has not been processed, this
    order changes to satisfy the dependency.

  The return value is the processed data which in the case of map[string]interface{} or
  []interface{} is the same object as the original data except that the contents have
  been replaced with their processed results. If data is a string, the return value is the
  result from the program execution.
*/
func Cook(defs *Definitions, vars []map[string]interface{}, funcs map[string]CookStackFunc, data interface{}) (interface{}, error) {
  return cook(defs, vars, funcs, data)
}

type cookStruct struct {
  order []string // the keys of the children map in the order in which they should be processed
  children map[string]*cookStruct // if the type of data is []interface{}, the key is a 4 byte big endian integer array index
  status int // 0: not looked at, yet; 1: done; -1: partially done
  data interface{}
}

func cook(defs *Definitions, vars []map[string]interface{}, funcs map[string]CookStackFunc, data interface{}) (interface{}, error) {
  top := &cookStruct{order:[]string{""}, children:map[string]*cookStruct{"":&cookStruct{data:data}}, status:-1, data:map[string]interface{}{"":data}}
  current := top
  
  // NOTE: path has one element more than scopes because path always ends in
  // the name of the child currently looked at whereas scopes ends in the scope
  // that child is in
  path := []string{}
  scopes := []*cookStruct{}
  
  for {
    done := true
    path = append(path, "")
    for _, name := range current.order {
      path[len(path)-1] = name
      child := current.children[name]
      if child.status == 0 { // not visited yet
        result, err := fillIn(child, defs, vars, scopes, funcs, path)
        if err != nil { return data, err }
        if result > 0 { // replace child
          switch dat := current.data.(type) {
            case map[string]interface{}: dat[name] = child.data
            case []interface{}: dat[(name[0] << 24) + (name[1] << 16) + (name[2] << 8) + name[3]] = child.data
            default: panic("Unhandled case in cook()")
          }
        } else if result < 0 { // tree has been rearranged => start over from top
          current = top
          path = path[0:0]
          scopes = scopes[0:0]
          done = false
          break
        }
      }
      
      if child.status == -1 { // child has been expanded but has unhandled children => step into child
        current = child
        scopes = append(scopes, child)
        done = false
        break
      }
    }
    
    if done {
      if current == top { return top.data.(map[string]interface{})[""], nil }
      current.status = 1
      current = top // => start over from top
      path = path[0:0]
      scopes = scopes[0:0]
    }
  }
}

func fillIn(c *cookStruct, defs *Definitions, vars []map[string]interface{}, scopes []*cookStruct, funcs map[string]CookStackFunc, path []string) (int, error) {
  switch data := c.data.(type) {
    case map[string]interface{}:
      c.children = map[string]*cookStruct{}
      for name, d := range data {
        c.order = append(c.order, name)
        c.children[name] = &cookStruct{data:d}
      }
      c.status = -1
      sort.Strings(c.order)
      return 0, nil
    case []interface{}:
      c.children = map[string]*cookStruct{}
      for i, d := range data {
        name := string([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
        c.order = append(c.order, name)
        c.children[name] = &cookStruct{data:d}
      }
      c.status = -1
      // no need to sort c.order because its already sorted
      return 0, nil
    case string:
      new_child, err := exec_program(defs, vars, scopes, funcs, data, path)
      if err != nil {
        if err == errReordered {
          return -1, nil
        }
        return 0, err
      }
      c.status = 1
      c.data = new_child
      return 1, nil
    default:
      c.status = 1
      return 0, nil
  }
}

// modified from strings.go:FieldsFunc()
func fieldsWithStrings(s string) []string {
  n := 0
  inField := false
  inString := false
  for _, rune := range s {
    if rune == '\'' { inString = !inString }
    wasInField := inField
    inField = inString || !unicode.IsSpace(rune)
    if inField && !wasInField {
      n++
    }
  }
  a := make([]string, n)
  na := 0
  fieldStart := -1 // Set to -1 when looking for start of field.
  inString = false
  for i, rune := range s {
    if rune == '\'' { inString = !inString }
    if !inString && unicode.IsSpace(rune) {
      if fieldStart >= 0 {
        a[na] = s[fieldStart:i]
        na++
        fieldStart = -1
      }
    } else if fieldStart == -1 {
      fieldStart = i
    }
  }
  if fieldStart >= 0 { // Last field might end at EOF.
    a[na] = s[fieldStart:]
  }
  return a
}

// only allow up to 9 digits per component to make sure every component can be converted to int
var integerSequence = regexp.MustCompile("^[0-9]{1,9}([.][0-9]{1,9}){2,}$")

var integer = regexp.MustCompile("^[+-]?[0-9]+$")

var errReordered = fmt.Errorf("Reordered => Reset")

func path2Location(path []string) string {
  s := []string{}
  for _, p := range path {
    if len(p) > 0 && p[0] == 0 { // we simply assume all indexes are < 16 million, so the first byte is 0
      i := (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])
      s = append(s, fmt.Sprintf("[%d]", i))
    } else {
      s = append(s, p)
    }
  }
  
  res := strings.Join(s,"/")
  if res != "" { res = res + ": " }
  return res
}

func exec_program(defs *Definitions, vars []map[string]interface{}, scopes []*cookStruct, funcs map[string]CookStackFunc, program string, path []string) (interface{}, error) {
  if len(program) == 0 || program[0] != '$' { return program, nil }
  
  fields := fieldsWithStrings(program[1:])
  
  /* Check dependencies to other fields that have not been processed yet */
  for _, f := range fields {
    _, is_func := funcs[f]
    if f[0] == '\'' {
    } else if is_func {
    } else if defs.HasType(f) {
    } else if defs.HasValue(f) {
    } else if integerSequence.MatchString(f) {
    } else if integer.MatchString(f) {
    } else {
      i := len(scopes)-1
      for ; i >= 0; i-- {
        if c, found := scopes[i].children[f]; found { 
          if c.status < 0 { // partially evaluated
            return nil, fmt.Errorf("%vCannot reorder elements to satisfy dependency on field \"%v\"", path2Location(path), f)
          } else if c.status == 0 { // not evaluated yet
            myname := path[i+1] // path[i] is the name of the scope, path[i+1] is the name of the entry within the scope
            a := -1
            b := -1
            for k := range scopes[i].order {
              if scopes[i].order[k] == f { b = k }
              if scopes[i].order[k] == myname { a = k }
            } 
            // prevent infinite loops
            if f <= myname {
              return nil, fmt.Errorf("%vCircular dependendy on field \"%v\"", path2Location(path), f)
            }
            
            if a < 0 || b < 0 || a >= b { panic("Something happened in exec_program() that's not supposed to be possible!") }
            
            // reorder
            for k := b; k > a; k-- {
              scopes[i].order[k] = scopes[i].order[k-1]
            }
            scopes[i].order[a] = f
            return nil, errReordered
          } else {
            break
          }
        }
      }
    }
  }
  
  stack := []*CookStackElement{}
  for _, f := range fields {
    fun, is_func := funcs[f]
    if f[0] == '\'' {
      if len(f) < 2 || f[len(f)-1] != '\'' {
        return nil, fmt.Errorf("%vUnterminated string constant: %v", path2Location(path), f)
      }
      stack = append(stack, &CookStackElement{Value:strings.Replace(f[1:len(f)-1],"''", "'", -1)})
    } else if is_func {
      err := fun(&stack, path2Location(path))
      if err != nil {
        return nil, err
      }
    } else if defs.HasType(f) {
      if len(stack) == 0 {
        return nil, fmt.Errorf("%vAttempt to instantiate type \"%v\" from empty stack", path2Location(path), f)
      }
      top := stack[len(stack)-1].Value
      stack = stack[:len(stack)-1]
      inst, err := defs.Instantiate(f, top)
      if err != nil {
        return nil, fmt.Errorf("%v%v", path2Location(path), err)
      }
      stack = append(stack, &CookStackElement{Value:inst})
    } else if defs.HasValue(f) {
      inst, _ := defs.Value(f) // no error possible because we checked with HasValue()
      stack = append(stack, &CookStackElement{Value:inst}) 
    } else if integerSequence.MatchString(f) {
      parts := strings.Split(f,".")
      oid := make([]int, len(parts))
      for i := range parts {
        // no error possible because regex enforces that result is in range for int
        oid[i],_ = strconv.Atoi(parts[i])
      }
      stack = append(stack, &CookStackElement{Value:oid})
    } else if integer.MatchString(f) {
      var b big.Int
      _, success := b.SetString(f, 10)
      if !success {
        return nil, fmt.Errorf("%vError parsing INTEGER: %v", path2Location(path), f)
      }
      stack = append(stack, &CookStackElement{Value:&b})
    } else {
      i := len(scopes)-1
      for ; i >= 0; i-- {
        if c, found := scopes[i].children[f]; found && c.status == 1 { 
          stack = append(stack, &CookStackElement{Value:c.data})
          break
        }
      }
      if i < 0 {
        i = len(vars)-1
        for ; i >= 0; i-- {
          if _, found := vars[i][f]; found { 
            stack = append(stack, &CookStackElement{Value:vars[i][f]})
            break 
          }
        }
        if i < 0 {
          return nil, fmt.Errorf("%vWord is not a known function, variable, type or constant: %v", path2Location(path), f)
        }
      }
    }
  }
  
  if len(stack) == 0 {
    return nil, fmt.Errorf("%vNo result value from program \"%v\"", path2Location(path), program)
  }
  if len(stack) > 1 {
    return nil, fmt.Errorf("%v%v elements left on stack after program \"%v\"", path2Location(path), len(stack), program)
  }
  
  return stack[0].Value, nil
}


