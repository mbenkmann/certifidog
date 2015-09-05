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
  * Key of a map entry that has already been processed. The value for that key will be pushed
    onto the stack. Map keys are processed in alphabetical order. The key can be within the
    same map as the program being processed or any of the ancestor maps on the recursion path.
    In case multiple maps contain the same key, the closer ancestor takes precedence (and the
    map that contains the program takes precedence over all ancestors). Effectively maps
    work as new variable scopes and their keys hide entries from vars.

  The return value is the processed data which in the case of map[string]interface{} or
  []interface{} is the same object as the original data except that the contents have
  been replaced with their processed results. If data is a string, the return value is the
  result from the program execution.
*/
func Cook(defs *Definitions, vars []map[string]interface{}, funcs map[string]CookStackFunc, data interface{}) (interface{}, error) {
  return cook(defs, vars, funcs, data, &pathNode{})
}

type UncookParameters struct {
}

/*
  Takes an *Instance and returns a data structure that corresponds to it but consists
  only of basic Go types. E.g. a SEQUENCE will be represented as map[string]interface{}.
  The result is comparable to what you get from json.Unmarshal() into a nil interface{}.
  The params control several aspects of the conversion, such as whether INTEGER values
  that have a corresponding name should be represented as the number or the name.
*/
func Uncook(defs *Definitions, params *UncookParameters, inst* Instance) interface{} {
return nil
}

func cook(defs *Definitions, vars []map[string]interface{}, funcs map[string]CookStackFunc, data interface{}, p *pathNode) (interface{}, error) {
  switch data := data.(type) {
    case map[string]interface{}:
      newvars := make([]map[string]interface{}, len(vars)+1)
      copy(newvars, vars)
      newvars[len(newvars)-1] = make(map[string]interface{})
      keys := make([]string,0,len(data))
      for key := range data { keys = append(keys, key) }
      sort.Strings(keys)
      for _, key := range keys {
        d, err := cook(defs, newvars, funcs, data[key], &pathNode{parent:p, name:"/"+key})
        if err != nil {
          return data, err
        }
        data[key] = d
        newvars[len(newvars)-1][key] = d
      }
    case []interface{}:
      for i := range data {
        d, err := cook(defs, vars, funcs, data[i], &pathNode{parent:p, name:fmt.Sprintf("[%d]", i)})
        if err != nil {
          return data, err
        }
        data[i] = d
      }
    case string:
      return exec_program(defs, vars, funcs, data, p.String())
  }
  
  return data, nil
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


func exec_program(defs *Definitions, vars []map[string]interface{}, funcs map[string]CookStackFunc, program string, location string) (interface{}, error) {
  if len(program) == 0 || program[0] != '$' { return program, nil }
  
  fields := fieldsWithStrings(program[1:])
  
  stack := []*CookStackElement{}
  for _, f := range fields {
    fun, is_func := funcs[f]
    if f[0] == '\'' {
      if len(f) < 2 || f[len(f)-1] != '\'' {
        return nil, fmt.Errorf("%vUnterminated string constant: %v", location, f)
      }
      stack = append(stack, &CookStackElement{Value:strings.Replace(f[1:len(f)-1],"''", "'", -1)})
    } else if is_func {
      err := fun(&stack, location)
      if err != nil {
        return nil, err
      }
    } else if defs.HasType(f) {
      if len(stack) == 0 {
        return nil, fmt.Errorf("%vAttempt to instantiate type \"%v\" from empty stack", location, f)
      }
      top := stack[len(stack)-1].Value
      stack = stack[:len(stack)-1]
      inst, err := defs.Instantiate(f, top)
      if err != nil {
        return nil, fmt.Errorf("%v%v", location, err)
      }
      stack = append(stack, &CookStackElement{Value:inst})
    } else if defs.HasValue(f) {
      inst, _ := defs.Value(f) // no error possible because we checked with HasValue()
      stack = append(stack, &CookStackElement{Value:inst}) 
    } else {
      i := len(vars)-1
      for ; i >= 0; i-- {
        if _, found := vars[i][f]; found { break }
      }
      if i < 0 {
        return nil, fmt.Errorf("%vWord is not a known function, variable, type or constant: %v", location, f)
      }
      stack = append(stack, &CookStackElement{Value:vars[i][f]})
    }
  }
  
  if len(stack) == 0 {
    return nil, fmt.Errorf("%vNo result value from program \"%v\"", location, program)
  }
  if len(stack) > 1 {
    return nil, fmt.Errorf("%v%v elements left on stack after program \"%v\"", location, len(stack), program)
  }
  
  return stack[0].Value, nil
}


