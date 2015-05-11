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
         "os"
         "fmt"
         "regexp"
         "strings"
         "strconv"
         "unicode"
)

var Debug = false

type parseFunction func(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error)

type token struct {
  Regex *regexp.Regexp
  HumanReadable string
  Parser parseFunction
}

var tokComment = &token{
  regexp.MustCompile("^--.*?(--|\n)"),
  "-- Comment",
  parseSkip,
}

var tokDEFINITIONS = &token{
  regexp.MustCompile(`^DEFINITIONS\b`),
  "DEFINITIONS",
  parseDEFINITIONS,
}

var tokIMPLICITTAGS = &token{
  regexp.MustCompile(`^IMPLICIT\s+TAGS\b`),
  "IMPLICIT TAGS",
  parseIMPLICITTAGS,
}

var tokEXPLICITTAGS = &token{
  regexp.MustCompile(`^EXPLICIT\s+TAGS\b`),
  "EXPLICIT TAGS",
  parseEXPLICITTAGS,
}

func tokCoCoEq(nextState *state) (*token) {
  return &token{
    regexp.MustCompile(`^::=`),
    "::=",
    parseCoCoEq(nextState),
  }
}

var tokBEGIN = &token{
  regexp.MustCompile(`^BEGIN\b`),
  "BEGIN",
  parseBEGIN,
}

var tokEND = &token{
  regexp.MustCompile(`^END\b`),
  "END",
  parseEND,
}

const upperCaseIdentifier = `([[:upper:]][0-9a-zA-Z-]*\b)`

var tokTypeName = &token{
  regexp.MustCompile(`^` + upperCaseIdentifier),
  "type name",
  parseTypeName,
}

var tokTag = &token{
  regexp.MustCompile(`^\[((?P<class>UNIVERSAL|APPLICATION|PRIVATE)\s+)?(?P<number>[0-9]+)\]`),
  "[tag]",
  parseTag,
}

var tok__PLICIT = &token{
  regexp.MustCompile(`^(EXPLICIT|IMPLICIT)\b`),
  "EXPLICIT/IMPLICIT",
  parse__PLICIT,
}

func tokTypeDef(nextState *state) (*token) {
  return &token{
    regexp.MustCompile(`^(((OCTET\s+STRING)\b)|((OBJECT\s+IDENTIFIER)\b)|(ANY\s+DEFINED\s+BY\s+`+lowerCaseIdentifier+`)|(((INTEGER)|(BIT\s+STRING)|(ENUMERATED))(\s*\{)?)|((SEQUENCE|SET)(\s+SIZE\s*\([^)]+\))?((\s+OF\b)|(\s*\{)))|(CHOICE\s*\{)|`+ upperCaseIdentifier  +`)`),
    "type definition",
    parseTypeDef(nextState),
  }
}

const lowerCaseIdentifier = `([[:lower:]][0-9a-zA-Z-]*\b)`

var tokValueName = &token{
  regexp.MustCompile(`^` + lowerCaseIdentifier),
  "value name",
  parseValueName,
}

var tokValueType = &token{
  regexp.MustCompile(`^(OBJECT\s+IDENTIFIER\b|`+ upperCaseIdentifier +`)`),
  "type of value",
  parseValueType,
}

var tokValueDef = &token{
  regexp.MustCompile(`(^\{\s*((`+lowerCaseIdentifier+`(\s*\(\s*[0-9]+\s*\))?\s*)|([0-9]+\b\s*))+\s*\})|(^`+ lowerCaseIdentifier +`)|(^TRUE)|(^FALSE)|(^[0-9]+)`),
  "value",
  parseValueDef,
}

var tokFieldName = &token{
  regexp.MustCompile(`^` + lowerCaseIdentifier),
  "field name",
  parseFieldName,
}

var tokDEFAULT = &token{
  regexp.MustCompile(`^DEFAULT\b`),
  "DEFAULT",
  parseDEFAULT,
}

var tokOPTIONAL = &token{
  regexp.MustCompile(`^OPTIONAL\b`),
  "OPTIONAL",
  parseOPTIONAL,
}

var tokSIZE = &token{
  regexp.MustCompile(`^\(SIZE\s*\([^)]+\)\s*\)`),
  "(SIZE(...))",
  parseSIZE,
}

var tokRange = &token{
  regexp.MustCompile(`^\(\s*[a-zA-Z0-9-]+\.\.[a-zA-Z0-9-]+\s*\)`),
  "(lo..hi)",
  parseRange,
}

var tokLabelledInt = &token{
  regexp.MustCompile(`^` + lowerCaseIdentifier + `\s*\(\s*[0-9]+\s*\)`),
  "name(int)",
  parseLabelledInt,
}

var tokCommaDontEat = &token{
  regexp.MustCompile(`^[,]`),
  ",",
  parseDontEat,
}

var tokCurlyCloseDontEat = &token{
  regexp.MustCompile(`^[}]`),
  "}",
  parseDontEat,
}

var tokNotParenDontEat = &token{
  regexp.MustCompile(`^[^(]`),
  "something",
  parseDontEat,
}

var tokEOF = &token{
  regexp.MustCompile("^$"),
  "End of File",
  parseDontEat,
}

func (t *token) String() string {
  return "'"+t.HumanReadable+"'"
}

type state []*token

var stateStart = state{tokComment, tokDEFINITIONS}
var stateDEFINITIONS = state{tokComment, tokIMPLICITTAGS, tokEXPLICITTAGS}
var stateCoCoEq = state{tokComment, tokCoCoEq(&stateBEGIN)}
var stateBEGIN = state{tokComment, tokBEGIN}
var stateMain = state{tokComment, tokEND, tokTypeName, tokValueName}
var stateEnd = state{tokComment, tokEOF}
var stateTypeDefPre = state{tokComment, tokCoCoEq(&stateTypeDef)}
var stateTypeDef state
var stateTypeDef2 = state{tokComment, tokTag, tok__PLICIT, tokTypeDef(&stateTypePost) }
var stateTypePost = state{tokComment, tokSIZE, tokRange, tokNotParenDontEat}
var stateValueType = state{tokComment, tokValueType}
var stateValueDefPre = state{tokComment, tokCoCoEq(&stateValueDef)}
var stateValueDef = state{tokComment, tokValueDef}
var stateStructure = state{tokComment, tokFieldName}
var stateFieldDef state
var stateFieldDef2 = state{tokComment, tokTag, tok__PLICIT, tokTypeDef(&stateFieldPost) }
var stateFieldPost = state{tokComment, tokDEFAULT, tokOPTIONAL, tokSIZE, tokRange, tokCommaDontEat, tokCurlyCloseDontEat}
var stateLabelledInts = state{tokComment, tokLabelledInt}
var stateLabelledIntPost = state{tokComment, tokCommaDontEat, tokCurlyCloseDontEat}

func init() {
  stateFieldDef = stateFieldDef2
  stateTypeDef = stateTypeDef2
}

func parseSkip(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(implicit, src, pos+len(match), stat, tree)
}

func parseDontEat(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return pos, nil
}

func parseDEFINITIONS(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(implicit, src, pos+len(match), stateDEFINITIONS, tree)
}

func parseCoCoEq(nextState *state) (parseFunction) {
  return func(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
    return parseRecursive(implicit, src, pos+len(match), *nextState, tree)
  }
}

func parseBEGIN(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  tree.implicit = implicit
  var err error
  pos += len(match)
  for err == nil && pos < len(src) {
    pos, err = parseRecursive(implicit, src, pos, stateMain, tree)
  }
  return pos, err
}

func parseEND(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(implicit, src, pos+len(match), stateEnd, tree)
}

func parseIMPLICITTAGS(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(true, src, pos+len(match), stateCoCoEq, tree)
}

func parseEXPLICITTAGS(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(false, src, pos+len(match), stateCoCoEq, tree)
}

func parseTypeName(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  child := &Tree{ tag: -1, implicit: implicit, /*NOT typename!!*/name: match }
  tree.children = append(tree.children, child)
  return parseRecursive(implicit, src, pos+len(match), stateTypeDefPre, child)
}

func state_without_tok(stat state,tok *token) (state) {
  state_without_tok := make(state, 0, len(stat)-1)
  for _, t := range stat {
    if t != tok {
      state_without_tok = append(state_without_tok, t)
    }
  }
  return state_without_tok
}

func parseTag(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  tree.tag = 128 // default: "context-specific"
  for i, sm := range tok.Regex.FindStringSubmatch(match) {
    if sm != "" && tok.Regex.SubexpNames()[i] == "class" {
      switch(sm) {
        case "UNIVERSAL":   tree.tag &= ^(128+64)
        case "APPLICATION": tree.tag = (tree.tag & ^128) | 64
        case "PRIVATE":     tree.tag |= 128+64
      }
    }
    if sm != "" && tok.Regex.SubexpNames()[i] == "number" {
      num, err := strconv.Atoi(sm)
      if err != nil { return pos, err }
      if num < 0 || num > 63 { return pos, fmt.Errorf("%v: Tag number out of range: %v", lineCol(src, pos), num) }
      tree.tag += num
    }
  }
  if Debug {
    fmt.Fprintf(os.Stderr, "                   => tag: %v 0x%02x 0b%08b\n", tree.tag, tree.tag, tree.tag)
  }
  return parseRecursive(implicit, src, pos+len(match), state_without_tok(stat,tok), tree)
}

func parse__PLICIT(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  switch(match) {
    case "IMPLICIT": tree.implicit = true
    case "EXPLICIT": tree.implicit = false
  }
  return parseRecursive(implicit, src, pos+len(match), state_without_tok(stat,tok), tree)
}

func parseOPTIONAL(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  tree.optional = true
  return parseRecursive(implicit, src, pos+len(match), state_without_tok(stat,tok), tree)
}

func parseDEFAULT(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  tree.optional = true
  pos, err := parseRecursive(implicit, src, pos+len(match), stateValueDef, tree)
  if err != nil { return pos, err }
  tree.default_value = tree.value
  tree.value = nil
  return parseRecursive(implicit, src, pos, state_without_tok(stat,tok), tree)
}

func parseSIZE(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(implicit, src, pos+len(match), state_without_tok(stat,tok), tree)
}

func parseRange(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(implicit, src, pos+len(match), state_without_tok(stat,tok), tree)
}

func parseTypeDef(nextState *state) (parseFunction) {
  return func(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
    pos, err := parseTypeDefStatic(implicit, src, pos, match, stat, tok, tree) 
    if err != nil {
      return pos, err
    }
    if nextState == nil {
      return pos, nil
    } else {
      return parseRecursive(implicit, src, pos, *nextState, tree)
    }
  }
}

func parseTypeDefStatic(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  pos += len(match)
  var err error
  
  typ := strings.Join(strings.Fields(strings.Replace(match , "{", " {", -1))," ")
  spl := strings.Fields(typ)
  first := spl[0]
  last := spl[len(spl)-1]
  if typ == "OCTET STRING" {
    tree.basictype = OCTET_STRING
  } else if typ == "BIT STRING" {
    tree.basictype = BIT_STRING
  } else if typ == "INTEGER" {
    tree.basictype = INTEGER
  } else if typ == "ENUMERATED" {
    return pos-len(match), fmt.Errorf("%v: ENUMERATED without {...} enumeration list", lineCol(src, pos-len(match)))
  } else if typ == "INTEGER {" || typ == "BIT STRING {" || typ == "ENUMERATED {" {
    if typ == "BIT STRING {" {
      tree.basictype = BIT_STRING
    } else if typ == "ENUMERATED" {
      tree.basictype = ENUMERATED
    } else {
      tree.basictype = INTEGER
    }
    for {
      pos, err = parseRecursive(implicit, src, pos, stateLabelledInts, tree)
      if err != nil { return pos, err }
      if src[pos] == /*{*/ '}' { 
        return pos+1, nil
      } else { // src[pos] == ','
        pos++
      }
    }
  } else if typ == "OBJECT IDENTIFIER" {
    tree.basictype = OBJECT_IDENTIFIER
  } else if first == "SEQUENCE" || first == "SET" || first == "CHOICE" {
    if last == "OF" {
      if first == "SEQUENCE" { tree.basictype = SEQUENCE_OF } else { tree.basictype = SET_OF }
      child := &Tree{ tag: -1, implicit: implicit }
      tree.children = append(tree.children, child)
      return parseRecursive(implicit, src, pos, stateTypeDef, child)
    } else {
      switch(first) {
        case "SEQUENCE": tree.basictype = SEQUENCE
        case "SET":      tree.basictype = SET
        case "CHOICE":   tree.basictype = CHOICE
      }
      for {
        pos, err = parseRecursive(implicit, src, pos, stateStructure, tree)
        if err != nil { return pos, err }
        if src[pos] == /*{*/ '}' { 
          return pos+1, nil
        } else { // src[pos] == ','
          pos++
        }
      }
    }
  } else if first == "ANY" {
    tree.basictype = ANY
  } else {  
    if len(spl) != 1 {
      return pos, fmt.Errorf("%v: Unimplemented case in parseTypeDefStatic(): %v", lineCol(src, pos), typ)
    }
    tree.typename = match
  }
  
  return pos, nil
}

func parseValueName(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  child := &Tree{ tag: -1, implicit: implicit, name: match }
  tree.children = append(tree.children, child)
  return parseRecursive(implicit, src, pos+len(match), stateValueType, child)
}

func parseValueType(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  switch(match) {
    case "OBJECT IDENTIFIER": tree.basictype = OBJECT_IDENTIFIER
    case "OCTET STRING": tree.basictype = OCTET_STRING
    case "BIT STRING": tree.basictype = BIT_STRING
    case "INTEGER": tree.basictype = INTEGER
    case "ANY": tree.basictype = ANY
    default: 
      if tokTypeName.Regex.MatchString(match) {
        tree.typename = match
      } else {
        return pos, fmt.Errorf("%v: Unimplemented case in parseValueType(): %v", lineCol(src, pos), match)
      }
  }
  return parseRecursive(implicit, src, pos+len(match), stateValueDefPre, tree)
}

func parseValueDef(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  tree.value = []byte(match)
  return pos+len(match), nil
}

func parseFieldName(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  child := &Tree{ tag: -1, implicit: implicit, name: match }
  tree.children = append(tree.children, child)
  return parseRecursive(implicit, src, pos+len(match), stateFieldDef, child)
}

func parseLabelledInt(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  i := strings.Index(match, "(")
  k := strings.Index(match, ")")
  label := strings.TrimSpace(match[0:i])
  val, err := strconv.Atoi(strings.TrimSpace(match[i+1:k]))
  if err != nil {
    return pos, err
  }
  child := &Tree{ tag: -1, implicit: implicit, name: label, value:[]byte(strconv.Itoa(val)) }
  tree.children = append(tree.children, child)
  return parseRecursive(implicit, src, pos+len(match), stateLabelledIntPost, child)
}


func lineCol(s string, pos int) (string) {
  col := 0
  line := 1
  for i := range s {
    col++
    
    if i == pos { break }
    
    if s[i] == '\n' {
      col = 0
      line++
    }
  }
  
  return fmt.Sprintf("Line %v column %v", line, col)
}

func Parse(src string) (*Tree, error) {
  tree := &Tree{tag:-1, basictype:DEFINITIONS}
  pos := 0
  var err error
  for err == nil && pos < len(src) {
    pos, err = parseRecursive(true, src, pos, stateStart, tree)
  }
  return tree, err
}

func parseRecursive(implicit bool, src string, pos int, stat state, tree *Tree) (pos2 int, err error) {  
  for pos < len(src) && unicode.IsSpace(rune(src[pos])) { pos++ }
  
  found := false
  for _, tok := range stat {
    if tok.Regex.MatchString(src[pos:]) {
      match := tok.Regex.FindString(src[pos:])
      if Debug {
        fmt.Fprintf(os.Stderr, "%v: %v -> %v\n", lineCol(src,pos), tok.HumanReadable, strings.TrimSpace(match))
      }
      pos, err = tok.Parser(implicit, src, pos, match, stat, tok, tree)
      if err != nil { return pos, err }
      found = true
      break
    }
  }
  
  if !found {
    expected := ""
    for i, tok := range stat {
      if expected != "" { 
        if i != len(stat)-1 {
          expected = expected + ", " 
        } else {
          expected = expected + " or " 
        }
      }
      expected = expected + "'" + tok.HumanReadable + "'"
    }
    gotf := strings.Fields(src[pos:])
    got := ""
    if len(gotf) > 0 {
      got = gotf[0]
    }
    return pos, fmt.Errorf("%v: Expected %v instead of '%v'", lineCol(src, pos), expected, got)
  }
  
  return pos, err
}
