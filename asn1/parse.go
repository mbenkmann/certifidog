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
  This file implements a recursive descent parser for ASN.1.
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

// All errors during the parse process are of this type.
type ParseError struct {
  // the ASN.1 source that was being parsed when the error occurred.
  Src string
  
  // the character index in the string src where the error occurred.
  Pos int
  
  // description of the error
  Desc string
}

const TRAILING_GARBAGE_ERROR = "Trailing garbage after 'END'"

func (e *ParseError) Error() string {
  col := 0
  line := 1
  for i := range e.Src {
    col++
    if i == e.Pos { break }
    if e.Src[i] == '\n' {
      col = 0
      line++
    }
  }
  return fmt.Sprintf("Line %v column %v: %v", line, col, e.Desc)
}

// Returns a *ParseError for string src at position pos with message fmt.Sprintf(format, a...).
func NewParseError(src string, pos int, format string, a ...interface{}) (*ParseError) {
  return &ParseError{Src:src, Pos:pos, Desc:fmt.Sprintf(format, a...)}
}

/*
Takes ASN.1 source beginning with "DEFINITIONS" and ending with "END" and parses
the contained value and type definitions, adding them to the already existing
definitions (if any). Any error that is returned is always of type *ParseError.
If an error occurs before "END", the Definitions object is
in an undefined state (and should not be used any more).
If an error occurs after the "END", the Definitions object is valid and the
returned error's Desc field is TRAILING_GARBAGE_ERROR. The Pos of that error points
to the first character of garbage. Note that -- comments that follow "END" are not
treated as garbage.
*/
func (defs *Definitions) Parse(asn1src string) error {
  if defs.tree == nil { 
    defs.tree = &Tree{src:asn1src, pos:0, nodetype: rootNode, tag:-1}
  }
  pos := 0
  var err error
  for err == nil && pos < len(asn1src) {
    pos, err = parseRecursive(true, asn1src, pos, stateStart, defs.tree)
  }
  
  if err != nil && pos != -1 { // all errors except TRAILING_GARBAGE_ERROR
    return err
  }
  
  defs.typedefs = map[string]*Tree{}
  defs.valuedefs = map[string]*Tree{}
  
  // use a different error variable for the following calls to preserve a possible TRAILING_GARBAGE_ERROR
  
  if resolve_err := defs.makeIndex(); resolve_err != nil {
    return resolve_err
  }
  
  defs.addUniversalTypes(asn1src, len(asn1src))
  
  if resolve_err := defs.resolveTypes(); resolve_err != nil {
    return resolve_err
  }
  
  if resolve_err := defs.resolveValueTypes(); resolve_err != nil {
    return resolve_err
  }
  
  for _, v := range defs.valuedefs {
    if resolve_err := defs.parseValue(v); resolve_err != nil {
      return resolve_err
    }
    if Debug {
      s := []string{}
      stringValue(&s, v)
      fmt.Fprintf(os.Stderr, "%v: %v %v -> %v\n", lineCol(v.src, v.pos), v.name, BasicTypeName[v.basictype], strings.Join(s,""))
    }
  }
  
  if resolve_err := defs.resolveValues(); resolve_err != nil {
    return resolve_err
  }
  
  for _, t := range defs.typedefs {
    if resolve_err := defs.resolveFields(t); resolve_err != nil {
      return resolve_err
    }
  }

  return err // this err is possibly TRAILING_GARBAGE_ERROR
}



// Every token is associated with a function of this type. When a token is identified by matching
// its regex, the corresponding parseFunction is called to process the token and integrate it
// into the parse tree.
//   implicit: default tag mode (true => IMPLICIT, false => EXPLICIT)
//   src: the ASN.1 source code being parsed
//   pos: character index in src of the token that caused this parseFunction to be called
//   match: the matched token, i.e. src[pos:pos+len(match)] == match
//   stat: the current parser state. This is simply a list of tokens that are allowed at this point.
//   tok: the token that matched. This is an element of the stat list. Some parseFunctions remove
//        tok from stat before performing recursion with the resulting state. This deals with states
//        that allow multiple tokens in any order but with only one instance of each token.
//   tree: the most recent node added to the parse tree. The parseFunction possibly adds new children
//         to this node.
type parseFunction func(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error)

// A token (duh!).
type token struct {
  // Regular expression that recognizes this token.
  Regex *regexp.Regexp
  // A string to use when referring to this token in (error) messages.
  HumanReadable string
  // When the token's regex matches, this parseFunction is called.
  Parser parseFunction
}

var tokComment = &token{
  regexp.MustCompile("^--.*?(--|\n)"),
  "'-- Comment'",
  parseSkip,
}

var tokDEFINITIONS = &token{
  regexp.MustCompile(`^DEFINITIONS\b`),
  "'DEFINITIONS'",
  parseDEFINITIONS,
}

var tokIMPLICITTAGS = &token{
  regexp.MustCompile(`^IMPLICIT\s+TAGS\b`),
  "'IMPLICIT TAGS'",
  parseIMPLICITTAGS,
}

var tokEXPLICITTAGS = &token{
  regexp.MustCompile(`^EXPLICIT\s+TAGS\b`),
  "'EXPLICIT TAGS'",
  parseEXPLICITTAGS,
}

func tokCoCoEq(nextState *state) (*token) {
  return &token{
    regexp.MustCompile(`^::=`),
    "'::='",
    parseCoCoEq(nextState),
  }
}

var tokBEGIN = &token{
  regexp.MustCompile(`^BEGIN\b`),
  "'BEGIN'",
  parseBEGIN,
}

var tokEND = &token{
  regexp.MustCompile(`^END\b`),
  "'END'",
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
  "'[tag]'",
  parseTag,
}

var tok__PLICIT = &token{
  regexp.MustCompile(`^(EXPLICIT|IMPLICIT)\b`),
  "'EXPLICIT'/'IMPLICIT'",
  parse__PLICIT,
}

const typeIdentifier = `^((BOOLEAN\b)|(NULL\b)|((OCTET\s+STRING)\b)|((OBJECT\s+IDENTIFIER)\b)|(ANY\s+DEFINED\s+BY\s+`+lowerCaseIdentifier+`)|(((INTEGER)|(BIT\s+STRING)|(ENUMERATED))(\s*\{)?)|((SEQUENCE|SET)(\s+SIZE\s*\([^)]+\))?((\s+OF\b)|(\s*\{)))|(CHOICE\s*\{)|`+ upperCaseIdentifier  +`)`

func tokTypeDef(nextState *state) (*token) {
  return &token{
    regexp.MustCompile(typeIdentifier),
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
  regexp.MustCompile(typeIdentifier),
  "type of value",
  parseValueType,
}

var tokValueInteger = &token{
  regexp.MustCompile(`(^-?[0-9]+)`),
  "integer",
  parseValueDef,
}

var tokValueBoolean = &token{
  regexp.MustCompile(`(^TRUE)|(^FALSE)`),
  "boolean",
  parseValueDef,
}

var tokValueNull = &token{
  regexp.MustCompile(`(^NULL)`),
  "NULL",
  parseValueDef,
}

var tokValueString = &token{
  // NOTE: IN ORDER TO SUPPORT MORE STRING SYNTAXES, resolve.go:parseValue() MUST BE EXPANDED, TOO!
  regexp.MustCompile(`(^"[^"]*")`),
  "string",
  parseValueDef,
}

var tokValueReference = &token{
  regexp.MustCompile(`(^`+lowerCaseIdentifier+`)`),
  "reference to another value",
  parseValueDef,
}

var tokValueOID = &token{
  // NOTE: We intentionally permit minus in the OID regex, even though negative numbers are not permitted.
  // This will be rejected in post-processing with a more meaningful error message than the
  // recursive descent parser would spit out.
  regexp.MustCompile(`(^\{\s*((`+lowerCaseIdentifier+`(\s*\(\s*-?[0-9]+\s*\))?\s*)|(-?[0-9]+\b\s*))+\s*\})`),
  "object identifier",
  parseValueDef,
}

var tokFieldName = &token{
  regexp.MustCompile(`^` + lowerCaseIdentifier),
  "field name",
  parseFieldName,
}

var tokDEFAULT = &token{
  regexp.MustCompile(`^DEFAULT\b`),
  "'DEFAULT'",
  parseDEFAULT,
}

var tokOPTIONAL = &token{
  regexp.MustCompile(`^OPTIONAL\b`),
  "'OPTIONAL'",
  parseOPTIONAL,
}

var tokSIZE = &token{
  regexp.MustCompile(`^\(SIZE\s*\([^)]+\)\s*\)`),
  "'(SIZE(...))'",
  parseSIZE,
}

var tokRange = &token{
  regexp.MustCompile(`^\(\s*[a-zA-Z0-9-]+\.\.[a-zA-Z0-9-]+\s*\)`),
  "'(lo..hi)'",
  parseRange,
}

var tokLabelledInt = &token{
  regexp.MustCompile(`^` + lowerCaseIdentifier + `\s*\(\s*-?[0-9]+\s*\)`),
  "'name(int)'",
  parseLabelledInt,
}

var tokCommaDontEat = &token{
  regexp.MustCompile(`^[,]`),
  "','",
  parseDontEat,
}

var tokCurlyCloseDontEat = &token{
  regexp.MustCompile(`^[}]`),
  "'}'",
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

// A parser state is simply the list of tokens that are valid when in that state.
// If a string is encountered that does not match any of the tokens in the current
// parser state list, this results in the familiar "... expected" parser error.
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
var stateValueDef = state{tokComment, tokValueInteger, tokValueBoolean, tokValueNull, tokValueString, tokValueReference, tokValueOID}
var stateStructure = state{tokComment, tokFieldName}
var stateFieldDef state
var stateFieldDef2 = state{tokComment, tokTag, tok__PLICIT, tokTypeDef(&stateFieldPost) }
var stateFieldPost = state{tokComment, tokDEFAULT, tokOPTIONAL, tokSIZE, tokRange, tokCommaDontEat, tokCurlyCloseDontEat}
var stateLabelledInts = state{tokComment, tokLabelledInt}
var stateLabelledIntPost = state{tokComment, tokCommaDontEat, tokCurlyCloseDontEat}

// This is required to break definition loops (stateTypeDef => tokTypeDef => parseTypeDef => parseTypeDefStatic => stateTypeDef)
func init() {
  stateFieldDef = stateFieldDef2
  stateTypeDef = stateTypeDef2
}

// eat up the token but stay in the same state (the eaten token remains valid)
func parseSkip(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(implicit, src, pos+len(match), stat, tree)
}

// do not eat the token, do not parse recursively
func parseDontEat(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return pos, nil
}

func parseDEFINITIONS(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  return parseRecursive(implicit, src, pos+len(match), stateDEFINITIONS, tree)
}

// eat the token and parse recursively in nextState
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
  child := &Tree{ src:src, pos:pos, nodetype:typeDefNode, tag: -1, implicit: implicit, /*NOT typename!!*/name: match }
  tree.children = append(tree.children, child)
  return parseRecursive(implicit, src, pos+len(match), stateTypeDefPre, child)
}

// returns the stat with tok removed from it.
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
      if err != nil { 
        return pos, NewParseError(src, pos, "Illegal tag number: %v", err)
      }
      if num < 0 || num > 63 { return pos, NewParseError(src, pos, "Tag number not in range [0..63]: %v", num) }
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
  } else if typ == "BOOLEAN" {
    tree.basictype = BOOLEAN
  } else if typ == "NULL" {
    tree.basictype = NULL
  } else if typ == "BIT STRING" {
    tree.basictype = BIT_STRING
  } else if typ == "INTEGER" {
    tree.basictype = INTEGER
  } else if typ == "ENUMERATED" {
    return pos-len(match), NewParseError(src, pos-len(match), "ENUMERATED without {...} enumeration list")
  } else if typ == "INTEGER {" || typ == "BIT STRING {" || typ == "ENUMERATED {" {
    if typ == "BIT STRING {" {
      tree.basictype = BIT_STRING
    } else if first == "ENUMERATED" {
      tree.basictype = ENUMERATED
    } else {
      tree.basictype = INTEGER
    }
    tree.namedints = map[string]int{}
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
      child := &Tree{ src:src, pos:pos, nodetype: ofNode, tag: -1, implicit: implicit }
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
        
        // Mark all fields of a CHOICE as OPTIONAL, because we use instantiateSEQUENCE()
        // for CHOICE and it would otherwise demand that all fields have an instance value.
        if tree.basictype == CHOICE {
          for i := range tree.children {
            tree.children[i].optional = true
          }
        }
        
        
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
      return pos, NewParseError(src, pos, "Unimplemented case in parseTypeDefStatic(): %v", typ)
    }
    tree.typename = match
  }
  
  return pos, nil
}

func parseValueName(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  child := &Tree{ src:src, pos:pos, nodetype: valueDefNode, tag: -1, implicit: implicit, name: match }
  tree.children = append(tree.children, child)
  return parseRecursive(implicit, src, pos+len(match), stateValueType, child)
}

func parseValueType(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  switch(match) {
    case "OBJECT IDENTIFIER": tree.basictype = OBJECT_IDENTIFIER
    case "OCTET STRING": tree.basictype = OCTET_STRING
    case "BIT STRING": tree.basictype = BIT_STRING
    case "ENUMERATED": tree.basictype = ENUMERATED
    case "INTEGER": tree.basictype = INTEGER
    case "BOOLEAN": tree.basictype = BOOLEAN
    case "NULL": tree.basictype = NULL
    case "ANY": tree.basictype = ANY
    default: 
      if tokTypeName.Regex.MatchString(match) {
        tree.typename = match
      } else {
        return pos, NewParseError(src, pos, "Unimplemented case in parseValueType(): %v", match)
      }
  }
  return parseRecursive(implicit, src, pos+len(match), stateValueDefPre, tree)
}

func parseValueDef(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  tree.value = match
  return pos+len(match), nil
}

func parseFieldName(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  child := &Tree{ src:src, pos:pos, nodetype: fieldNode, tag: -1, implicit: implicit, name: match }
  tree.children = append(tree.children, child)
  return parseRecursive(implicit, src, pos+len(match), stateFieldDef, child)
}

func parseLabelledInt(implicit bool, src string, pos int, match string, stat state, tok *token, tree *Tree) (int, error) { 
  i := strings.Index(match, "(")
  k := strings.Index(match, ")")
  label := strings.TrimSpace(match[0:i])
  val, err := strconv.Atoi(strings.TrimSpace(match[i+1:k]))
  if err != nil {
    return pos, NewParseError(src, pos+i+1, "Not a valid integer: %v", err)
  }
  if tree.basictype == BIT_STRING && val < 0 {
    return pos, NewParseError(src, pos+i+1, "Bit index must not be negative")
  }
  tree.namedints[label] = val
  return parseRecursive(implicit, src, pos+len(match), stateLabelledIntPost, tree)
}

func lineCol(src string, pos int) string {
  col := 0
  line := 1
  for i := range src {
    col++
    if i == pos { break }
    if src[i] == '\n' {
      col = 0
      line++
    }
  }
  return fmt.Sprintf("Line %v col %v", line, col)
}

// In case of TRAILING_GARBAGE_ERROR, pos2 is -1. For other errors it's the actual error position.
// If there is no error, the position of the next token is returned in pos2.
func parseRecursive(implicit bool, src string, pos int, stat state, tree *Tree) (pos2 int, err error) {  
  for pos < len(src) && unicode.IsSpace(rune(src[pos])) { 
    if tree.pos == pos { tree.pos++}
    pos++ 
  }
  
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
    if stat[len(stat)-1] == tokEOF {
      return -1, NewParseError(src, pos, TRAILING_GARBAGE_ERROR)
    }
    
    expected := ""
    for i, tok := range stat {
      if expected != "" { 
        if i != len(stat)-1 {
          expected = expected + ", " 
        } else {
          expected = expected + " or " 
        }
      }
      expected = expected + tok.HumanReadable
    }
    gotf := strings.Fields(src[pos:])
    got := ""
    if len(gotf) > 0 {
      got = gotf[0]
    }
    return pos, NewParseError(src, pos, "Expected %v instead of '%v'", expected, got)
  }
  
  return pos, err
}

