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
  This file contains the code for converting asn1.Instance to a
  []byte encoded according to DER.
*/

package asn1

import "fmt"
import "strings"
import "math/big"

// Takes a DER encoding and produces a human-readable, pretty-printed analysis of it.
func AnalyseDER(der []byte) string {
  output := []string{}
  l := analyseDER(der, 0, "", &output)
  if l < len(der) {
    output = append(output, fmt.Sprintf("\n%v UNDECODED BYTES REMAINING!", len(der)-l))
  }
  return strings.Join(output,"")
}

func (i *Instance) DER() []byte {
  var b []byte
  encodeDER(&b, (*Tree)(i), i.implicit, i.tag)
  return b
}

func encodeDER(b *[]byte, t *Tree, implicit bool, tag int) {
  if tag < 0 { panic("Instance has no tag") }
  start := len(*b)
  *b = append(*b, byte(tag))
  tagnum := (*b)[start] & 63
  if tagnum >= 31 {
    // Since we only support tags <= 63 we never need more than additional 1 byte
    *b = append(*b, tagnum)
    (*b)[start] = ((*b)[start] & (128+64)) + 31
  }
  
  *b = append(*b, 0) // reserve 1 byte for length
  
  datastart := len(*b)
  
  // encode data
  if !implicit {
    (*b)[start] += 32 // tag as constructed encoding
    encodeDER(b, t, true, BasicTypeTag[t.basictype])
  } else {
    switch t.basictype {
      case SEQUENCE, SET:
        (*b)[start] += 32 // tag as constructed encoding
        
        // filter out optional children that are at DEFAULT value
        // because they are not allowed to be encoded in DER.
        children := make([]*Tree,0,len(t.children))
        for _, c := range t.children {
          if !c.isDefaultValue { children = append(children, c) }
        }
        
        if t.basictype == SET { // for SET we need to sort children by tag
          children = make([]*Tree,len(t.children))
          copy(children, t.children)
          // insertion sort
          for x := 1; x < len(children); x++ {
            child_to_find_place_for := children[x]
            y := x
            for y > 0 && children[y-1].tag > child_to_find_place_for.tag {
              children[y] = children[y-1]
              y--
            }
            children[y] = child_to_find_place_for
          }
        }
        
        // process children
        for _, c := range children {
          encodeDER(b, c, c.implicit, c.tag)
        }
        
      case SEQUENCE_OF:
        (*b)[start] += 32 // tag as constructed encoding
        for _, c := range t.children {
          encodeDER(b, c, c.implicit, c.tag)
        }
      
      case SET_OF:
        (*b)[start] += 32 // tag as constructed encoding
        
        // SET OF is ordered lexicographically by encoding of the individual elements,
        // so we have to collect them first and then append them in sorted order
        encodings := make([]*[]byte, len(t.children))
        for i, c := range t.children {
          encodeDER(encodings[i], c, c.implicit, c.tag)
        }
        
        // insertion sort
        for x := 1; x < len(encodings); x++ {
          child_to_find_place_for := encodings[x]
          y := x
          for y > 0 && greater(encodings[y-1], child_to_find_place_for) {
            encodings[y] = encodings[y-1]
            y--
          }
          encodings[y] = child_to_find_place_for
        }
        
        for _, enc := range encodings {
          *b = append(*b, (*enc)...)
        }
      
      case OCTET_STRING:
        *b = append(*b, t.value.([]byte)...)
      
      case BOOLEAN:
        if t.value.(bool) == true {
          *b = append(*b, 255)
        } else {
          *b = append(*b, 0)
        }
      
      case INTEGER, ENUMERATED:
        val := t.value.(int)
        // based on http://golang.org/src/encoding/asn1/marshal.go:marshalInt64()
        numBytes := 1
        i := val
        for i > 127 {
          numBytes++
          i >>= 8
        }
        for i < -128 {
          numBytes++
          i >>= 8
        }
        for ; numBytes > 0; numBytes-- {
          *b = append(*b, byte(val >> uint((numBytes-1)*8)))
        }
      case BIT_STRING:
        bits := t.value.([]bool)
        rest := (8-(len(bits) & 7)) & 7
        *b = append(*b, byte(rest))
        octet := byte(0)
        for i, bit := range bits {
          octet = (octet << 1)
          if bit { octet++ }
          if (i+1) & 7 == 0 { *b = append(*b, octet) }
        }
        if rest > 0 { *b = append(*b, octet << uint(rest)) }
      case OBJECT_IDENTIFIER:
        oid := t.value.([]int)
        *b = append(*b, byte(40 * oid[0] + oid[1]))
        for _, component := range oid[2:] {
          start := len(*b)
          for {
            *b = append(*b, 0)
            for i:=len(*b)-1; i > start; i-- {
              (*b)[i] = (*b)[i-1]
            }
            
            (*b)[start] = byte(component) & 127

            if component <= 127 {
              break
            }

            (*b)[start] += 128
            component >>= 7
          }
        }
      default: panic("Unhandled case in encodeDER()")
    }
  }
  
  // encode length
  length := len(*b) - datastart
  if length <= 127 { // length can be encoded in the 1 byte we reserved earlier
    (*b)[datastart-1] = byte(length)
  } else if length <= 0xFF { // length can be encoded in 1 byte
    additional := 1
    newb := make([]byte, len(*b)+additional)
    copy(newb, (*b)[:datastart])
    copy(newb[datastart+additional:], (*b)[datastart:])
    newb[datastart-1] = byte(128+additional)
    newb[datastart] = byte(length)
    *b = newb
  } else if length <= 0xFFFF { // length can be encoded in 2 bytes
    additional := 2
    newb := make([]byte, len(*b)+additional)
    copy(newb, (*b)[:datastart])
    copy(newb[datastart+additional:], (*b)[datastart:])
    newb[datastart-1] = byte(128+additional)
    newb[datastart] = byte(length)
    newb[datastart+1] = byte(length >> 8)
    *b = newb
  } else if length <= 0xFFFFFF { // length can be encoded in 3 bytes
    additional := 3
    newb := make([]byte, len(*b)+additional)
    copy(newb, (*b)[:datastart])
    copy(newb[datastart+additional:], (*b)[datastart:])
    newb[datastart-1] = byte(128 + additional)
    newb[datastart] = byte(length)
    newb[datastart+1] = byte(length >> 8)
    newb[datastart+2] = byte(length >> 16)
    *b = newb
  } else {
    panic("Structures larger than 16MB not supported at this time")
  }
}

// Returns true iff a is lexicographically greater than b.
// If b is a prefix of a but shorter in length then true is returned.
// If a is a prefix of b but shorter in length or if both are the same, then false is returned.
func greater(a,b *[]byte) bool {
  i := 0
  for i < len(*a) && i < len(*b) && (*a)[i] == (*b)[i] { i++ }
  if i < len(*a) {
    if i == len(*b) { return true }
    return (*a)[i] > (*b)[i]
  }
  return false
}

const indentStep = "  "
const prematureEnd = " !PREMATURE END OF DATA!"
// 3f 80 80 01 UNIVERSAL 1 (BOOLEAN), CONSTRUCTED
// returns the index of the next undecoded byte
func analyseDER(der []byte, idx int, indent string, output *[]string) int {
  for idx < len(der) {
    *output = append(*output, indent)
    tag := int(der[idx])
    *output = append(*output, fmt.Sprintf("%02X", tag))
    class := tag & (128+64)
    constructed := (tag & 32) != 0
    tagnum := tag & 31
    if tagnum == 31 {
      tagnum = 0
      for {
        idx++
        if idx == len(der) {
          *output = append(*output, prematureEnd)
          return idx
        }
        *output = append(*output, fmt.Sprintf(" %02X", der[idx]))
        tagnum = (tagnum << 7) + int(der[idx] & 127)
        if der[idx] & 128 == 0 { break }
        if tagnum > 0xFFFFFF { // arbitrary cutoff for tag sizes to prevent overflow of tagnum
          *output = append(*output, " !TAG OUT OF RANGE!")
          return idx
        }
      }
    }
    
    classstr := TagClass[class]
    if classstr == "" { classstr = "CONTEXT-SPECIFIC " }
    *output = append(*output, fmt.Sprintf(" %v%v", classstr, tagnum))
    
    if class == 0 && tagnum > 0 && tagnum < 31{ // UNIVERSAL (except 0 which is reserved)
      *output = append(*output, fmt.Sprintf(" (%v)", UniversalTagName[tagnum]))
    }
    
    if constructed {
      *output = append(*output, " CONSTRUCTED")
    } else {
      *output = append(*output, " PRIMITIVE")
    }
    *output = append(*output, "\n")
    
    idx++
    if idx == len(der) {
      *output = append(*output, prematureEnd)
      return idx
    }
    
    *output = append(*output, fmt.Sprintf("%v%02X", indent, der[idx]))
    
    length := int(der[idx])
    if length <= 127 {
      *output = append(*output, fmt.Sprintf(" LENGTH %v", length))
    } else {
      length &= 127
      if length == 0 { // indefinite length
        length = -1
        if !constructed {
          *output = append(*output, fmt.Sprintf(" !PRIMITIVE ENCODING WITH INDEFINITE LENGTH!"))
          return idx
        }
        *output = append(*output, fmt.Sprintf(" INDEFINITE LENGTH"))
      } else {
        if length > 3 { // reject data structures larger than 16MB (or incorrectly encoded length)
          *output = append(*output, " !TOO MANY LENGTH OCTETS!")
          return idx
        }
        
        l := 0
        for length > 0 {
          idx++
          if idx == len(der) {
            *output = append(*output, prematureEnd)
            return idx
          }
          *output = append(*output, fmt.Sprintf(" %02X", der[idx]))
          l = (l << 8) + int(der[idx])
          length--
        }
        length = l
        *output = append(*output, fmt.Sprintf(" LENGTH %v", length))
      }
    }
    
    if tag == 0 && length == 0 { // end of contents marker
      return idx+1
    }

    *output = append(*output, "\n")
    
    if constructed {
      idx++
      if length < 0 { // indefinite length
        idx = analyseDER(der, idx, indent+indentStep, output)
      } else if idx+length > len(der) { // length exceeds available data
        *output = append(*output, " !LENGTH EXCEEDS AVAILABLE DATA!")
      } else {
        idx2 := analyseDER(der[0:idx+length], idx, indent+indentStep, output)
        if idx2 != idx+length {
          *output = append(*output, " !SHORT DATA!")
        }
        idx = idx2
      }
      
      // if a decoding error occurred, do not continue
      if strings.HasSuffix((*output)[len(*output)-1], "!") {
        return idx
      }
      
    } else { // primitive
      *output = append(*output, indent)
      if length == 0 {
        *output = append(*output, "EMPTY ")
      }
      
      contents := ""
      already_decoded := false
      decoding := []string{}
      if idx+length < len(der) && ( (tag & (128+64) == 128) || tag == 19 || tag == 4 || tag == 6 || tag == 12 || tag == 23 || tag == 2 ) {
        cont := der[idx+1:idx+1+length]
        if tag == 2 { // INTEGER
           var b big.Int
           b.SetBytes(cont)
           contents = " "+b.String()
        }
        if contents == "" { // try to parse as DER
          idx2 := analyseDER(cont, 0, indent+indentStep, &decoding)
          if idx2 == len(cont) && len(decoding) > 0 && !strings.HasSuffix(decoding[len(decoding)-1], "!") {
            contents = " ARE VALID DER => DECODING\n"
            already_decoded = true
            length -= len(cont)
            idx += len(cont)
          }
        }
        if contents == "" && length < 80 { // try to parse as string
          contents = fmt.Sprintf(" %q", cont)
          if strings.Contains(contents, `\x`) { contents = "" }
        }
        if contents == "" && (tag == 6 || (length < 16 && length >= 4)) { // Try to parse as OID
          contents = " "+oidString(cont)
          if strings.HasSuffix(contents, "!") { contents = "" }
        }
      } // no else for error reporting here because error will be reported further below
      
      for !already_decoded && length > 0 {
        idx++
        if idx == len(der) {
          *output = append(*output, prematureEnd)
          return idx
        }
        *output = append(*output, fmt.Sprintf("%02X ", der[idx]))
        length--
      }
      
      *output = append(*output, "CONTENTS")
      if contents != "" {
        *output = append(*output, contents)
        
      }
      if already_decoded {
        *output = append(*output, decoding...)
      } else {
        *output = append(*output, "\n")
      } 
      idx++
    }
  }
  
  return idx
}

// Takes a DER encoded OBJECT IDENTIFIER and converts it to a string
// If the oid is illegal, the string will contain an error message and 
// will have a "!" as last character
func oidString(oid []byte) string {
  if len(oid) == 0 {
    return "!EMPTY OBJECT IDENTIFIER!"
  }
  
  value1 := int(oid[0]) / 40
  value2 := int(oid[0]) % 40
  st := fmt.Sprintf("%d.%d", value1, value2)
  valuen := 0
  for i := 1; i < len(oid); i++ {
    if valuen >= 0xFFFFFF {
      // Cannot decode integers this large
      break 
    }
    valuen = (valuen << 7) + int(oid[i] & 127)
    if oid[i] & 128 == 0 {
      st = fmt.Sprintf("%s.%d", st, valuen)
      valuen = 0
    }
  }
  
  if valuen != 0 {
    st = st + "!ERROR DECODING OBJECT IDENTIFIER!"
  }
  return st
}
