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
