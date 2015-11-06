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
  []byte encoded according to DER and code for parsing and analysing
  DER blobs.
*/

package asn1

import (
         "io"
         "os"
         "fmt"
         "strings"
         "math/big"
         "crypto"
         "crypto/x509"
         "crypto/rsa"
         "crypto/ecdsa"
         "github.com/mbenkmann/golib/util"
         "github.com/mbenkmann/golib/deque"
       )

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
  encodeDER(&b, (*Tree)(i))
  return b
}

func encodeDER(b *[]byte, t *Tree) {
  start := len(*b)
  
  *b = append(*b, t.tags...)
  
  datastart := len(*b)
  
  {
    switch t.basictype {
      case SEQUENCE, SET, CHOICE:
        // filter out optional children that are at DEFAULT value
        // because they are not allowed to be encoded in DER.
        children := make([]*Tree,0,len(t.children))
        for _, c := range t.children {
          if !c.isDefaultValue { children = append(children, c) }
        }
        
        if t.basictype == SET { // for SET we need to sort children by tag
          // insertion sort
          for x := 1; x < len(children); x++ {
            child_to_find_place_for := children[x]
            y := x
            for y > 0 && greater(&children[y-1].tags,&child_to_find_place_for.tags) {
              children[y] = children[y-1]
              y--
            }
            children[y] = child_to_find_place_for
          }
        }
        
        // process children
        for _, c := range children {
          encodeDER(b, c)
        }
        
      case SEQUENCE_OF:
        for _, c := range t.children {
          encodeDER(b, c)
        }
      
      case SET_OF:
        // SET OF is ordered lexicographically by encoding of the individual elements,
        // so we have to collect them first and then append them in sorted order
        encodings := make([]*[]byte, len(t.children))
        for i, c := range t.children {
          encodings[i] = &[]byte{}
          encodeDER(encodings[i], c)
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
        if t.tags[len(t.tags)-2] == 30 { // BMPString; -2 because the last byte of tags is 0
          *b = append(*b, encodeUTF16(t.value.([]byte))...)
        } else {
          *b = append(*b, t.value.([]byte)...)
        }
      
      case BOOLEAN:
        if t.value.(bool) == true {
          *b = append(*b, 255)
        } else {
          *b = append(*b, 0)
        }
      
      case NULL:
        {} /* nothing to append */
      
      case INTEGER, ENUMERATED:
        var bi *big.Int
        switch val := t.value.(type) {
          case int: bi = big.NewInt(int64(val))
          case *big.Int: bi = val
        }
        if bi.Sign() == 0 {
          *b = append(*b, 0)
        } else if bi.Sign() < 0 {
          bi.Add(bi, big.NewInt(1))
          bytes := bi.Bytes()
          for i := range bytes {
            bytes[i] = ^bytes[i]
          }
          if len(bytes) == 0 || bytes[0] < 128 {
            *b = append(*b, 255)
          }
          *b = append(*b, bytes...)
        } else {
          bytes := bi.Bytes()
          if bytes[0] >= 128 {
            *b = append(*b, 0)
          }
          *b = append(*b, bytes...)
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
            
            (*b)[start] = (byte(component) & 127) + 128

            if component <= 127 {
              break
            }

            component >>= 7
          }
          // unset bit 8 on last octet
          (*b)[len(*b)-1] -= 128
        }
      default: panic("Unhandled case in encodeDER()")
    }
  }
  
  // fill in all length placeholders with actual length
  for datastart > start {
    length := len(*b) - datastart
    if length <= 127 { // length can be encoded in the 1 byte already reserved
      (*b)[datastart-1] = byte(length)
    } else { // we need to insert more bytes
      le := big.NewInt(int64(length)).Bytes()
      // The reserved byte is used to give the number of length bytes following,
      // so the number of additional bytes we need is len(le), NOT len(le)-1 as
      // it would be if we could use the reserved byte as part of the length.
      additional := len(le)
      newb := make([]byte, len(*b)+additional)
      copy(newb, (*b)[:datastart])
      copy(newb[datastart+additional:], (*b)[datastart:])
      newb[datastart-1] = byte(128+additional)
      copy(newb[datastart:], le)
      *b = newb
    }
    
    // find next length placeholder
    datastart--
    for datastart > start && (*b)[datastart-1] != 0 { datastart-- }
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
      if length > 0 && idx+length < len(der) && ( (tag & (128+64) == 128) || tag == 19 || tag == 4 || tag == 6 || tag == 12 || tag == 23 || tag == 2 ) {
        cont := der[idx+1:idx+1+length]
        if tag == 2 { // INTEGER
           var b big.Int
           b.SetBytes(cont)
           if cont[0] & 128 != 0 { // negative number
             var x big.Int
             x.SetBit(&x, len(cont)*8, 1)
             x.Sub(&x, &b)
             b.Neg(&x)
           }
           contents = " "+b.String()
        }
        if contents == "" && (tag == 4 || tag > 31) { // try to parse as DER
          idx2 := analyseDER(cont, 0, indent+indentStep, &decoding)
          if idx2 == len(cont) && len(decoding) > 0 && !strings.HasSuffix(decoding[len(decoding)-1], "!") {
            contents = " ARE VALID DER => DECODING\n"
            already_decoded = true
            length -= len(cont)
            idx += len(cont)
          }
        }
        if contents == "" && tag != 6 && length < 80 { // try to parse as string
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

// A data structure produced by parsing DER-encoded bytes with UnmarshalDER().
type Unmarshalled interface {
  // The ASN.1 tag of the 1st entity in the DER bytes. At this time, this
  // is just the 1st byte of the tag without any processing. In the future
  // support for multi-byte tags may be added.
  Tag() int
}

// There are 2 types of Rawtag:
// 1) The byte(s) of the DER encoding of one ASN.1 tag.
// 2) The byte(s) of one or more DER encoded ASN.1 tags with a 0-byte after each tag.
//    The 0 byte is present even if there is only one tag. This means that form 2) and form 1)
//    of Rawtag can be clearly distinguished.
type Rawtag string

// Subtype of Unmarshalled that is produced by UnmarshalDER() when applied to a
// CONSTRUCTED DER encoding.
type UnmarshalledConstructed struct {
  _Tag int
  
  // This map contains 1 or 2 mappings entries for each element in the constructed sequence.
  // One entry, that always exists, has as its key the concatenation of the tags of
  // all elements that precede the mapped element in the sequence, followed by the tag
  // of the mapped element, with a 0-byte after each tag (including the last). This is
  // form 2) as described in the doc of the Rawtag type.
  // The second entry only exists if the mapped element has a unique tag among all elements
  // of the constructed sequence. It has as its key that unique tag WITHOUT a 0-byte following it.
  // This is form 1) as described in the doc of the Rawtag type.
  Data map[Rawtag]Unmarshalled
}

func (u *UnmarshalledConstructed) Tag() int { return u._Tag }

// Subtype of Unmarshalled that is produced by UnmarshalDER() when applied to a
// PRIMITIVE DER encoding.
type UnmarshalledPrimitive struct {
  _Tag int
  
  // The raw content bytes of the primitive encoding without the tag and length bytes.
  Data []byte
}

func (u *UnmarshalledPrimitive) Tag() int { return u._Tag }

// Parses the bytes in der[idx:] which have to be DER-encoded ASN.1 data structures
// and returns the resulting tree. If there is any problem parsing the data, nil is returned.
func UnmarshalDER(der []byte, idx int) *UnmarshalledConstructed {
  seq := map[Rawtag]Unmarshalled{}
  
  conflict := map[Rawtag]bool{}
  
  // Each child is added to seq with 2 keys:
  // 1) the tag of the child converted to string; this cannot contain any 0 bytes
  // 2) all tags of preceding children concatenated with the child's tag, with a 0 byte after each tag
  // In case 2 siblings have the same tag, the entry 1) above is removed from the map
  preceding_tags := []byte{}
  
  for idx < len(der) {
    tag := []byte{der[idx]}
    constructed := (tag[0] & 32) != 0
    if tag[0] & 31 == 31 {
      for {
        idx++
        if idx == len(der) { // premature end of data
          return nil 
        }
        tag = append(tag, der[idx])
        if der[idx] & 128 == 0 { break }
      }
    }
    
    if Debug {
      fmt.Fprintf(os.Stderr, "Tag: %x constructed: %v\n",tag,constructed)
    }
    
    idx++
    if idx == len(der) { // premature end of data
      return nil
    }
    
    length := int(der[idx])
    if length > 127 { // multi-byte length
      length &= 127
      if length == 0 { // indefinite length
        length = -1
        if !constructed { // error, indefinite length is only permitted with constructed
          return nil
        }
      } else { // definite multi-byte length
        if length > 3 { // reject data structures larger than 16MB (or incorrectly encoded length)
          return nil
        }
        
        l := 0
        for length > 0 {
          idx++
          if idx == len(der) { // premature end of data
            return nil
          }
          l = (l << 8) + int(der[idx])
          length--
        }
        length = l
      }
    }
    
    if Debug {
      fmt.Fprintf(os.Stderr, "Length: %v\n", length)
    }
    
    if tag[0] == 0 && length == 0 { // end of contents marker
      return nil // indefinite length (and hence end of contents markers) not permitted in DER
    }
    
    preceding_tags = append(preceding_tags, tag...)
    preceding_tags = append(preceding_tags, 0) // separator

    var contents Unmarshalled
    
    if constructed {
      idx++
      if length < 0 { // indefinite length
        return nil // indefinite length not permitted in DER
      } else if idx+length > len(der) { // length exceeds available data
        return nil
      } else {
        cont := UnmarshalDER(der[0:idx+length], idx)
        if cont == nil { // if an error occurred
          return nil
        }
        idx += length
        cont._Tag = int(tag[0])
        contents = cont
      }
    } else { // primitive
      idx++
      contents = &UnmarshalledPrimitive{_Tag:int(tag[0]), Data:der[idx:idx+length]}
      idx += length
    }
    
    tagstr1 := Rawtag(tag)
    tagstr2 := Rawtag(preceding_tags)
    if Debug {
      fmt.Fprintf(os.Stderr, "Storing as %x\n", tagstr2)
    }
    
    if _, ok := seq[tagstr1]; ok {
      delete(seq, tagstr1)
      conflict[tagstr1] = true
    } else {
      if !conflict[tagstr1] {
        seq[tagstr1] = contents
      }
    }
    seq[tagstr2] = contents
  }
  
  return &UnmarshalledConstructed{_Tag:-1, Data:seq}
}

/*
  Reads and returns the next DER encoded SEQUENCE from r,
  which may optionally be base64 encoded and may be preceded
  by "garbage". The returned data will always be DER bytes
  without preceding garbage and NOT base64 encoded.
  The SEQUENCE will only be recognized as valid if
  it does not contain APPLICATION or PRIVATE tags or
  tags >= 31.
  This function takes care not to read more bytes than
  necessary which allows the function to be called
  multiple times on a stream of concatenated SEQUENCEs.
*/
func ReadNextSEQUENCE(r io.Reader) ([]byte, error) {
  b := []byte{0}
  var err error
  var n int
  space := true
  var eaters deque.Deque
  for {
    n, err = r.Read(b)
    if err != nil {
      return nil, err
    }
    if n == 0 { 
      return nil, io.EOF
    }
    if b[0] == 0x30 { // SEQUENCE
      eaters.Push(newRawEater())
    } 
    if b[0] > ' ' {
      if space {
        eaters.Push(newBase64Eater())
      }
      space = false
    } else {
      space = true
    }
    
    for i:=0; i < eaters.Count(); {
      result := eaters.At(i).(eater).Eat(b[0])
      switch result {
        case -1: // error
          eaters.RemoveAt(i)
        case 0:  // ok, need more data
          i++
        case 1:  // done
          return eaters.At(i).(eater).Data(), nil
      }
    }
  }
}

/*
  Reads and returns the next DER-encoded private key from r,
  which may optionally be base64 encoded (PEM format)
  and may be preceded by "garbage" (PEM headers).
  This function takes care not to read more bytes than
  necessary which allows the function to be called
  multiple times on a stream of concatenated keys.
*/
func ReadNextKey(in io.Reader) (crypto.Signer, error) {
  data, err := ReadNextSEQUENCE(in)
  if err != nil {
    return nil, err
  }
  key1, err1 := x509.ParseECPrivateKey(data)
  key2, err2 := x509.ParsePKCS1PrivateKey(data)
  key3, err3 := x509.ParsePKCS8PrivateKey(data)
  if err1 == nil {
    return key1, nil
  }
  if err2 == nil {
    return key2, nil
  }
  if err3 != nil {
    return nil, err3
  }
  switch key := key3.(type){
    case *rsa.PrivateKey: return key, nil
    case *ecdsa.PrivateKey: return key, nil
  }
  return nil, fmt.Errorf("Unknown key type in PKCS8 container")
}


type eater interface {
  Data() []byte
  Eat(byte) int
}

type base64Eater struct {
  status int
  carry int
  daisy eater
}

func (e *base64Eater) Eat(b byte) int {
  if b <= ' ' || e.status != 0 { // ignore control characters; also exit if we have a status
    return e.status
  }
  carry_old := e.carry
  decoded := util.Base64DecodeString(string([]byte{b}), &e.carry)
  if len(decoded) == 0 {
    if carry_old == e.carry {  // no result and no state change => garbage
      e.status = -1
    }
  } else {
    for _, dec := range decoded {
      e.status = e.daisy.Eat(dec)
    }
  }
  
  return e.status
}

func (e *base64Eater) Data() []byte {
  return e.daisy.Data()
}

func newBase64Eater() eater {
  return &base64Eater{daisy:newRawEater()}
}

type rawEater struct {
  status int
  data []byte
  state int
  constructed bool
  length []int
  length_count int
  length_buffer int
}

func (e *rawEater) Data() []byte { return e.data }

func newRawEater() eater { return &rawEater{} }

func (e *rawEater) Eat(b byte) int {
  if e.status != 0 { return e.status }
  if e.state == 0 { // waiting for the initial 0x30
    if b != 0x30 {
      e.status = -1 // error
    } else {
      e.state = 1
      e.constructed = true
    }
  } else if e.state == 1 { // tag has been read, now read 1st length byte
    if b <= 127 { // short form length
      if len(e.length) > 0 && int(b) > e.length[len(e.length)-1]-1 { // -1 because the length byte we just parsed has not been subtracted yet
        // if new object doesn't fit into surrounding structure
        e.status = -1 // error
      } else {
        e.length = append(e.length, int(b) + 1) // + 1 because it will be decremented further below
        if e.constructed { 
          e.state = 3
        } else {
          e.state = 4
        }
      }
    } else {
      e.length_count = int(b) & 127
      if e.length_count == 0 || e.length_count > 2 {
        // illegal length: 0 or more than 64K
        e.status = -1
      }
      e.length_buffer = 0
      e.state = 2
    }
  } else if e.state == 2 { // reading long form length octets
    e.length_buffer <<= 8
    e.length_buffer  += int(b)
    e.length_count--
    if e.length_count == 0 {
      if len(e.length) > 0 && e.length_buffer > e.length[len(e.length)-1]-1 { // -1 because the length byte we just parsed has not been subtracted yet
        // if new object doesn't fit into surrounding structure
        e.status = -1 // error
      } else {
        e.length = append(e.length, e.length_buffer + 1) // + 1 because it will be decremented further below
        if e.constructed { 
          e.state = 3
        } else {
          e.state = 4
        }
      }
    }
  } else if e.state == 3 { // inside constructed, expecting tag byte
    if (b & 64) != 0 ||  // the structures we're interested in do not contain APPLICATION or PRIVATE tags
       (b & 31) == 31 {  // the structures we're interested in do not have tags >= 31
      e.status = -1
    }
    e.constructed = (b & 32 != 0)
    e.state = 1
  } else if e.state == 4 { // inside primitive, expecting data byte
    // nothing to do
  }
  
  e.data = append(e.data, b)
  
  for i := range e.length {
    e.length[i]--
  }
  
  for len(e.length) > 0 && e.length[len(e.length)-1] == 0 {
    e.length = e.length[0:len(e.length)-1]
    e.constructed = true
    e.state = 3
  }
  
  if len(e.length) == 0 {
    switch e.state {
      case 3: e.status = 1
      case 1,2: {} // still waiting for length of outermost SEQUENCE
      default: e.status = -1 // error
    }
  }
  
  return e.status
}

