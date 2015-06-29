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
  This file contains the code to create an instance of a type from asn1.Definitions.
*/

package asn1

import (
         "fmt"
       )

// Creates an instance of the type called typename whose definition has to be
// parsed from ASN.1 source by the Parse() method.
// data is the value to be filled into the instance. The value's type must correspond to
// the ASN.1 definition of typename according to the following rules:
// SEQUENCE/SET/CHOICE => map[string]interface{} where the keys match the ASN.1 field names
// SEQUENCE_OF/SET_OF => []interface{}
// OCTET_STRING => string or []byte
// BOOLEAN => bool or string that compares (case-insensitive) to "false" or "true"
// INTEGER => int or string that either parses as an integer or compares (CASE-SENSITIVE) to
//            one of the named numbers for from the ASN.1 source for the respective context.
// ENUMERATED => like INTEGER above, but it is an error if the number does not match one of
//               the named numbers from the ASN.1 source for the respective context.
// BIT_STRING => Option 1: a string that is composed either just of "0" and "1" characters or
//               contains a list of words from the bit names from the ASN.1 source where
//               the words may be separated by any sequence of characters not from the
//               set [0-9a-zA-Z-].
//               Option 2: a []byte. This is limited to bit strings that are a multiple of
//               8 bits long.
//               Option 3: a []bool
// OBJECT_IDENTIFIER => []int or a string of integers separated by arbitrary sequences of
//                      non-digit characters, e.g. "1.2.3" or "1 2 3" or even "{1 foo(2) 3}"
// ANY => bool (encoded as BOOLEAN), int (encoded as INTEGER), []int (encoded as OBJECT IDENTIFIER),
//        []byte (encoded as OCTET STRING), []interface{} (encoded as SEQUENCE OF ANY),
//        string (encoded as some character string type, typically UTF8String),
//        []bool (encoded as BIT STRING)
func (d *Definitions) Instantiate(typename string, data interface{}) (*Instance, error) {
  return nil, nil
}

// Returns an instance of the value called valuename whose definition has to be
// parsed from ASN.1 source by the Parse() method.
func (d *Definitions) Value(valuename string) (*Instance, error) {
  v, ok := d.valuedefs[valuename]
  if !ok {
    return nil, fmt.Errorf("Value %v is undefined", valuename)
  }
  // children are not handled because compound value definitions are not supported, so no value can have children.
  return &Instance{nodetype:instanceNode, tag:v.tag, name:valuename, typename:v.typename, basictype:v.basictype, value:v.value, namedints:v.namedints, src:v.src, pos:v.pos}, nil
}
