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
  This file contains test instances of data structures from the asn1 package.
  They need to be in the asn1 package to have access to private fields.
  This data is only used in test/ programs.
*/

package asn1

var TestInstanceOmni = &Instance{
  basictype:SEQUENCE_OF,
  children:[]*Tree{
    &Tree{
      basictype:BOOLEAN,
      value:true,
    },
    &Tree{
      basictype:INTEGER,
      value:11,
      namedints:map[string]int{"dozen":12},
    },
    &Tree{
      basictype:INTEGER,
      value:12,
      namedints:map[string]int{"dozen":12},
    },
    &Tree{
      basictype:OBJECT_IDENTIFIER,
      value:[]int{1,2,3},
    },
    &Tree{
      basictype:OCTET_STRING,
      value:[]byte("Hallo\nWelt!\u0000"),
    },
    &Tree{
      basictype:BIT_STRING,
      value:[]bool{},
    },
    &Tree{
      basictype:BIT_STRING,
      value:[]bool{true},
    },
    &Tree{
      basictype:BIT_STRING,
      value:[]bool{true, false},
    },
    &Tree{
      basictype:BIT_STRING,
      value:[]bool{true, false, true},
      namedints:map[string]int{"first":0, "second":1, "third":2},
    },
    &Tree{
      basictype:BIT_STRING,
      value:[]bool{true, false, true},
      namedints:map[string]int{"second":1, "third":2},
    },
    &Tree{
      basictype:BIT_STRING,
      value:[]bool{true, true, true, false, false, false, true, true, 
                   false, true, true, true,  true,  true,  true, true, 
                   false, false, false, false, false, false, false, false,
                   true, false, false},
      namedints:map[string]int{"second":1, "third":2},
    },
    &Tree{
      basictype:SET,
      children:[]*Tree{
        &Tree{
          name: "god",
          basictype:BOOLEAN,
          value:false,
        },
      },
    },
    &Tree{
      basictype:SET,
      children:[]*Tree{
        &Tree{
          name: "god",
          basictype:BOOLEAN,
          value:false,
        },
        &Tree{
          name: "flyingSpaghettiMonster",
          basictype:BOOLEAN,
          value:true,
        },
      },
    },
  },
}
