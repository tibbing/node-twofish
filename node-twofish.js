/*globals exports*/

(function twofish(exports) {

  var twofishAlgorithm = {};

  // debug methods and variables
  var NAME = "Twofish_Algorithm"
    , DEBUG = false
    , debuglevel = 0
    , debug = function (s) {
        if (DEBUG) {
          if (s) {
            console.log(">>> " + NAME + ": " + s);
          } else {
            console.log("");
          }
        }
      }
    , debugNoNewLine = function (s) {
        if (DEBUG) {
          process.stdout.write(s);
        }
      };

  // Constants and variables
  //...........................................................................
  var BLOCK_SIZE = 16 // bytes in a data-block
    , ROUNDS = 16
    , MAX_ROUNDS = 16 // max # rounds (for allocating subkeys)

    /* Subkey array indices */
    , INPUT_WHITEN = 0
    , OUTPUT_WHITEN = INPUT_WHITEN +  BLOCK_SIZE/4
    , ROUND_SUBKEYS = OUTPUT_WHITEN + BLOCK_SIZE/4 // 2*(# rounds)
    , TOTAL_SUBKEYS = ROUND_SUBKEYS + 2*MAX_ROUNDS
    , SK_STEP = 0x02020202
    , SK_BUMP = 0x01010101
    , SK_ROTL = 9;

  /** Fixed 8x8 permutation S-boxes */
  var P = [
    [  // p0
      0xA9, 0x67, 0xB3, 0xE8,
      0x04, 0xFD, 0xA3, 0x76,
      0x9A, 0x92, 0x80, 0x78,
      0xE4, 0xDD, 0xD1, 0x38,
      0x0D, 0xC6, 0x35, 0x98,
      0x18, 0xF7, 0xEC, 0x6C,
      0x43, 0x75, 0x37, 0x26,
      0xFA, 0x13, 0x94, 0x48,
      0xF2, 0xD0, 0x8B, 0x30,
      0x84, 0x54, 0xDF, 0x23,
      0x19, 0x5B, 0x3D, 0x59,
      0xF3, 0xAE, 0xA2, 0x82,
      0x63, 0x01, 0x83, 0x2E,
      0xD9, 0x51, 0x9B, 0x7C,
      0xA6, 0xEB, 0xA5, 0xBE,
      0x16, 0x0C, 0xE3, 0x61,
      0xC0, 0x8C, 0x3A, 0xF5,
      0x73, 0x2C, 0x25, 0x0B,
      0xBB, 0x4E, 0x89, 0x6B,
      0x53, 0x6A, 0xB4, 0xF1,
      0xE1, 0xE6, 0xBD, 0x45,
      0xE2, 0xF4, 0xB6, 0x66,
      0xCC, 0x95, 0x03, 0x56,
      0xD4, 0x1C, 0x1E, 0xD7,
      0xFB, 0xC3, 0x8E, 0xB5,
      0xE9, 0xCF, 0xBF, 0xBA,
      0xEA, 0x77, 0x39, 0xAF,
      0x33, 0xC9, 0x62, 0x71,
      0x81, 0x79, 0x09, 0xAD,
      0x24, 0xCD, 0xF9, 0xD8,
      0xE5, 0xC5, 0xB9, 0x4D,
      0x44, 0x08, 0x86, 0xE7,
      0xA1, 0x1D, 0xAA, 0xED,
      0x06, 0x70, 0xB2, 0xD2,
      0x41, 0x7B, 0xA0, 0x11,
      0x31, 0xC2, 0x27, 0x90,
      0x20, 0xF6, 0x60, 0xFF,
      0x96, 0x5C, 0xB1, 0xAB,
      0x9E, 0x9C, 0x52, 0x1B,
      0x5F, 0x93, 0x0A, 0xEF,
      0x91, 0x85, 0x49, 0xEE,
      0x2D, 0x4F, 0x8F, 0x3B,
      0x47, 0x87, 0x6D, 0x46,
      0xD6, 0x3E, 0x69, 0x64,
      0x2A, 0xCE, 0xCB, 0x2F,
      0xFC, 0x97, 0x05, 0x7A,
      0xAC, 0x7F, 0xD5, 0x1A,
      0x4B, 0x0E, 0xA7, 0x5A,
      0x28, 0x14, 0x3F, 0x29,
      0x88, 0x3C, 0x4C, 0x02,
      0xB8, 0xDA, 0xB0, 0x17,
      0x55, 0x1F, 0x8A, 0x7D,
      0x57, 0xC7, 0x8D, 0x74,
      0xB7, 0xC4, 0x9F, 0x72,
      0x7E, 0x15, 0x22, 0x12,
      0x58, 0x07, 0x99, 0x34,
      0x6E, 0x50, 0xDE, 0x68,
      0x65, 0xBC, 0xDB, 0xF8,
      0xC8, 0xA8, 0x2B, 0x40,
      0xDC, 0xFE, 0x32, 0xA4,
      0xCA, 0x10, 0x21, 0xF0,
      0xD3, 0x5D, 0x0F, 0x00,
      0x6F, 0x9D, 0x36, 0x42,
      0x4A, 0x5E, 0xC1, 0xE0
    ],
    [  // p1
      0x75, 0xF3, 0xC6, 0xF4,
      0xDB, 0x7B, 0xFB, 0xC8,
      0x4A, 0xD3, 0xE6, 0x6B,
      0x45, 0x7D, 0xE8, 0x4B,
      0xD6, 0x32, 0xD8, 0xFD,
      0x37, 0x71, 0xF1, 0xE1,
      0x30, 0x0F, 0xF8, 0x1B,
      0x87, 0xFA, 0x06, 0x3F,
      0x5E, 0xBA, 0xAE, 0x5B,
      0x8A, 0x00, 0xBC, 0x9D,
      0x6D, 0xC1, 0xB1, 0x0E,
      0x80, 0x5D, 0xD2, 0xD5,
      0xA0, 0x84, 0x07, 0x14,
      0xB5, 0x90, 0x2C, 0xA3,
      0xB2, 0x73, 0x4C, 0x54,
      0x92, 0x74, 0x36, 0x51,
      0x38, 0xB0, 0xBD, 0x5A,
      0xFC, 0x60, 0x62, 0x96,
      0x6C, 0x42, 0xF7, 0x10,
      0x7C, 0x28, 0x27, 0x8C,
      0x13, 0x95, 0x9C, 0xC7,
      0x24, 0x46, 0x3B, 0x70,
      0xCA, 0xE3, 0x85, 0xCB,
      0x11, 0xD0, 0x93, 0xB8,
      0xA6, 0x83, 0x20, 0xFF,
      0x9F, 0x77, 0xC3, 0xCC,
      0x03, 0x6F, 0x08, 0xBF,
      0x40, 0xE7, 0x2B, 0xE2,
      0x79, 0x0C, 0xAA, 0x82,
      0x41, 0x3A, 0xEA, 0xB9,
      0xE4, 0x9A, 0xA4, 0x97,
      0x7E, 0xDA, 0x7A, 0x17,
      0x66, 0x94, 0xA1, 0x1D,
      0x3D, 0xF0, 0xDE, 0xB3,
      0x0B, 0x72, 0xA7, 0x1C,
      0xEF, 0xD1, 0x53, 0x3E,
      0x8F, 0x33, 0x26, 0x5F,
      0xEC, 0x76, 0x2A, 0x49,
      0x81, 0x88, 0xEE, 0x21,
      0xC4, 0x1A, 0xEB, 0xD9,
      0xC5, 0x39, 0x99, 0xCD,
      0xAD, 0x31, 0x8B, 0x01,
      0x18, 0x23, 0xDD, 0x1F,
      0x4E, 0x2D, 0xF9, 0x48,
      0x4F, 0xF2, 0x65, 0x8E,
      0x78, 0x5C, 0x58, 0x19,
      0x8D, 0xE5, 0x98, 0x57,
      0x67, 0x7F, 0x05, 0x64,
      0xAF, 0x63, 0xB6, 0xFE,
      0xF5, 0xB7, 0x3C, 0xA5,
      0xCE, 0xE9, 0x68, 0x44,
      0xE0, 0x4D, 0x43, 0x69,
      0x29, 0x2E, 0xAC, 0x15,
      0x59, 0xA8, 0x0A, 0x9E,
      0x6E, 0x47, 0xDF, 0x34,
      0x35, 0x6A, 0xCF, 0xDC,
      0x22, 0xC9, 0xC0, 0x9B,
      0x89, 0xD4, 0xED, 0xAB,
      0x12, 0xA2, 0x0D, 0x52,
      0xBB, 0x02, 0x2F, 0xA9,
      0xD7, 0x61, 0x1E, 0xB4,
      0x50, 0x04, 0xF6, 0xC2,
      0x16, 0x25, 0x86, 0x56,
      0x55, 0x09, 0xBE, 0x91
    ]
  ];

  /**
   * Define the fixed p0/p1 permutations used in keyed S-box lookup.
   * By changing the following constant definitions, the S-boxes will
   * automatically get changed in the Twofish engine.
   */
  var P_00 = 1
    , P_01 = 0
    , P_02 = 0
    , P_03 = P_01 ^ 1
    , P_04 = 1
    , P_10 = 0
    , P_11 = 0
    , P_12 = 1
    , P_13 = P_11 ^ 1
    , P_14 = 0
    , P_20 = 1
    , P_21 = 1
    , P_22 = 0
    , P_23 = P_21 ^ 1
    , P_24 = 0
    , P_30 = 0
    , P_31 = 1
    , P_32 = 1
    , P_33 = P_31 ^ 1
    , P_34 = 1;

  /** Primitive polynomial for GF(256) */
  var GF256_FDBK =   0x169
    , GF256_FDBK_2 = 0x169 / 2
    , GF256_FDBK_4 = 0x169 / 4

    /** MDS matrix */
    , MDS = [ [], [], [], [] ]//new int[4][256] // blank final
    , RS_GF_FDBK = 0x14D // field generator
    , HEX_DIGITS = [
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
      ];
  
  // Static code - to intialise the MDS matrix
  //...........................................................................
  var initMds = function () {
    if (DEBUG) console.time('init mds');

    debug("Algorithm Name: " + NAME);
    debug("Electronic Codebook (ECB) Mode");

    //
    // precompute the MDS matrix
    //
    var m1 = []
      , mX = []
      , mY = []
      , i, j;

    for (i = 0; i < 256; i++) {
      j = P[0][i]       & 0xFF; // compute all the matrix elements
      m1[0] = j;
      mX[0] = Mx_X( j ) & 0xFF;
      mY[0] = Mx_Y( j ) & 0xFF;

      j = P[1][i]       & 0xFF;
      m1[1] = j;
      mX[1] = Mx_X( j ) & 0xFF;
      mY[1] = Mx_Y( j ) & 0xFF;

      MDS[0][i] = m1[P_00] <<  0 | // fill matrix w/ above elements
                  mX[P_00] <<  8 |
                  mY[P_00] << 16 |
                  mY[P_00] << 24;
      MDS[1][i] = mY[P_10] <<  0 |
                  mY[P_10] <<  8 |
                  mX[P_10] << 16 |
                  m1[P_10] << 24;
      MDS[2][i] = mX[P_20] <<  0 |
                  mY[P_20] <<  8 |
                  m1[P_20] << 16 |
                  mY[P_20] << 24;
      MDS[3][i] = mX[P_30] <<  0 |
                  m1[P_30] <<  8 |
                  mY[P_30] << 16 |
                  mX[P_30] << 24;
    }

    debug("==========");
    debug();
    debug("Static Data");
    debug();
    debug("MDS[0][]:"); for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(MDS[0][i*4+j])+", "); debug();}
    debug();
    debug("MDS[1][]:"); for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(MDS[1][i*4+j])+", "); debug();}
    debug();
    debug("MDS[2][]:"); for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(MDS[2][i*4+j])+", "); debug();}
    debug();
    debug("MDS[3][]:"); for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(MDS[3][i*4+j])+", "); debug();}
    debug();

    if (DEBUG) console.timeEnd('init mds');
  };

  var LFSR1 = function (x) {
    return (x >> 1) ^
      ((x & 0x01) != 0 ? GF256_FDBK_2 : 0);
  };
  
  var LFSR2 = function (x) {
    return (x >> 2) ^
      ((x & 0x02) != 0 ? GF256_FDBK_2 : 0) ^
      ((x & 0x01) != 0 ? GF256_FDBK_4 : 0);
  };
  
  var Mx_1 = function (x) { return x; }
  var Mx_X = function (x) { return x ^ LFSR2(x); }            // 5B
  var Mx_Y = function (x) { return x ^ LFSR1(x) ^ LFSR2(x); } // EF

  // Basic API methods
  //...........................................................................
  
  /**
   * Expand a user-supplied key material into a session key.
   *
   * @param key  The 64/128/192/256-bit user-key to use.
   * @return  This cipher's round keys.
   * @exception  InvalidKeyException  If the key is invalid.
   */
  var makeKey = twofishAlgorithm.makeKey = function (k) {
    if (!k || !k.length) {
      throw new InvalidKeyException("Empty key");
    }
    var length = k.length;
    if (!(length == 8 || length == 16 || length == 24 || length == 32)) {
      throw new InvalidKeyException("Incorrect key length");
    }
    debug("Intermediate Session Key Values");
    debug();
    debug("Raw="+toString(k));
    debug();

    var k64Cnt = length / 8
      , subkeyCnt = ROUND_SUBKEYS + 2*ROUNDS
      , k32e = new Array(4) // even 32-bit entities
      , k32o = new Array(4) // odd 32-bit entities
      , sBoxKey = new Array(4);

    //
    // split user key material into even and odd 32-bit entities and
    // compute S-box keys using (12, 8) Reed-Solomon code over GF(256)
    //
    var i, j, offset = 0;

    for (i = 0, j = k64Cnt-1; i < 4 && offset < length; i++, j--) {
      k32e[i] = (k[offset++] & 0xFF)       |
                (k[offset++] & 0xFF) <<  8 |
                (k[offset++] & 0xFF) << 16 |
                (k[offset++] & 0xFF) << 24;
      k32o[i] = (k[offset++] & 0xFF)       |
                (k[offset++] & 0xFF) <<  8 |
                (k[offset++] & 0xFF) << 16 |
                (k[offset++] & 0xFF) << 24;
      sBoxKey[j] = RS_MDS_Encode( k32e[i], k32o[i] ); // reverse order
    }

    // compute the round decryption subkeys for PHT. these same subkeys
    // will be used in encryption but will be applied in reverse order.
    var q, A, B;
    var subKeys = new Array(subkeyCnt);
    for (i = q = 0; i < subkeyCnt/2; i++, q += SK_STEP) {
      A = F32( k64Cnt, q        , k32e ); // A uses even key entities
      B = F32( k64Cnt, q+SK_BUMP, k32o ); // B uses odd  key entities
      B = B << 8 | B >>> 24;
      A += B;
      subKeys[2*i    ] = A;               // combine with a PHT
      A += B;
      subKeys[2*i + 1] = A << SK_ROTL | A >>> (32-SK_ROTL);
    }
    //
    // fully expand the table for speed
    //
    var k0 = sBoxKey[0]
      , k1 = sBoxKey[1]
      , k2 = sBoxKey[2]
      , k3 = sBoxKey[3]
      , b0, b1, b2, b3
      , sBox = new Array(4 * 256);

    for (i = 0; i < 256; i++) {
      b0 = b1 = b2 = b3 = i;
      switch (k64Cnt & 3) {
        case 1:
            sBox[      2*i  ] = MDS[0][(P[P_01][b0] & 0xFF) ^ _b0(k0)];
            sBox[      2*i+1] = MDS[1][(P[P_11][b1] & 0xFF) ^ _b1(k0)];
            sBox[0x200+2*i  ] = MDS[2][(P[P_21][b2] & 0xFF) ^ _b2(k0)];
            sBox[0x200+2*i+1] = MDS[3][(P[P_31][b3] & 0xFF) ^ _b3(k0)];
            break;
        case 0: // same as 4
            b0 = (P[P_04][b0] & 0xFF) ^ _b0(k3);
            b1 = (P[P_14][b1] & 0xFF) ^ _b1(k3);
            b2 = (P[P_24][b2] & 0xFF) ^ _b2(k3);
            b3 = (P[P_34][b3] & 0xFF) ^ _b3(k3);
        case 3:
            b0 = (P[P_03][b0] & 0xFF) ^ _b0(k2);
            b1 = (P[P_13][b1] & 0xFF) ^ _b1(k2);
            b2 = (P[P_23][b2] & 0xFF) ^ _b2(k2);
            b3 = (P[P_33][b3] & 0xFF) ^ _b3(k2);
        case 2: // 128-bit keys
            sBox[      2*i  ] = MDS[0][(P[P_01][(P[P_02][b0] & 0xFF) ^ _b0(k1)] & 0xFF) ^ _b0(k0)];
            sBox[      2*i+1] = MDS[1][(P[P_11][(P[P_12][b1] & 0xFF) ^ _b1(k1)] & 0xFF) ^ _b1(k0)];
            sBox[0x200+2*i  ] = MDS[2][(P[P_21][(P[P_22][b2] & 0xFF) ^ _b2(k1)] & 0xFF) ^ _b2(k0)];
            sBox[0x200+2*i+1] = MDS[3][(P[P_31][(P[P_32][b3] & 0xFF) ^ _b3(k1)] & 0xFF) ^ _b3(k0)];
      }
    }

    var sessionKey = [ sBox, subKeys ];

    debug("S-box[]:");
    for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(sBox[i*4+j])+", "); debug();}
    debug();
    for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(sBox[256+i*4+j])+", "); debug();}
    debug();
    for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(sBox[512+i*4+j])+", "); debug();}
    debug();
    for(i=0;i<64;i++) { for(j=0;j<4;j++) debugNoNewLine("0x"+intToString(sBox[768+i*4+j])+", "); debug();}
    debug();
    debug("User (odd, even) keys  --> S-Box keys:");
    for(i=0;i<k64Cnt;i++) { debug("0x"+intToString(k32o[i])+"  0x"+intToString(k32e[i])+" --> 0x"+intToString(sBoxKey[k64Cnt-1-i])); }
    debug();
    debug("Round keys:");
    for(i=0;i<ROUND_SUBKEYS + 2*ROUNDS;i+=2) { debug("0x"+intToString(subKeys[i])+"  0x"+intToString(subKeys[i+1])); }
    debug();

    return sessionKey;
  };

  /**
   * Encrypt exactly one block of plaintext.
   *
   * @param input      The plaintext.
   * @param inOffset   Index of in from which to start considering data.
   * @param sessionKey  The session key to use for encryption.
   * @return The ciphertext generated from a plaintext using the session key.
   */
  var blockEncrypt = twofishAlgorithm.blockEncrypt = function (input, inOffset, sessionKey) {
    debug("blockEncrypt("+input+", "+inOffset+", "+sessionKey+")");
    // extract S-box and session key
    var sBox = sessionKey[0]
      , sKey = sessionKey[1];

    debug("PT="+toString(input, inOffset, BLOCK_SIZE));

    var x0 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;
    var x1 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;
    var x2 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;
    var x3 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;

    x0 ^= sKey[INPUT_WHITEN    ];
    x1 ^= sKey[INPUT_WHITEN + 1];
    x2 ^= sKey[INPUT_WHITEN + 2];
    x3 ^= sKey[INPUT_WHITEN + 3];
    
    debug("PTw="+intToString(x0)+intToString(x1)+intToString(x2)+intToString(x3));

    var t0, t1
      , k = ROUND_SUBKEYS;
      
    for (var R = 0; R < ROUNDS; R += 2) {
      t0 = Fe32( sBox, x0, 0 );
      t1 = Fe32( sBox, x1, 3 );
      x2 ^= t0 + t1 + sKey[k++];
      x2  = x2 >>> 1 | x2 << 31;
      x3  = x3 << 1 | x3 >>> 31;
      x3 ^= t0 + 2*t1 + sKey[k++];
    
      debug("CT"+(R)+"="+intToString(x0)+intToString(x1)+intToString(x2)+intToString(x3));

      t0 = Fe32( sBox, x2, 0 );
      t1 = Fe32( sBox, x3, 3 );
      x0 ^= t0 + t1 + sKey[k++];
      x0  = x0 >>> 1 | x0 << 31;
      x1  = x1 << 1 | x1 >>> 31;
      x1 ^= t0 + 2*t1 + sKey[k++];
    
      debug("CT"+(R+1)+"="+intToString(x0)+intToString(x1)+intToString(x2)+intToString(x3));
    }
    x2 ^= sKey[OUTPUT_WHITEN    ];
    x3 ^= sKey[OUTPUT_WHITEN + 1];
    x0 ^= sKey[OUTPUT_WHITEN + 2];
    x1 ^= sKey[OUTPUT_WHITEN + 3];

    debug("CTw="+intToString(x0)+intToString(x1)+intToString(x2)+intToString(x3));

    var result = [
      x2, (x2 >>> 8), (x2 >>> 16), (x2 >>> 24),
      x3, (x3 >>> 8), (x3 >>> 16), (x3 >>> 24),
      x0, (x0 >>> 8), (x0 >>> 16), (x0 >>> 24),
      x1, (x1 >>> 8), (x1 >>> 16), (x1 >>> 24),
    ];

    debug("CT="+toString(result));
    debug();
    debug("blockEncrypt()");

    return result;
  };

  /**
   * Decrypt exactly one block of ciphertext.
   *
   * @param input      The ciphertext.
   * @param inOffset   Index of in from which to start considering data.
   * @param sessionKey  The session key to use for decryption.
   * @return The plaintext generated from a ciphertext using the session key.
   */
  var blockDecrypt = twofishAlgorithm.blockDecrypt = function (input, inOffset, sessionKey) {
    debug("blockDecrypt("+input+", "+inOffset+", "+sessionKey+")");
    // extract S-box and session key
    var sBox = sessionKey[0]
      , sKey = sessionKey[1];
  
    debug("CT="+toString(input, inOffset, BLOCK_SIZE));
  
    var x2 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;
    var x3 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;
    var x0 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;
    var x1 = (input[inOffset++] & 0xFF)       |
            (input[inOffset++] & 0xFF) <<  8 |
            (input[inOffset++] & 0xFF) << 16 |
            (input[inOffset++] & 0xFF) << 24;
  
    x2 ^= sKey[OUTPUT_WHITEN    ];
    x3 ^= sKey[OUTPUT_WHITEN + 1];
    x0 ^= sKey[OUTPUT_WHITEN + 2];
    x1 ^= sKey[OUTPUT_WHITEN + 3];

    debug("CTw="+intToString(x2)+intToString(x3)+intToString(x0)+intToString(x1));
  
    var k = ROUND_SUBKEYS + 2*ROUNDS - 1
      , t0, t1;

    for (var R = 0; R < ROUNDS; R += 2) {
      t0 = Fe32( sBox, x2, 0 );
      t1 = Fe32( sBox, x3, 3 );
      x1 ^= t0 + 2*t1 + sKey[k--];
      x1  = x1 >>> 1 | x1 << 31;
      x0  = x0 << 1 | x0 >>> 31;
      x0 ^= t0 + t1 + sKey[k--];
    
      debug("PT"+(ROUNDS-R)+"="+intToString(x2)+intToString(x3)+intToString(x0)+intToString(x1));
  
      t0 = Fe32( sBox, x0, 0 );
      t1 = Fe32( sBox, x1, 3 );
      x3 ^= t0 + 2*t1 + sKey[k--];
      x3  = x3 >>> 1 | x3 << 31;
      x2  = x2 << 1 | x2 >>> 31;
      x2 ^= t0 + t1 + sKey[k--];

      debug("PT"+(ROUNDS-R-1)+"="+intToString(x2)+intToString(x3)+intToString(x0)+intToString(x1));
    }
    x0 ^= sKey[INPUT_WHITEN    ];
    x1 ^= sKey[INPUT_WHITEN + 1];
    x2 ^= sKey[INPUT_WHITEN + 2];
    x3 ^= sKey[INPUT_WHITEN + 3];

    debug("PTw="+intToString(x2)+intToString(x3)+intToString(x0)+intToString(x1));
  
    var result = [
      x0, (x0 >>> 8), (x0 >>> 16), (x0 >>> 24), 
      x1, (x1 >>> 8), (x1 >>> 16), (x1 >>> 24), 
      x2, (x2 >>> 8), (x2 >>> 16), (x2 >>> 24), 
      x3, (x3 >>> 8), (x3 >>> 16), (x3 >>> 24),
    ];

    debug("PT="+toString(result));
    debug("blockDecrypt()");

    return result;
  };

  // own methods
  //...........................................................................

  var _b0 = function(x) { return  x         & 0xFF; }
  var _b1 = function(x) { return (x >>>  8) & 0xFF; }
  var _b2 = function(x) { return (x >>> 16) & 0xFF; }
  var _b3 = function(x) { return (x >>> 24) & 0xFF; }
  
  /**
   * Use (12, 8) Reed-Solomon code over GF(256) to produce a key S-box
   * 32-bit entity from two key material 32-bit entities.
   *
   * @param  k0  1st 32-bit entity.
   * @param  k1  2nd 32-bit entity.
   * @return  Remainder polynomial generated using RS code
   */
  var RS_MDS_Encode = function(k0, k1) {
    var r = k1;
    for (var i = 0; i < 4; i++) // shift 1 byte at a time
      r = RS_rem( r );
    r ^= k0;
    for (var i = 0; i < 4; i++)
      r = RS_rem( r );
    return r;
  };
  
  /*
  * Reed-Solomon code parameters: (12, 8) reversible code:<p>
  * <pre>
  *   g(x) = x**4 + (a + 1/a) x**3 + a x**2 + (a + 1/a) x + 1
  * </pre>
  * where a = primitive root of field generator 0x14D
  */
  var RS_rem = function (x) {
    var b  =  (x >>> 24) & 0xFF;
    var g2 = ((b  <<  1) ^ ( (b & 0x80) != 0 ? RS_GF_FDBK : 0 )) & 0xFF;
    var g3 =  (b >>>  1) ^ ( (b & 0x01) != 0 ? (RS_GF_FDBK >>> 1) : 0 ) ^ g2 ;
    var result = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
    return result;
  };
  
  var F32 = function (k64Cnt, x, k32) {
    var b0 = _b0(x);
    var b1 = _b1(x);
    var b2 = _b2(x);
    var b3 = _b3(x);
    var k0 = k32[0];
    var k1 = k32[1];
    var k2 = k32[2];
    var k3 = k32[3];
  
    var result = 0;
    switch (k64Cnt & 3) {
      case 1:
        result =
            MDS[0][(P[P_01][b0] & 0xFF) ^ _b0(k0)] ^
            MDS[1][(P[P_11][b1] & 0xFF) ^ _b1(k0)] ^
            MDS[2][(P[P_21][b2] & 0xFF) ^ _b2(k0)] ^
            MDS[3][(P[P_31][b3] & 0xFF) ^ _b3(k0)];
        break;
      case 0:  // same as 4
        b0 = (P[P_04][b0] & 0xFF) ^ _b0(k3);
        b1 = (P[P_14][b1] & 0xFF) ^ _b1(k3);
        b2 = (P[P_24][b2] & 0xFF) ^ _b2(k3);
        b3 = (P[P_34][b3] & 0xFF) ^ _b3(k3);
      case 3:
        b0 = (P[P_03][b0] & 0xFF) ^ _b0(k2);
        b1 = (P[P_13][b1] & 0xFF) ^ _b1(k2);
        b2 = (P[P_23][b2] & 0xFF) ^ _b2(k2);
        b3 = (P[P_33][b3] & 0xFF) ^ _b3(k2);
      case 2:                             // 128-bit keys (optimize for this case)
        result =
            MDS[0][(P[P_01][(P[P_02][b0] & 0xFF) ^ _b0(k1)] & 0xFF) ^ _b0(k0)] ^
            MDS[1][(P[P_11][(P[P_12][b1] & 0xFF) ^ _b1(k1)] & 0xFF) ^ _b1(k0)] ^
            MDS[2][(P[P_21][(P[P_22][b2] & 0xFF) ^ _b2(k1)] & 0xFF) ^ _b2(k0)] ^
            MDS[3][(P[P_31][(P[P_32][b3] & 0xFF) ^ _b3(k1)] & 0xFF) ^ _b3(k0)];
        break;
    }
    return result;
  };
  
  var Fe32 = function (sBox, x, R) {
    return sBox[        2*_b(x, R  )    ] ^
          sBox[        2*_b(x, R+1) + 1] ^
          sBox[0x200 + 2*_b(x, R+2)    ] ^
          sBox[0x200 + 2*_b(x, R+3) + 1];
  };

  var _b = function (x, N) {
    var result = 0;
    switch (N%4) {
      case 0: result = _b0(x); break;
      case 1: result = _b1(x); break;
      case 2: result = _b2(x); break;
      case 3: result = _b3(x); break;
    }
    return result;
  };
    
  /** @return The length in bytes of the Algorithm input block. */
  var blockSize = twofishAlgorithm.blockSize = function () { return BLOCK_SIZE; }

  var utils = {};
  /**
   * Returns a string of 8 hexadecimal digits (most significant
   * digit first) corresponding to the integer <i>n</i>, which is
   * treated as unsigned.
   */
  var intToString = utils.intToString = function (n) {
    const buf = [];
    for (var i = 7; i >= 0; i--) {
      buf[i] = HEX_DIGITS[n & 0x0F];
      n >>>= 4;
    }
    return buf.join('');
  };

  /**
   * Returns a string of hexadecimal digits from a byte array. Each
   * byte is converted to 2 hex symbols.
   */
  var toString = utils.toString = function (ba, offset, length) {
    offset = offset || 0;
    length = length || ba.length;

    var buf = new Array(length * 2);
    for (var i = offset, j = 0, k; i < offset+length; ) {
      k = ba[i++];
      buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
      buf[j++] = HEX_DIGITS[ k      & 0x0F];
    }
    return buf.join('');
  };

  twofishAlgorithm.utils = utils;

  var InvalidKeyException = function (value) {
    this.value = value;
    this.message = "Invalid key Exception ";
    this.toString = function() {
        return this.value + this.message
    };
  }

  initMds();

  const defaultOpts = {
    "blockSize": 16
  };

  var twofishCypher = {};

  /**
   * encrypt the given message
   * @param input message to encrypt. Should be a non-null string
   * @param keyText to use for encryption
   * @return encrypted message, or throw an error
   */
  twofishCypher.encrypt = function encrypt (input, keyText) {
    if (!input) {
      throw new Error('must be given valid input');
    }
    input = input + "";
    keyText = keyText || process.env.KEY;
    
    const buf = new Buffer(input)
    var key = twofishAlgorithm.makeKey(new Buffer(keyText))
      , blockSize = defaultOpts.blockSize
      , inputLengthModulo = buf.length % blockSize
      , paddedLength = buf.length + (inputLengthModulo !== 0 && (blockSize - inputLengthModulo))
      , outs = new Buffer(paddedLength);

    for (var i = 0; i < paddedLength; i += blockSize) {
      var encrypted = twofishAlgorithm.blockEncrypt(buf, i, key);
      for (var j = 0; j < encrypted.length; j++) {
        outs[i + j] = encrypted[j];
      }
    }

    return bytesToHexString(outs, 0, outs.length);
  }

  /**
   * decrypt the given message. encrypted message size must be divisible by the default block size
   * @param input encrypted message. Should be a hexidecimal string with length divisible by 16, as generated by encrypt
   * @param keyText to use for decryption
   * @return decrypted message, or throw an error
   */
  twofishCypher.decrypt = function decrypt (input, keyText) {
    keyText = keyText || process.env.KEY;
    const buf = new Buffer(hexStringToBytes(input))
    var key = twofishAlgorithm.makeKey(new Buffer(keyText))
      , blockSize = defaultOpts.blockSize
      , outs = new Buffer(buf.length)
      , lastSigIndex;

    if ((buf.length % blockSize) !== 0) {
      throw new Error("input message size is " + buf.length + " which should be divisible by " + blockSize);
    }
    for (var i = 0; i < buf.length; i += blockSize) {
      var decrypted = twofishAlgorithm.blockDecrypt(buf, i, key);
      for (var j = 0; j < decrypted.length; j++) {
        outs[i + j] = decrypted[j];
      }
    }
    // reduce toString length to exclude NUL
    lastSigIndex = outs.length;
    for (var i = outs.length - 1; i >= 0; i--) {
      if (outs[i] === 0) {
        lastSigIndex = i;
      }
    }
    return outs.toString('utf8', 0, lastSigIndex);
  };

  /**
   * Converts raw bytes into a printable string.
   * <p>
   * Precondition: input is non-null.<br>
   * Precondition: index is greater than or equal to zero.<br>
   * Precondition: (index + length) is less than or equal to input.length.
   */
  var bytesToHexString = function (input, index, length) {
    if (!input) {
        throw new Error("input cannot be null");
    }
    if (index < 0) {
        throw new Error("index must be positive value");
    }
    if ((index + length) > input.length) {
        throw new Error("input process must be within range");
    }

    var sb = "";

    for (var i = index; i < (index + length); ++i) {
      var val = input.readInt8(i) + 128;

      if (val <= 15) {
        sb += "0";
      }
      sb += val.toString(16);
    }

    return sb;
  };

  /**
   * Converts a hex string (presumably from bytesToHexString())
   * to a raw byte array.
   * <p>
   * Precondition: input string is non-null.
   */
  var hexStringToBytes = function(input) {
      if (!input) {
          throw new Error("input cannot be null");
      }

      var len = input.length;
      var outs = new Array(len / 2);

      for (var i = 0, y = 0; i < len; i += 2, ++y) {
        outs[y] = parseInt(input.substring(i, i + 2), 16) - 128;
      }

      return outs;
  };

  exports.twofish = function twofish() {
    return {
      'encrypt': twofishCypher.encrypt,
      'decrypt': twofishCypher.decrypt,
    };
  };

}(typeof exports === 'undefined' ? this : exports));

