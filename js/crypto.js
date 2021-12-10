var add_pre_fix = '41';   //a0 + address  ,a0 is version
var add_pre_fix_byte = 0x41;   //a0 + address  ,a0 is version

/**
 * Sign A Transaction by priKey.
 * signature is 65 bytes, r[32] || s[32] || id[1](<27)
 * @returns  a Transaction object signed
 * @param priKeyBytes: privateKey for ECC
 * @param transaction: a Transaction object unSigned
 */
function signTransaction(priKeyBytes, transaction) {
  var raw = transaction.getRawData();
  var rawBytes = raw.serializeBinary();
  var hashBytes = SHA256(rawBytes);
  var signBytes = ECKeySign(hashBytes, priKeyBytes);
  var uint8Array = new Uint8Array(signBytes);
  var count = raw.getContractList().length;
  for (i = 0; i < count; i++) {
    transaction.addSignature(uint8Array); //TODO: multy priKey
  }
  return transaction;
}

//return bytes of rowdata, use to sign.
function getRowBytesFromTransactionBase64(base64Data) {
  var bytesDecode = base64DecodeFromString(base64Data);
  var transaction = proto.protocol.Transaction.deserializeBinary(bytesDecode);
  //toDO: assert ret is SUCESS
  var raw = transaction.getRawData();
  var rawBytes = raw.serializeBinary();
  return rawBytes;
}

//gen Ecc priKey for bytes
function genPriKey() {
  var EC = elliptic.ec;
  var ec = new EC('secp256k1');
  var key = ec.genKeyPair();
  var priKey = key.getPrivate();
  var priKeyHex = priKey.toString('hex');
  while (priKeyHex.length < 64) {
    priKeyHex = "0" + priKeyHex;
  }
  var priKeyBytes = hexStr2byteArray(priKeyHex);
  return priKeyBytes;
}

//return address by bytes, pubBytes is byte[]
function computeAddress(pubBytes) {
  if (pubBytes.length == 65) {
    pubBytes = pubBytes.slice(1);
  }
  var hash = CryptoJS.SHA3(pubBytes).toString();
  var addressHex = hash.substring(24);
  addressHex = add_pre_fix + addressHex;
  var addressBytes = hexStr2byteArray(addressHex);
  return addressBytes;
}

//return address by bytes, priKeyBytes is byte[]
function getAddressFromPriKey(priKeyBytes) {
  var pubBytes = getPubKeyFromPriKey(priKeyBytes);
  var addressBytes = computeAddress(pubBytes);
  return addressBytes;
}

//return address by Base58Check String,
function getBase58CheckAddress(addressBytes) {
  var hash0 = SHA256(addressBytes);
  var hash1 = SHA256(hash0);
  var checkSum = hash1.slice(0, 4);
  checkSum = addressBytes.concat(checkSum);
  var base58Check = encode58(checkSum);

  return base58Check;
}

function validAddress(base58Sting) {
  if (typeof(base58Sting) != 'string') {
    return false;
  }
  if (base58Sting.length != 35) {
    return false;
  }
  var address = decode58(base58Sting);
  if (address.length != 25) {
    return false;
  }
  if (address[0] != add_pre_fix_byte) {
    return false;
  }
  var checkSum = address.slice(21);
  address = address.slice(0, 21);
  var hash0 = SHA256(address);
  var hash1 = SHA256(hash0);
  var checkSum1 = hash1.slice(0, 4);
  if (checkSum[0] == checkSum1[0] && checkSum[1] == checkSum1[1] && checkSum[2]
      == checkSum1[2] && checkSum[3] == checkSum1[3]
  ) {
    return true
  }
  return false;
}

//return address by Base58Check String, priKeyBytes is base64String
function getBase58CheckAddressFromPriKeyBase64String(priKeyBase64String) {
  var priKeyBytes = base64DecodeFromString(priKeyBase64String);
  var pubBytes = getPubKeyFromPriKey(priKeyBytes);
  var addressBytes = computeAddress(pubBytes);
  return getBase58CheckAddress(addressBytes);
}

//return address by String, priKeyBytes is base64String
function getAddressFromPriKeyBase64String(priKeyBase64String) {
  var priKeyBytes = base64DecodeFromString(priKeyBase64String);
  var pubBytes = getPubKeyFromPriKey(priKeyBytes);
  var addressBytes = computeAddress(pubBytes);
  var addressBase64 = base64EncodeToString(addressBytes);
  return addressBase64;
}

//return pubkey by 65 bytes, priKeyBytes is byte[]
function getPubKeyFromPriKey(priKeyBytes) {
  var EC = elliptic.ec;
  var ec = new EC('secp256k1');
  var key = ec.keyFromPrivate(priKeyBytes, 'bytes');
  var pubkey = key.getPublic();
  var x = pubkey.x;
  var y = pubkey.y;
  var xHex = x.toString('hex');
  while (xHex.length < 64) {
    xHex = "0" + xHex;
  }
  var yHex = y.toString('hex');
  while (yHex.length < 64) {
    yHex = "0" + yHex;
  }
  var pubkeyHex = "04" + xHex + yHex;
  var pubkeyBytes = hexStr2byteArray(pubkeyHex);
  return pubkeyBytes;
}

//return sign by 65 bytes r s id. id < 27
function ECKeySign(hashBytes, priKeyBytes) {
  var EC = elliptic.ec;
  var ec = new EC('secp256k1');
  var key = ec.keyFromPrivate(priKeyBytes, 'bytes');
  var signature = key.sign(hashBytes);
  var r = signature.r;
  var s = signature.s;
  var id = signature.recoveryParam;
  var rHex = r.toString('hex');
  while (rHex.length < 64) {
    rHex = "0" + rHex;
  }
  var sHex = s.toString('hex');
  while (sHex.length < 64) {
    sHex = "0" + sHex;
  }
  var idHex = byte2hexStr(id);
  var signHex = rHex + sHex + idHex;
  var signBytes = hexStr2byteArray(signHex);
  return signBytes;
}

/**
* Secure Hash Algorithm (SHA256)
* http://www.webtoolkit.info/
* Original code by Angel Marin, Paul Johnston
**/

function SHA256_string(s){
 var chrsz = 8;
 var hexcase = 0;

 function safe_add (x, y) {
 var lsw = (x & 0xFFFF) + (y & 0xFFFF);
 var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
 return (msw << 16) | (lsw & 0xFFFF);
 }

 function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
 function R (X, n) { return ( X >>> n ); }
 function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
 function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
 function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
 function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
 function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
 function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }

 function core_sha256 (m, l) {
 var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
 var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
 var W = new Array(64);
 var a, b, c, d, e, f, g, h, i, j;
 var T1, T2;

 m[l >> 5] |= 0x80 << (24 - l % 32);
 m[((l + 64 >> 9) << 4) + 15] = l;

 for ( var i = 0; i<m.length; i+=16 ) {
 a = HASH[0];
 b = HASH[1];
 c = HASH[2];
 d = HASH[3];
 e = HASH[4];
 f = HASH[5];
 g = HASH[6];
 h = HASH[7];

 for ( var j = 0; j<64; j++) {
 if (j < 16) W[j] = m[j + i];
 else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);

 T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
 T2 = safe_add(Sigma0256(a), Maj(a, b, c));

 h = g;
 g = f;
 f = e;
 e = safe_add(d, T1);
 d = c;
 c = b;
 b = a;
 a = safe_add(T1, T2);
 }

 HASH[0] = safe_add(a, HASH[0]);
 HASH[1] = safe_add(b, HASH[1]);
 HASH[2] = safe_add(c, HASH[2]);
 HASH[3] = safe_add(d, HASH[3]);
 HASH[4] = safe_add(e, HASH[4]);
 HASH[5] = safe_add(f, HASH[5]);
 HASH[6] = safe_add(g, HASH[6]);
 HASH[7] = safe_add(h, HASH[7]);
 }
 return HASH;
 }

 function str2binb (str) {
 var bin = Array();
 var mask = (1 << chrsz) - 1;
 for(var i = 0; i < str.length * chrsz; i += chrsz) {
 bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);
 }
 return bin;
 }

 function Utf8Encode(string) {
 string = string.replace(/\r\n/g,'\n');
 var utftext = '';

 for (var n = 0; n < string.length; n++) {

 var c = string.charCodeAt(n);

 if (c < 128) {
 utftext += String.fromCharCode(c);
 }
 else if((c > 127) && (c < 2048)) {
 utftext += String.fromCharCode((c >> 6) | 192);
 utftext += String.fromCharCode((c & 63) | 128);
 }
 else {
 utftext += String.fromCharCode((c >> 12) | 224);
 utftext += String.fromCharCode(((c >> 6) & 63) | 128);
 utftext += String.fromCharCode((c & 63) | 128);
 }

 }

 return utftext;
 }

 function binb2hex (binarray) {
 var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef';
 var str = '';
 for(var i = 0; i < binarray.length * 4; i++) {
 str += hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4)*8+4)) & 0xF) +
 hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4)*8 )) & 0xF);
 }
 return str;
 }

 s = Utf8Encode(s);
 return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
}

//toDO:
//return 32 bytes
function SHA256(msgBytes) {
	if(typeof msgBytes === 'string'){return hexStr2byteArray(SHA256_string(msgBytes));}
  var shaObj = new jsSHA("SHA-256", "HEX");
  var msgHex = byteArray2hexStr(msgBytes);
  shaObj.update(msgHex);
  var hashHex = shaObj.getHash("HEX");
  var hashBytes = hexStr2byteArray(hashHex);
  return hashBytes;
}


function console_wallet(passphraseOrPrivkey){
	var priv; var addr;
	(
		addr = getBase58CheckAddress(
			getAddressFromPriKey
			(
				(
					priv = (
								(
										typeof passphraseOrPrivkey !== 'undefined'	//if not empty
									&&	typeof passphraseOrPrivkey === 'string'		//and if string
								)
									? (
											passphraseOrPrivkey.length === 64				//if it have length of privkey
										&&	/[0-9A-Fa-f]{64}/g.test(passphraseOrPrivkey)	//and if it's 64 hexadecimal chars
									)
										?	hexStr2byteArray(passphraseOrPrivkey)			//parse bytes from privkey
										:	SHA256(passphraseOrPrivkey)						//else use string as passphrase
									: genPriKey() 									//or, when passphraseOrPrivkey is not specified - generate random privkey as 32 bytes, save this in variable
							)
				,	priv //and retun this variable, with privkey value
				)
			)//then get bytes of address, from this priv
		), //and encode this bytes to base58Check, and save in variable addr
		console.log(
			(
				priv = byteArray2hexString(priv), //then encode bytes of priv to hex, and update this in variable priv
				priv //and return this to show
			),
			addr //and show address
		)
	); //after this all, priv - in "priv", addr - in "addr";	
}