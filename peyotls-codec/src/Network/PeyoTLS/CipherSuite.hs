{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.CipherSuite (
	CipherSuite(..), KeyEx(..), BulkEnc(..)) where

import Control.Arrow (first, (***))
import Data.Word (Word8)
import Data.String (IsString(..))

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

modNm :: String
modNm = "Network.PeyoTLS.CipherSuite"

-- | RFC 5246 7.4.1.2. Client Hello
--
-- @
-- uint8 CipherSuite[2];
-- @
--
-- RFC 5246 A.5. The Cipher Suite
--
-- @
-- CipherSuite TLS_NULL_WITH_NULL_NULL		= { 0x00, 0x00 };
-- CipherSuite TLS_RSA_WITH_NULL_MD5		= { 0x00, 0x01 };
-- CipherSuite TLS_RSA_WITH_NULL_SHA		= { 0x00, 0x02 };
-- CipherSuite TLS_RSA_WITH_NULL_SHA256		= { 0x00, 0x3B };
-- CipherSuite TLS_RSA_WITH_RC4_128_MD5		= { 0x00, 0x04 };
-- CipherSuite TLS_RSA_WITH_RC4_128_SHA		= { 0x00, 0x05 };
-- CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA	= { 0x00, 0x0A };
-- CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA	= { 0x00, 0x2F };
-- CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA	= { 0x00, 0x35 };
-- CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256	= { 0x00, 0x3C };
-- CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256	= { 0x00, 0x3D };
-- @
--
-- @
-- CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA	= { 0x00, 0x0D };
-- CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA	= { 0x00, 0x10 };
-- CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA	= { 0x00, 0x13 };
-- CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA	= { 0x00, 0x16 };
-- CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA	= { 0x00, 0x30 };
-- CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA	= { 0x00, 0x31 };
-- CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA	= { 0x00, 0x32 };
-- CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA	= { 0x00, 0x33 };
-- CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA	= { 0x00, 0x36 };
-- CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA	= { 0x00, 0x37 };
-- CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA	= { 0x00, 0x38 };
-- CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA	= { 0x00, 0x39 };
-- CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA256	= { 0x00, 0x3E };
-- CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA256	= { 0x00, 0x3F };
-- CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA256= { 0x00, 0x40 };
-- CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256= { 0x00, 0x67 };
-- CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA256	= { 0x00, 0x68 };
-- CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA256	= { 0x00, 0x69 };
-- CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA256= { 0x00, 0x6A };
-- CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256= { 0x00, 0x6B };
-- @
--
-- @
-- CipherSuite TLS_DH_anon_WITH_RC4_128_MD5	= { 0x00, 0x00 };
-- CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA	= { 0x00, 0x00 };
-- CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA	= { 0x00, 0x00 };
-- CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA	= { 0x00, 0x00 };
-- CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA256= { 0x00, 0x00 };
-- CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA256= { 0x00, 0x00 };
-- @
--
-- RFC 4492 6. Cipher Suites
--
-- @
-- CipherSuite TLS_ECDH_ECDSA_WITH_NULL_SHA		= { 0xC0, 0x01 };
-- CipherSuite TLS_ECDH_ECDSA_WITH_RC4_128_SHA		= { 0xC0, 0x02 };
-- CipherSuite TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA	= { 0xC0, 0x03 };
-- CipherSuite TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA	= { 0xC0, 0x04 };
-- CipherSuite TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA	= { 0xC0, 0x05 };
-- @
--
-- @
-- CipyherSuite TLS_ECDHE_ECDSA_WITH_NULL_SHA		= { 0xC0, 0x06 };
-- CipyherSuite TLS_ECDHE_ECDSA_WITH_RC4_128_SHA		= { 0xC0, 0x07};
-- CipyherSuite TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA	= { 0xC0, 0x08 };
-- CipyherSuite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	= { 0xC0, 0x09 };
-- CipyherSuite TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	= { 0xC0, 0x0A };
-- @
--
-- @
-- CipherSuite TLS_ECDH_RSA_WITH_NULL_SHA			= { 0xC0, 0x0B };
-- CipherSuite TLS_ECDH_RSA_WITH_RC4_128_SHA		= { 0xC0, 0x0C };
-- CipherSuite TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA		= { 0xC0, 0x0D };
-- CipherSuite TLS_ECDH_RSA_WITH_AES_128_CBC_SHA		= { 0xC0, 0x0E };
-- CipherSuite TLS_ECDH_RSA_WITH_AES_256_CBC_SHA		= { 0xC0, 0x0F };
-- @
--
-- @
-- CipherSuite TLS_ECDHE_RSA_WITH_NULL_SHA		= { 0xC0, 0x10 };
-- CipherSuite TLS_ECDHE_RSA_WITH_RC4_128_SHA		= { 0xC0, 0x11 };
-- CipherSuite TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA	= { 0xC0, 0x12 };
-- CipherSuite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA		= { 0xC0, 0x13 };
-- CipherSuite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA		= { 0xC0, 0x14 };
-- @
--
-- @
-- CipherSuite TLS_ECDH_anon_WITH_NULL_SHA		= { 0xC0, 0x15 };
-- CipherSuite TLS_ECDH_anon_WITH_RC4_128_SHA		= { 0xC0, 0x16 };
-- CipherSuite TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA	= { 0xC0, 0x17 };
-- CipherSuite TLS_ECDH_anon_WITH_AES_128_CBC_SHA		= { 0xC0, 0x18 };
-- CipherSuite TLS_ECDH_anon_WITH_AES_256_CBC_SHA		= { 0xC0, 0x19 };
-- @
--
-- RFC 5746 3.3. Renegotiation Protection Request Signaling Cipher Suite Value
--
-- @
-- CipherSuite TLS_EMPTY_RENEGOTIATION_INFO_SCSV	= {0x00, 0xFF}
-- @

data CipherSuite
	= CipherSuite KeyEx BulkEnc
	| EMPTY_RENEGOTIATION_INFO
	| CipherSuiteRaw Word8 Word8
	deriving (Show, Read, Eq)

data KeyEx = RSA | DHE_RSA | ECDHE_RSA | ECDHE_ECDSA | KE_NULL
	deriving (Show, Read, Eq)

data BulkEnc = AES_128_CBC_SHA | AES_128_CBC_SHA256 | BE_NULL
	deriving (Show, Read, Eq)


instance B.Bytable CipherSuite where
	decode = decodeCs
	encode = encodeCs

decodeCs :: BS.ByteString -> Either String CipherSuite
decodeCs bs = case BS.unpack bs of
	[w1, w2] -> Right $ case (w1, w2) of
		(0x00, 0x00) -> CipherSuite KE_NULL BE_NULL
		(0x00, 0x2f) -> CipherSuite RSA AES_128_CBC_SHA
		(0x00, 0x33) -> CipherSuite DHE_RSA AES_128_CBC_SHA
		(0x00, 0x3c) -> CipherSuite RSA AES_128_CBC_SHA256
		(0x00, 0x67) -> CipherSuite DHE_RSA AES_128_CBC_SHA256
		(0xc0, 0x09) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA
		(0xc0, 0x13) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA
		(0xc0, 0x23) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256
		(0xc0, 0x27) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA256
		(0x00, 0xff) -> EMPTY_RENEGOTIATION_INFO
		_ -> CipherSuiteRaw w1 w2
	_ -> Left $ modNm ++ ".decodeCs: not 2 byte"

encodeCs :: CipherSuite -> BS.ByteString
encodeCs (CipherSuite KE_NULL BE_NULL) = "\x00\x00"
encodeCs (CipherSuite RSA AES_128_CBC_SHA) = "\x00\x2f"
encodeCs (CipherSuite DHE_RSA AES_128_CBC_SHA) = "\x00\x33"
encodeCs (CipherSuite RSA AES_128_CBC_SHA256) = "\x00\x3c"
encodeCs (CipherSuite DHE_RSA AES_128_CBC_SHA256) = "\x00\x67"
encodeCs (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA) = "\xc0\x09"
encodeCs (CipherSuite ECDHE_RSA AES_128_CBC_SHA) = "\xc0\x13"
encodeCs (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256) = "\xc0\x23"
encodeCs (CipherSuite ECDHE_RSA AES_128_CBC_SHA256) = "\xc0\x27"
encodeCs (CipherSuiteRaw w1 w2) = BS.pack [w1, w2]
encodeCs EMPTY_RENEGOTIATION_INFO = "\x00\xff"
encodeCs _ = error $ modNm ++ ".encodeCs: unknown cipher suite"

instance IsString CipherSuite where
	fromString = uncurry CipherSuite . (read *** read) . sep . drop 4
		where
		sep "" = error $ modNm ++ ".separateByWith: parse error"
		sep ('_' : 'W' : 'I' : 'T' : 'H' : '_' : be) = ("", be)
		sep (k : r) = (k :) `first` sep r
