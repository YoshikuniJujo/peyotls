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
