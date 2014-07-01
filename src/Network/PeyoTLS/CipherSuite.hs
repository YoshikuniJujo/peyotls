{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.CipherSuite (
	CipherSuite(..), KeyExchange(..), BulkEncryption(..)) where

import Control.Arrow (first, (***))
import Data.Word (Word8)
import Data.String (IsString(..))

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B

data CipherSuite
	= CipherSuite KeyExchange BulkEncryption
	| CipherSuiteRaw Word8 Word8
	deriving (Show, Read, Eq)

data KeyExchange
	= RSA
	| DHE_RSA
	| ECDHE_RSA
	| ECDHE_ECDSA
--	| ECDHE_PSK
	| KE_NULL
	deriving (Show, Read, Eq)

data BulkEncryption
	= AES_128_CBC_SHA
	| AES_128_CBC_SHA256
--	| CAMELLIA_128_CBC_SHA
--	| NULL_SHA
	| BE_NULL
	deriving (Show, Read, Eq)


instance B.Bytable CipherSuite where
	decode = decodeCipherSuite
	encode = encodeCipherSuite

decodeCipherSuite :: BS.ByteString -> Either String CipherSuite
decodeCipherSuite bs = case BS.unpack bs of
	[w1, w2] -> Right $ case (w1, w2) of
		(0x00, 0x00) -> CipherSuite KE_NULL BE_NULL
		(0x00, 0x2f) -> CipherSuite RSA AES_128_CBC_SHA
		(0x00, 0x33) -> CipherSuite DHE_RSA AES_128_CBC_SHA
--		(0x00, 0x39) -> CipherSuite ECDHE_PSK NULL_SHA
		(0x00, 0x3c) -> CipherSuite RSA AES_128_CBC_SHA256
--		(0x00, 0x45) -> CipherSuite DHE_RSA CAMELLIA_128_CBC_SHA
		(0x00, 0x67) -> CipherSuite DHE_RSA AES_128_CBC_SHA256
		(0xc0, 0x09) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA
		(0xc0, 0x13) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA
		(0xc0, 0x23) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256
		(0xc0, 0x27) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA256
		_ -> CipherSuiteRaw w1 w2
	_ -> Left "CipherSuite.decodeCipherSuite: not 2 byte"

encodeCipherSuite :: CipherSuite -> BS.ByteString
encodeCipherSuite (CipherSuite KE_NULL BE_NULL) = "\x00\x00"
encodeCipherSuite (CipherSuite RSA AES_128_CBC_SHA) = "\x00\x2f"
encodeCipherSuite (CipherSuite DHE_RSA AES_128_CBC_SHA) = "\x00\x33"
-- encodeCipherSuite (CipherSuite ECDHE_PSK NULL_SHA) = "\x00\x39"
encodeCipherSuite (CipherSuite RSA AES_128_CBC_SHA256) = "\x00\x3c"
-- encodeCipherSuite (CipherSuite DHE_RSA CAMELLIA_128_CBC_SHA) = "\x00\x45"
encodeCipherSuite (CipherSuite DHE_RSA AES_128_CBC_SHA256) = "\x00\x67"
encodeCipherSuite (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA) = "\xc0\x09"
encodeCipherSuite (CipherSuite ECDHE_RSA AES_128_CBC_SHA) = "\xc0\x13"
encodeCipherSuite (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256) = "\xc0\x23"
encodeCipherSuite (CipherSuite ECDHE_RSA AES_128_CBC_SHA256) = "\xc0\x27"
encodeCipherSuite (CipherSuiteRaw w1 w2) = BS.pack [w1, w2]
encodeCipherSuite _ = error "CipherSuite.encodeCipherSuite: unknown cipher suite"

separateByWith :: String -> (String, String)
separateByWith "" = error "CipherSuite: parse error"
separateByWith ('_' : 'W' : 'I' : 'T' : 'H' : '_' : be) = ("", be)
separateByWith (k : r) = (k :) `first` separateByWith r

instance IsString CipherSuite where
	fromString = uncurry CipherSuite . (read *** read) . separateByWith . drop 4
