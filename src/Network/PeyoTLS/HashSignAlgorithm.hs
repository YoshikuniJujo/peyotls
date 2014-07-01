{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.HashSignAlgorithm (SignAlg(..), HashAlg(..)) where

import Data.Word (Word8)

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

data HashAlg = Sha1 | Sha224 | Sha256 | Sha384 | Sha512 | HARaw Word8
	deriving Show

instance B.Bytable HashAlg where
	encode Sha1   = "\x02"
	encode Sha224 = "\x03"
	encode Sha256 = "\x04"
	encode Sha384 = "\x05"
	encode Sha512 = "\x06"
	encode (HARaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[ha] -> Right $ case ha of
			2 -> Sha1  ; 3 -> Sha224; 4 -> Sha256
			5 -> Sha384; 6 -> Sha512; _ -> HARaw ha
		_ -> Left "HashSignAlgorithm: Bytable.decode"

instance B.Parsable HashAlg where
	parse = B.take 1

data SignAlg = Rsa | Dsa | Ecdsa | SARaw Word8 deriving (Show, Eq)

instance B.Bytable SignAlg where
	encode Rsa = "\x01"
	encode Dsa = "\x02"
	encode Ecdsa = "\x03"
	encode (SARaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[sa] -> Right $ case sa of
			1 -> Rsa; 2 -> Dsa; 3 -> Ecdsa; _ -> SARaw sa
		_ -> Left "Type.decodeSA"

instance B.Parsable SignAlg where
	parse = B.take 1
