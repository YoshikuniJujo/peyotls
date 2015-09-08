{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.Codec.HSAlg (HSAlg(..), SignAlg(..), HashAlg(..)) where

import Control.Applicative
import Data.Word (Word8)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

modNm :: String
modNm = "Network.PeyoTLS.Codec.HSAlg"

-- | RFC 5246 7.4.1.4.1.
--
-- @
-- struct {
-- 	HashAlgorithm hash;
-- 	SignatureAlgorithm signature;
-- } SignatureAndHashAlgorithm;
-- @

data HSAlg = HSAlg HashAlg SignAlg deriving (Show, Eq)

instance B.Bytable HSAlg where
	encode (HSAlg ha sa) = B.encode ha `BS.append` B.encode sa
	decode hasa = let (ha, sa) = BS.splitAt 1 hasa in
		HSAlg <$> B.decode ha <*> B.decode sa

-- | RFC 5246 7.4.1.4.1.
--
-- @
-- enum {
-- 	none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
-- 	sha512(6), (255)
-- } HashAlgorithm;
-- @

data HashAlg
	= HANone | Md5 | Sha1 | Sha224 | Sha256 | Sha384 | Sha512
	| HARaw Word8
	deriving (Show, Eq)

instance B.Bytable HashAlg where
	encode HANone  = "\x00"
	encode Md5    = "\x01"
	encode Sha1   = "\x02"
	encode Sha224 = "\x03"
	encode Sha256 = "\x04"
	encode Sha384 = "\x05"
	encode Sha512 = "\x06"
	encode (HARaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[ha] -> Right $ case ha of
			0 -> HANone ; 1 -> Md5
			2 -> Sha1  ; 3 -> Sha224; 4 -> Sha256
			5 -> Sha384; 6 -> Sha512; _ -> HARaw ha
		_ -> Left $ modNm ++ ": HashAlg.decode"
instance B.Parsable HashAlg where parse = B.take 1

-- | RFC 5246 7.4.1.4.1.
--
-- @
-- enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
-- @

data SignAlg = SAnon | Rsa | Dsa | Ecdsa | SARaw Word8 deriving (Show, Eq)

instance B.Bytable SignAlg where
	encode SAnon = "\x00"
	encode Rsa = "\x01"
	encode Dsa = "\x02"
	encode Ecdsa = "\x03"
	encode (SARaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[sa] -> Right $ case sa of
			0 -> SAnon
			1 -> Rsa; 2 -> Dsa; 3 -> Ecdsa; _ -> SARaw sa
		_ -> Left $ modNm ++ ": SignAlg.decode"
instance B.Parsable SignAlg where parse = B.take 1
