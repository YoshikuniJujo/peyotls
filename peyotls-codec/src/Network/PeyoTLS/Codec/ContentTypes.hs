{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.Codec.ContentTypes (PrtVrsn(..), ContType(..)) where

import Data.Word

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

modNm :: String
modNm = "Network.PeyoTLS.Codec.ContentTypes"

-- | RFC 5246 6.2.1 Fragmentation
--
-- @
-- struct {
-- 	uint8 major;
-- 	uint8 minor;
-- } ProtocolVersion;
-- @

data PrtVrsn = PrtVrsn Word8 Word8 deriving (Show, Eq, Ord)

instance B.Bytable PrtVrsn where
	encode (PrtVrsn mj mn) = BS.pack [mj, mn]
	decode mjmn = case BS.unpack mjmn of
		[mj, mn] -> Right $ PrtVrsn mj mn
		_ -> Left $ modNm ++ ": PrtVrsn.decode"

-- | RFC 5246 6.2.1 Fragmentation
--
-- @
-- enum {
-- 	change_cipher_spec(20), alert(21), handshake(22),
-- 	application_data(23), (255)
-- } ContentType;
-- @

data ContType = CTCCSpec | CTAlert | CTHandshake | CTAppData | CTNull | CTRaw Word8
	deriving (Show, Eq)

instance B.Bytable ContType where
	encode CTNull = BS.pack [0]
	encode CTCCSpec = BS.pack [20]
	encode CTAlert = BS.pack [21]
	encode CTHandshake = BS.pack [22]
	encode CTAppData = BS.pack [23]
	encode (CTRaw ct) = BS.pack [ct]
	decode "\0" = Right CTNull
	decode "\20" = Right CTCCSpec
	decode "\21" = Right CTAlert
	decode "\22" = Right CTHandshake
	decode "\23" = Right CTAppData
	decode bs | [ct] <- BS.unpack bs = Right $ CTRaw ct
	decode _ = Left $ modNm ++ ": ContType.decode"
