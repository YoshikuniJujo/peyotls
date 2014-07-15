{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.Codec.Hello (
	ClHello(..), SvHello(..), SssnId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CmpMtd(..), SignAlg(..), HashAlg(..),
		Extension(..), isRnInfo, emptyRnInfo ) where

import Control.Applicative ((<$>), (<*>))
import Data.Word (Word8, Word16)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

import Network.PeyoTLS.Codec.Extension (
	Extension(..), isRnInfo, emptyRnInfo, SignAlg(..), HashAlg(..) )
import Network.PeyoTLS.CipherSuite (CipherSuite(..), KeyEx(..), BulkEnc(..))

modNm :: String
modNm = "Network.PeyoTLS.Codec.Hello"

data ClHello
	= ClHello (Word8, Word8) BS.ByteString SssnId [CipherSuite] [CmpMtd]
		(Maybe [Extension])
	| ClHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ClHello where
	decode = B.evalBytableM $ ClHello
		<$> ((,) <$> B.head <*> B.head)
		<*> B.take 32 <*> (B.take =<< B.take 1)
		<*> (flip B.list (B.take 2) =<< B.take 2)
		<*> (flip B.list (B.take 1) =<< B.take 1)
		<*> do	nl <- B.null
			if nl then return Nothing else Just <$>
				(flip B.list B.parse =<< B.take 2)
	encode (ClHello (vj, vn) r sid css cms mel) = BS.concat [
		B.encode vj, B.encode vn, B.encode r, B.addLen w8 $ B.encode sid,
		B.addLen w16 . BS.concat $ map B.encode css,
		B.addLen w8 . BS.concat $ map B.encode cms,
		maybe "" (B.addLen w16 . BS.concat . map B.encode) mel ]
	encode (ClHelloRaw bs) = bs

data SvHello
	= SvHello (Word8, Word8) BS.ByteString SssnId CipherSuite CmpMtd
		(Maybe [Extension])
	| SvHelloRaw BS.ByteString
	deriving Show

instance B.Bytable SvHello where
	decode = B.evalBytableM $ SvHello
		<$> ((,) <$> B.head <*> B.head)
		<*> B.take 32 <*> (B.take =<< B.take 1) <*> B.take 2 <*> B.take 1
		<*> do	n <- B.null
			if n then return Nothing else Just <$>
				(flip B.list B.parse =<< B.take 2)
	encode (SvHello (vj, vn) r sid cs cm mes) = BS.concat [
		B.encode vj, B.encode vn, B.encode r, B.addLen w8 $ B.encode sid,
		B.encode cs, B.encode cm,
		maybe "" (B.addLen w16 . BS.concat . map B.encode) mes ]
	encode (SvHelloRaw sh) = sh

data SssnId = SssnId BS.ByteString deriving Show

instance B.Bytable SssnId where decode = Right . SssnId; encode (SssnId bs) = bs

data CmpMtd = CmpMtdNull | CmpMtdRaw Word8 deriving (Show, Eq)

instance B.Bytable CmpMtd where
	decode bs = case BS.unpack bs of
		[cm] -> Right $ case cm of 0 -> CmpMtdNull; _ -> CmpMtdRaw cm
		_ -> Left $ modNm ++ ": CmpMtd.decode"
	encode CmpMtdNull = "\0"
	encode (CmpMtdRaw cm) = BS.pack [cm]

w8 :: Word8; w8 = undefined
w16 :: Word16; w16 = undefined
