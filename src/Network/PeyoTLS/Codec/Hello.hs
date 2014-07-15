{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.Codec.Hello ( Extension(..), isRenegoInfo, emptyRenegoInfo,
	ClHello(..), SvHello(..), SssnId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..),
		SignAlg(..), HashAlg(..) ) where

import Control.Applicative ((<$>), (<*>))
import Data.Word (Word8, Word16)
import Numeric (showHex)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

import Network.PeyoTLS.Codec.Extension (
	Extension(..), SignAlg(..), HashAlg(..),
	isRenegoInfo, emptyRenegoInfo,
	)
import Network.PeyoTLS.CipherSuite (
	CipherSuite(..), KeyEx(..), BulkEnc(..))

data ClHello
	= ClHello (Word8, Word8) BS.ByteString SssnId
		[CipherSuite] [CompMethod] (Maybe [Extension])
	| ClHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ClHello where
	decode = B.evalBytableM $ do
		(pv, r, sid) <- (,,) <$> ((,) <$> B.head <*> B.head)
			<*> B.take 32 <*> (B.take =<< B.take 1)
		cs <- flip B.list (B.take 2) =<< B.take 2
		cm <- flip B.list (B.take 1) =<< B.take 1
		nl <- B.null
		me <- if nl then return Nothing else
			Just <$> (flip B.list B.parse =<< B.take 2)
		return $ ClHello pv r sid cs cm me
	encode = encodeCh

encodeCh :: ClHello -> BS.ByteString
encodeCh (ClHello (vmjr, vmnr) r sid css cms mel) = BS.concat [
	B.encode vmjr, B.encode vmnr, B.encode r,
	B.addLen (undefined :: Word8) $ B.encode sid,
	B.addLen (undefined :: Word16) . BS.concat $ map B.encode css,
	B.addLen (undefined :: Word8) . BS.concat $ map B.encode cms,
	maybe "" (B.addLen (undefined :: Word16) . BS.concat . map B.encode) mel ]
encodeCh (ClHelloRaw bs) = bs

data SvHello
	= SvHello (Word8, Word8) BS.ByteString SssnId
		CipherSuite CompMethod (Maybe [Extension])
	| SvHelloRaw BS.ByteString
	deriving Show

instance B.Bytable SvHello where
	decode = B.evalBytableM $ do
		(pv, r, sid) <- (,,) <$> ((,) <$> B.head <*> B.head)
			<*> B.take 32 <*> (B.take =<< B.take 1)
		cs <- B.take 2
		cm <- B.take 1
		e <- B.null
		me <- if e then return Nothing else do
			mel <- B.take 2
			Just <$> B.list mel B.parse
		return $ SvHello pv r sid cs cm me
	encode = encodeSh

encodeSh :: SvHello -> BS.ByteString
encodeSh (SvHello (vmjr, vmnr) r sid cs cm mes) = BS.concat [
	B.encode vmjr, B.encode vmnr, B.encode r,
	B.addLen (undefined :: Word8) $ B.encode sid,
	B.encode cs, B.encode cm,
	maybe "" (B.addLen (undefined :: Word16) . BS.concat . map B.encode) mes ]
encodeSh (SvHelloRaw sh) = sh

data CompMethod = CompMethodNull | CompMethodRaw Word8
	deriving (Show, Eq)

instance B.Bytable CompMethod where
	decode bs = case BS.unpack bs of
		[cm] -> Right $ case cm of
			0 -> CompMethodNull
			_ -> CompMethodRaw cm
		_ -> Left "Hello.decodeCm"
	encode CompMethodNull = "\0"
	encode (CompMethodRaw cm) = BS.pack [cm]

data SssnId = SssnId BS.ByteString

instance Show SssnId where
	show (SssnId sid) = "(SessionID " ++
		concatMap (`showHex` "") (BS.unpack sid) ++ ")"

instance B.Bytable SssnId where
	decode = Right . SssnId
	encode (SssnId bs) = bs
