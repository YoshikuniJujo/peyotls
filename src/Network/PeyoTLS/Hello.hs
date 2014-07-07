{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.Hello ( Extension(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..),
		SignAlg(..), HashAlg(..) ) where

import Control.Applicative ((<$>), (<*>))
import Data.Word (Word8, Word16)
import Numeric (showHex)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

import Network.PeyoTLS.Extension (Extension(..), SignAlg(..), HashAlg(..))
import Network.PeyoTLS.CipherSuite (
	CipherSuite(..), KeyEx(..), BulkEnc(..))

data ClientHello
	= ClientHello (Word8, Word8) BS.ByteString SessionId
		[CipherSuite] [CompMethod] (Maybe [Extension])
	| ClientHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ClientHello where
	decode = B.evalBytableM $ do
		(pv, r, sid) <- (,,) <$> ((,) <$> B.head <*> B.head)
			<*> B.take 32 <*> (B.take =<< B.take 1)
		cs <- flip B.list (B.take 2) =<< B.take 2
		cm <- flip B.list (B.take 1) =<< B.take 1
		nl <- B.null
		me <- if nl then return Nothing else
			Just <$> (flip B.list B.parse =<< B.take 2)
		return $ ClientHello pv r sid cs cm me
	encode = encodeCh

encodeCh :: ClientHello -> BS.ByteString
encodeCh (ClientHello (vmjr, vmnr) r sid css cms mel) = BS.concat [
	B.encode vmjr, B.encode vmnr, B.encode r,
	B.addLen (undefined :: Word8) $ B.encode sid,
	B.addLen (undefined :: Word16) . BS.concat $ map B.encode css,
	B.addLen (undefined :: Word8) . BS.concat $ map B.encode cms,
	maybe "" (B.addLen (undefined :: Word16) . BS.concat . map B.encode) mel ]
encodeCh (ClientHelloRaw bs) = bs

data ServerHello
	= ServerHello (Word8, Word8) BS.ByteString SessionId
		CipherSuite CompMethod (Maybe [Extension])
	| ServerHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ServerHello where
	decode = B.evalBytableM $ do
		(pv, r, sid) <- (,,) <$> ((,) <$> B.head <*> B.head)
			<*> B.take 32 <*> (B.take =<< B.take 1)
		cs <- B.take 2
		cm <- B.take 1
		e <- B.null
		me <- if e then return Nothing else do
			mel <- B.take 2
			Just <$> B.list mel B.parse
		return $ ServerHello pv r sid cs cm me
	encode = encodeSh

encodeSh :: ServerHello -> BS.ByteString
encodeSh (ServerHello (vmjr, vmnr) r sid cs cm mes) = BS.concat [
	B.encode vmjr, B.encode vmnr, B.encode r,
	B.addLen (undefined :: Word8) $ B.encode sid,
	B.encode cs, B.encode cm,
	maybe "" (B.addLen (undefined :: Word16) . BS.concat . map B.encode) mes ]
encodeSh (ServerHelloRaw sh) = sh

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

data SessionId = SessionId BS.ByteString

instance Show SessionId where
	show (SessionId sid) = "(SessionID " ++
		concatMap (`showHex` "") (BS.unpack sid) ++ ")"

instance B.Bytable SessionId where
	decode = Right . SessionId
	encode (SessionId bs) = bs
