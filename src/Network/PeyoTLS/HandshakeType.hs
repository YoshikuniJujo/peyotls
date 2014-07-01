{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.HandshakeType (
	Handshake, HandshakeItem(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..),
	ServerKeyExchange(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
	CertificateRequest(..), certificateRequest, ClientCertificateType(..),
		SignAlg(..), HashAlg(..),
	ServerHelloDone(..), ClientKeyExchange(..), Epms(..),
	DigitallySigned(..), Finished(..) ) where

import Control.Applicative ((<$>), (<*>))
import Data.Word (Word8, Word16)
import Data.Word.Word24 (Word24)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Codec.Bytable as B
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import Network.PeyoTLS.Hello (
	ClientHello(..), ServerHello(..), SessionId(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	CompressionMethod(..), HashAlg(..), SignAlg(..) )
import Network.PeyoTLS.Certificate (
	CertificateRequest(..), certificateRequest, ClientCertificateType(..),
	ClientKeyExchange(..), DigitallySigned(..) )

data Handshake
	= HClientHello ClientHello           | HServerHello ServerHello
	| HCertificate X509.CertificateChain | HServerKeyEx BS.ByteString
	| HCertificateReq CertificateRequest | HServerHelloDone
	| HCertVerify DigitallySigned        | HClientKeyEx ClientKeyExchange
	| HFinished BS.ByteString            | HRaw Type BS.ByteString
	deriving Show

instance B.Bytable Handshake where
	decode = B.evalBytableM B.parse; encode = encodeH

instance B.Parsable Handshake where
	parse = do
		t <- B.take 1
		len <- B.take 3
		case t of
			TClientHello -> HClientHello <$> B.take len
			TServerHello -> HServerHello <$> B.take len
			TCertificate -> HCertificate <$> B.take len
			TServerKeyEx -> HServerKeyEx <$> B.take len
			TCertificateReq -> HCertificateReq <$> B.take len
			TServerHelloDone -> let 0 = len in return HServerHelloDone
			TCertVerify -> HCertVerify <$> B.take len
			TClientKeyEx -> HClientKeyEx <$> B.take len
			TFinished -> HFinished <$> B.take len
			_ -> HRaw t <$> B.take len

encodeH :: Handshake -> BS.ByteString
encodeH (HClientHello ch) = encodeH . HRaw TClientHello $ B.encode ch
encodeH (HServerHello sh) = encodeH . HRaw TServerHello $ B.encode sh
encodeH (HCertificate crts) = encodeH . HRaw TCertificate $ B.encode crts
encodeH (HServerKeyEx ske) = encodeH $ HRaw TServerKeyEx ske
encodeH (HCertificateReq cr) = encodeH . HRaw TCertificateReq $ B.encode cr
encodeH HServerHelloDone = encodeH $ HRaw TServerHelloDone ""
encodeH (HCertVerify ds) = encodeH . HRaw TCertVerify $ B.encode ds
encodeH (HClientKeyEx epms) = encodeH . HRaw TClientKeyEx $ B.encode epms
encodeH (HFinished bs) = encodeH $ HRaw TFinished bs
encodeH (HRaw t bs) = B.encode t `BS.append` B.addLen (undefined :: Word24) bs

class HandshakeItem hi where
	fromHandshake :: Handshake -> Maybe hi;
	toHandshake :: hi -> Handshake

instance (HandshakeItem l, HandshakeItem r) => HandshakeItem (Either l r) where
	fromHandshake hs = let
		l = fromHandshake hs
		r = fromHandshake hs in maybe (Right <$> r) (Just . Left) l
	toHandshake (Left l) = toHandshake l
	toHandshake (Right r) = toHandshake r

instance HandshakeItem ClientHello where
	fromHandshake (HClientHello ch) = Just ch
	fromHandshake _ = Nothing
	toHandshake = HClientHello

instance HandshakeItem ServerHello where
	fromHandshake (HServerHello sh) = Just sh
	fromHandshake _ = Nothing
	toHandshake = HServerHello

instance HandshakeItem X509.CertificateChain where
	fromHandshake (HCertificate cc) = Just cc
	fromHandshake _ = Nothing
	toHandshake = HCertificate

data ServerKeyExchange = ServerKeyEx BS.ByteString BS.ByteString
	HashAlg SignAlg BS.ByteString deriving Show

data ServerKeyExDhe = ServerKeyExDhe DH.Params DH.PublicNumber
	HashAlg SignAlg BS.ByteString deriving Show

data ServerKeyExEcdhe = ServerKeyExEcdhe ECC.Curve ECC.Point
	HashAlg SignAlg BS.ByteString deriving Show

instance HandshakeItem ServerKeyExchange where
	fromHandshake = undefined
	toHandshake = HServerKeyEx . B.encode

instance HandshakeItem ServerKeyExDhe where
	toHandshake = HServerKeyEx . B.encode
	fromHandshake (HServerKeyEx ske) =
		either (const Nothing) Just $ B.decode ske
	fromHandshake _ = Nothing

instance HandshakeItem ServerKeyExEcdhe where
	toHandshake = HServerKeyEx . B.encode
	fromHandshake (HServerKeyEx ske) =
		either (const Nothing) Just $ B.decode ske
	fromHandshake _ = Nothing

instance B.Bytable ServerKeyExchange where
	decode = undefined
	encode (ServerKeyEx ps pv ha sa sn) = BS.concat [
		ps, pv, B.encode ha, B.encode sa,
		B.addLen (undefined :: Word16) sn ]

instance B.Bytable ServerKeyExDhe where
	encode (ServerKeyExDhe ps pv ha sa sn) = BS.concat [
		B.encode ps, B.encode pv, B.encode ha, B.encode sa,
		B.addLen (undefined :: Word16) sn ]
	decode = B.evalBytableM B.parse

instance B.Bytable ServerKeyExEcdhe where
	encode (ServerKeyExEcdhe cv pnt ha sa sn) = BS.concat [
		B.encode cv, B.encode pnt, B.encode ha, B.encode sa,
		B.addLen (undefined :: Word16) sn ]
	decode = B.evalBytableM B.parse

instance B.Parsable ServerKeyExDhe where
	parse = do
		ps <- B.parse
		pv <- B.parse
		(ha, sa, sn) <- hasasn
		return $ ServerKeyExDhe ps pv ha sa sn

instance B.Parsable ServerKeyExEcdhe where
	parse = do
		cv <- B.parse
		pnt <- B.parse
		(ha, sa, sn) <- hasasn
		return $ ServerKeyExEcdhe cv pnt ha sa sn

hasasn :: B.BytableM (HashAlg, SignAlg, BS.ByteString)
hasasn = (,,) <$> B.parse <*> B.parse <*> (B.take =<< B.take 2)

instance HandshakeItem CertificateRequest where
	fromHandshake (HCertificateReq cr) = Just cr
	fromHandshake _ = Nothing
	toHandshake = HCertificateReq

instance HandshakeItem ServerHelloDone where
	fromHandshake HServerHelloDone = Just ServerHelloDone
	fromHandshake _ = Nothing
	toHandshake _ = HServerHelloDone

instance HandshakeItem DigitallySigned where
	fromHandshake (HCertVerify ds) = Just ds
	fromHandshake _ = Nothing
	toHandshake = HCertVerify

instance HandshakeItem ClientKeyExchange where
	fromHandshake (HClientKeyEx cke) = Just cke
	fromHandshake _ = Nothing
	toHandshake = HClientKeyEx

data Epms = Epms BS.ByteString

instance HandshakeItem Epms where
	fromHandshake (HClientKeyEx cke) = ckeToEpms cke
	fromHandshake _ = Nothing
	toHandshake = HClientKeyEx . epmsToCke

ckeToEpms :: ClientKeyExchange -> Maybe Epms
ckeToEpms (ClientKeyExchange cke) = case B.runBytableM (B.take =<< B.take 2) cke of
	Right (e, "") -> Just $ Epms e
	_ -> Nothing

epmsToCke :: Epms -> ClientKeyExchange
epmsToCke (Epms epms) = ClientKeyExchange $ B.addLen (undefined :: Word16) epms

data Finished = Finished BS.ByteString deriving (Show, Eq)

instance HandshakeItem Finished where
	fromHandshake (HFinished f) = Just $ Finished f
	fromHandshake _ = Nothing
	toHandshake (Finished f) = HFinished f

data ServerHelloDone = ServerHelloDone deriving Show

data Type
	= TClientHello | TServerHello
	| TCertificate | TServerKeyEx | TCertificateReq | TServerHelloDone
	| TCertVerify  | TClientKeyEx | TFinished       | TRaw Word8
	deriving Show

instance B.Bytable Type where
	decode bs = case BS.unpack bs of
		[1] -> Right TClientHello
		[2] -> Right TServerHello
		[11] -> Right TCertificate
		[12] -> Right TServerKeyEx
		[13] -> Right TCertificateReq
		[14] -> Right TServerHelloDone
		[15] -> Right TCertVerify
		[16] -> Right TClientKeyEx
		[20] -> Right TFinished
		[ht] -> Right $ TRaw ht
		_ -> Left "Handshake.decodeT"
	encode TClientHello = BS.pack [1]
	encode TServerHello = BS.pack [2]
	encode TCertificate = BS.pack [11]
	encode TServerKeyEx = BS.pack [12]
	encode TCertificateReq = BS.pack [13]
	encode TServerHelloDone = BS.pack [14]
	encode TCertVerify = BS.pack [15]
	encode TClientKeyEx = BS.pack [16]
	encode TFinished = BS.pack [20]
	encode (TRaw w) = BS.pack [w]
