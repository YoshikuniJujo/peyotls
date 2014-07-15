{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.Types (
	Handshake(..), HandshakeItem(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), Extension(..), isRenegoInfo, emptyRenegoInfo,
	ServerKeyEx(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
	CertReq(..), certReq, ClCertType(..), SignAlg(..), HashAlg(..),
	ServerHelloDone(..), ClientKeyEx(..), Epms(..),
	DigitallySigned(..), Finished(..),
	ChangeCipherSpec(..), ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless)
import Data.Word (Word8, Word16)
import Data.Word.Word24 (Word24)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import Network.PeyoTLS.Hello (
	ClientHello(..), ServerHello(..), SessionId(..),
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	CompMethod(..), HashAlg(..), SignAlg(..),  Extension(..) )
import Network.PeyoTLS.Certificate (
	CertReq(..), certReq, ClCertType(..),
	ClientKeyEx(..), DigitallySigned(..) )

modNm :: String
modNm = "Network.PeyoTLS.Types"

data Handshake
	= HCCSpec                     | HHelloReq
	| HClHello ClientHello        | HSvHello ServerHello
	| HCert X509.CertificateChain | HSvKeyEx BS.ByteString
	| HCertReq CertReq            | HSvHelloDone
	| HCertVerify DigitallySigned | HClKeyEx ClientKeyEx
	| HFinished BS.ByteString     | HRaw Type BS.ByteString
	deriving Show

instance B.Bytable Handshake where
	decode = B.evalBytableM B.parse; encode = encodeH

instance B.Parsable Handshake where
	parse = (,) <$> B.take 1 <*> B.take 3 >>= \(t, l) -> case t of
		THelloRequest -> const HHelloReq <$>
			unless (l == 0) (fail $ modNm ++ ": Handshake.parse")
		TClientHello -> HClHello <$> B.take l
		TServerHello -> HSvHello <$> B.take l
		TCertificate -> HCert <$> B.take l
		TServerKeyEx -> HSvKeyEx <$> B.take l
		TCertificateReq -> HCertReq <$> B.take l
		TServerHelloDone -> const HSvHelloDone <$>
			unless (l == 0) (fail $ modNm ++ ": Handshake.parse")
		TCertVerify -> HCertVerify <$> B.take l
		TClientKeyEx -> HClKeyEx <$> B.take l
		TFinished -> HFinished <$> B.take l
		_ -> HRaw t <$> B.take l

encodeH :: Handshake -> BS.ByteString
encodeH HHelloReq = encodeH $ HRaw THelloRequest ""
encodeH (HClHello ch) = encodeH . HRaw TClientHello $ B.encode ch
encodeH (HSvHello sh) = encodeH . HRaw TServerHello $ B.encode sh
encodeH (HCert crts) = encodeH . HRaw TCertificate $ B.encode crts
encodeH (HSvKeyEx ske) = encodeH $ HRaw TServerKeyEx ske
encodeH (HCertReq cr) = encodeH . HRaw TCertificateReq $ B.encode cr
encodeH HSvHelloDone = encodeH $ HRaw TServerHelloDone ""
encodeH (HCertVerify ds) = encodeH . HRaw TCertVerify $ B.encode ds
encodeH (HClKeyEx epms) = encodeH . HRaw TClientKeyEx $ B.encode epms
encodeH (HFinished bs) = encodeH $ HRaw TFinished bs
encodeH (HRaw t bs) = B.encode t `BS.append` B.addLen w24 bs
encodeH HCCSpec = B.encode ChangeCipherSpec

w16 :: Word16; w16 = undefined
w24 :: Word24; w24 = undefined

class HandshakeItem hi where
	fromHandshake :: Handshake -> Maybe hi; toHandshake :: hi -> Handshake

instance HandshakeItem Handshake where fromHandshake = Just; toHandshake = id

instance (HandshakeItem l, HandshakeItem r) => HandshakeItem (Either l r) where
	fromHandshake hs = let l = fromHandshake hs; r = fromHandshake hs in
		maybe (Right <$> r) (Just . Left) l
	toHandshake (Left l) = toHandshake l
	toHandshake (Right r) = toHandshake r

instance HandshakeItem ChangeCipherSpec where
	fromHandshake HCCSpec = Just ChangeCipherSpec
	fromHandshake _ = Nothing
	toHandshake ChangeCipherSpec = HCCSpec
	toHandshake (ChangeCipherSpecRaw _) =
		error $ modNm ++ ": ChangeCipherSpec.toHandshake"

instance HandshakeItem ClientHello where
	fromHandshake (HClHello ch) = Just ch
	fromHandshake _ = Nothing
	toHandshake = HClHello

instance HandshakeItem ServerHello where
	fromHandshake (HSvHello sh) = Just sh
	fromHandshake _ = Nothing
	toHandshake = HSvHello

instance HandshakeItem X509.CertificateChain where
	fromHandshake (HCert cc) = Just cc
	fromHandshake _ = Nothing
	toHandshake = HCert

data ServerKeyEx =
	ServerKeyEx BS.ByteString BS.ByteString HashAlg SignAlg BS.ByteString
	deriving Show

instance HandshakeItem ServerKeyEx where
	fromHandshake = undefined
	toHandshake = HSvKeyEx . B.encode

instance B.Bytable ServerKeyEx where
	decode = undefined
	encode (ServerKeyEx ps pv h s sn) = BS.concat [
		ps, pv, B.encode h, B.encode s, B.addLen w16 sn ]

data ServerKeyExDhe =
	ServerKeyExDhe DH.Params DH.PublicNumber HashAlg SignAlg BS.ByteString
	deriving Show

instance HandshakeItem ServerKeyExDhe where
	fromHandshake (HSvKeyEx ske) = either (const Nothing) Just $ B.decode ske
	fromHandshake _ = Nothing
	toHandshake = HSvKeyEx . B.encode

instance B.Bytable ServerKeyExDhe where
	encode (ServerKeyExDhe ps pn h s sn) = BS.concat [
		B.encode ps, B.encode pn, B.encode h, B.encode s, B.addLen w16 sn ]
	decode = B.evalBytableM B.parse

instance B.Parsable ServerKeyExDhe where
	parse = ServerKeyExDhe <$> B.parse <*> B.parse
		<*> B.parse <*> B.parse <*> (B.take =<< B.take 2)

data ServerKeyExEcdhe =
	ServerKeyExEcdhe ECC.Curve ECC.Point HashAlg SignAlg BS.ByteString
	deriving Show

instance HandshakeItem ServerKeyExEcdhe where
	fromHandshake (HSvKeyEx ske) = either (const Nothing) Just $ B.decode ske
	fromHandshake _ = Nothing
	toHandshake = HSvKeyEx . B.encode

instance B.Bytable ServerKeyExEcdhe where
	encode (ServerKeyExEcdhe cv pnt h s sn) = BS.concat [
		B.encode cv, B.encode pnt, B.encode h, B.encode s, B.addLen w16 sn ]
	decode = B.evalBytableM B.parse

instance B.Parsable ServerKeyExEcdhe where
	parse = ServerKeyExEcdhe <$> B.parse <*> B.parse
		<*> B.parse <*> B.parse <*> (B.take =<< B.take 2)

instance HandshakeItem CertReq where
	fromHandshake (HCertReq cr) = Just cr
	fromHandshake _ = Nothing
	toHandshake = HCertReq

instance HandshakeItem ServerHelloDone where
	fromHandshake HSvHelloDone = Just SHDone
	fromHandshake _ = Nothing
	toHandshake _ = HSvHelloDone

instance HandshakeItem DigitallySigned where
	fromHandshake (HCertVerify ds) = Just ds
	fromHandshake _ = Nothing
	toHandshake = HCertVerify

instance HandshakeItem ClientKeyEx where
	fromHandshake (HClKeyEx cke) = Just cke
	fromHandshake _ = Nothing
	toHandshake = HClKeyEx

data Epms = Epms BS.ByteString

instance HandshakeItem Epms where
	fromHandshake (HClKeyEx cke) = ckeToEpms cke
	fromHandshake _ = Nothing
	toHandshake = HClKeyEx . epmsToCke

ckeToEpms :: ClientKeyEx -> Maybe Epms
ckeToEpms (ClientKeyEx cke) = case B.runBytableM (B.take =<< B.take 2) cke of
	Right (e, "") -> Just $ Epms e
	_ -> Nothing

epmsToCke :: Epms -> ClientKeyEx
epmsToCke (Epms epms) = ClientKeyEx $ B.addLen w16 epms

data Finished = Finished BS.ByteString deriving (Show, Eq)

instance HandshakeItem Finished where
	fromHandshake (HFinished f) = Just $ Finished f
	fromHandshake _ = Nothing
	toHandshake (Finished f) = HFinished f

data ServerHelloDone = SHDone deriving Show

data Type
	= THelloRequest | TClientHello | TServerHello
	| TCertificate  | TServerKeyEx | TCertificateReq | TServerHelloDone
	| TCertVerify   | TClientKeyEx | TFinished       | TRaw Word8
	deriving Show

instance B.Bytable Type where
	decode bs = case BS.unpack bs of
		[0] -> Right THelloRequest
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
	encode THelloRequest = BS.pack [0]
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

data ChangeCipherSpec = ChangeCipherSpec | ChangeCipherSpecRaw Word8 deriving Show

instance B.Bytable ChangeCipherSpec where
	decode bs = case BS.unpack bs of
		[1] -> Right ChangeCipherSpec
		[w] -> Right $ ChangeCipherSpecRaw w
		_ -> Left "HandshakeBase: ChangeCipherSpec.decode"
	encode ChangeCipherSpec = BS.pack [1]
	encode (ChangeCipherSpecRaw w) = BS.pack [w]

isRenegoInfo :: Extension -> Bool
isRenegoInfo (ERenegoInfo _) = True
isRenegoInfo _ = False

emptyRenegoInfo :: Extension
emptyRenegoInfo = ERenegoInfo ""
