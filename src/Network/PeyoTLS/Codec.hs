{-# LANGUAGE OverloadedStrings #-}

module Network.PeyoTLS.Codec (
	Handshake(..), HandshakeItem(..),
	ClHello(..), SvHello(..), SssnId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CmpMtd(..), Extension(..), isRnInfo, emptyRnInfo,
	SvKeyEx(..), SvKeyExDhe(..), SvKeyExEcdhe(..),
	CertReq(..), certReq, ClCertType(..), SignAlg(..), HashAlg(..),
	SHDone(..), ClKeyEx(..), Epms(..),
	DigitSigned(..), Finished(..),
	CCSpec(..), ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless)
import Data.Word (Word8, Word16)
import Data.Word.Word24 (Word24)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import Network.PeyoTLS.Codec.Hello (
	ClHello(..), SvHello(..), SssnId(..),
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	CmpMtd(..), HashAlg(..), SignAlg(..),
	Extension(..), isRnInfo, emptyRnInfo )
import Network.PeyoTLS.Codec.Certificate (
	CertReq(..), certReq, ClCertType(..), ClKeyEx(..), DigitSigned(..) )

modNm :: String
modNm = "Network.PeyoTLS.Types"

data Handshake
	= HCCSpec                     | HHelloReq
	| HClHello ClHello            | HSvHello SvHello
	| HCert X509.CertificateChain | HSvKeyEx BS.ByteString
	| HCertReq CertReq            | HSHDone
	| HCertVer DigitSigned        | HClKeyEx ClKeyEx
	| HFinished BS.ByteString     | HRaw Type BS.ByteString
	deriving Show

instance B.Bytable Handshake where
	decode = B.evalBytableM B.parse; encode = encodeH

instance B.Parsable Handshake where
	parse = (,) <$> B.take 1 <*> B.take 3 >>= \(t, l) -> case t of
		THelloReq -> const HHelloReq <$>
			unless (l == 0) (fail $ modNm ++ ": Handshake.parse")
		TClHello -> HClHello <$> B.take l
		TSvHello -> HSvHello <$> B.take l
		TCert -> HCert <$> B.take l
		TSvKeyEx -> HSvKeyEx <$> B.take l
		TCertReq -> HCertReq <$> B.take l
		TSHDone -> const HSHDone <$>
			unless (l == 0) (fail $ modNm ++ ": Handshake.parse")
		TCertVer -> HCertVer <$> B.take l
		TClKeyEx -> HClKeyEx <$> B.take l
		TFinished -> HFinished <$> B.take l
		_ -> HRaw t <$> B.take l

encodeH :: Handshake -> BS.ByteString
encodeH HHelloReq = encodeH $ HRaw THelloReq ""
encodeH (HClHello ch) = encodeH . HRaw TClHello $ B.encode ch
encodeH (HSvHello sh) = encodeH . HRaw TSvHello $ B.encode sh
encodeH (HCert crts) = encodeH . HRaw TCert $ B.encode crts
encodeH (HSvKeyEx ske) = encodeH $ HRaw TSvKeyEx ske
encodeH (HCertReq cr) = encodeH . HRaw TCertReq $ B.encode cr
encodeH HSHDone = encodeH $ HRaw TSHDone ""
encodeH (HCertVer ds) = encodeH . HRaw TCertVer $ B.encode ds
encodeH (HClKeyEx epms) = encodeH . HRaw TClKeyEx $ B.encode epms
encodeH (HFinished bs) = encodeH $ HRaw TFinished bs
encodeH (HRaw t bs) = B.encode t `BS.append` B.addLen w24 bs
encodeH HCCSpec = B.encode CCSpec

class HandshakeItem hi where
	fromHandshake :: Handshake -> Maybe hi; toHandshake :: hi -> Handshake

instance HandshakeItem Handshake where fromHandshake = Just; toHandshake = id

instance (HandshakeItem l, HandshakeItem r) => HandshakeItem (Either l r) where
	fromHandshake hs = let l = fromHandshake hs; r = fromHandshake hs in
		maybe (Right <$> r) (Just . Left) l
	toHandshake (Left l) = toHandshake l
	toHandshake (Right r) = toHandshake r

data CCSpec = CCSpec | CCSpecRaw Word8 deriving Show

instance HandshakeItem CCSpec where
	fromHandshake HCCSpec = Just CCSpec
	fromHandshake _ = Nothing
	toHandshake CCSpec = HCCSpec
	toHandshake (CCSpecRaw _) = error $ modNm ++ ": CCSpec.toHandshake"

instance B.Bytable CCSpec where
	decode bs = case BS.unpack bs of
		[1] -> Right CCSpec
		[w] -> Right $ CCSpecRaw w
		_ -> Left $ modNm ++ ": CCSpec.decode"
	encode CCSpec = BS.pack [1]
	encode (CCSpecRaw w) = BS.pack [w]

instance HandshakeItem ClHello where
	fromHandshake (HClHello ch) = Just ch
	fromHandshake _ = Nothing
	toHandshake = HClHello

instance HandshakeItem SvHello where
	fromHandshake (HSvHello sh) = Just sh
	fromHandshake _ = Nothing
	toHandshake = HSvHello

instance HandshakeItem X509.CertificateChain where
	fromHandshake (HCert cc) = Just cc
	fromHandshake _ = Nothing
	toHandshake = HCert

data SvKeyEx = SvKeyEx BS.ByteString BS.ByteString HashAlg SignAlg BS.ByteString
	deriving Show

instance HandshakeItem SvKeyEx where
	fromHandshake = undefined
	toHandshake = HSvKeyEx . B.encode

instance B.Bytable SvKeyEx where
	decode = undefined
	encode (SvKeyEx ps pv h s sn) = BS.concat [
		ps, pv, B.encode h, B.encode s, B.addLen w16 sn ]

data SvKeyExDhe = SvKeyExDhe DH.Params DH.PublicNumber HashAlg SignAlg BS.ByteString
	deriving Show

instance HandshakeItem SvKeyExDhe where
	fromHandshake (HSvKeyEx ske) = either (const Nothing) Just $ B.decode ske
	fromHandshake _ = Nothing
	toHandshake = HSvKeyEx . B.encode

instance B.Bytable SvKeyExDhe where
	encode (SvKeyExDhe ps pn h s sn) = BS.concat [
		B.encode ps, B.encode pn, B.encode h, B.encode s, B.addLen w16 sn ]
	decode = B.evalBytableM B.parse

instance B.Parsable SvKeyExDhe where
	parse = SvKeyExDhe <$> B.parse <*> B.parse
		<*> B.parse <*> B.parse <*> (B.take =<< B.take 2)

data SvKeyExEcdhe = SvKeyExEcdhe ECC.Curve ECC.Point HashAlg SignAlg BS.ByteString
	deriving Show

instance HandshakeItem SvKeyExEcdhe where
	fromHandshake (HSvKeyEx ske) = either (const Nothing) Just $ B.decode ske
	fromHandshake _ = Nothing
	toHandshake = HSvKeyEx . B.encode

instance B.Bytable SvKeyExEcdhe where
	encode (SvKeyExEcdhe cv pnt h s sn) = BS.concat [
		B.encode cv, B.encode pnt, B.encode h, B.encode s, B.addLen w16 sn ]
	decode = B.evalBytableM B.parse

instance B.Parsable SvKeyExEcdhe where
	parse = SvKeyExEcdhe <$> B.parse <*> B.parse
		<*> B.parse <*> B.parse <*> (B.take =<< B.take 2)

instance HandshakeItem CertReq where
	fromHandshake (HCertReq cr) = Just cr
	fromHandshake _ = Nothing
	toHandshake = HCertReq

data SHDone = SHDone deriving Show

instance HandshakeItem SHDone where
	fromHandshake HSHDone = Just SHDone
	fromHandshake _ = Nothing
	toHandshake _ = HSHDone

instance HandshakeItem DigitSigned where
	fromHandshake (HCertVer ds) = Just ds
	fromHandshake _ = Nothing
	toHandshake = HCertVer

instance HandshakeItem ClKeyEx where
	fromHandshake (HClKeyEx cke) = Just cke
	fromHandshake _ = Nothing
	toHandshake = HClKeyEx

data Epms = Epms BS.ByteString

instance HandshakeItem Epms where
	fromHandshake (HClKeyEx (ClKeyEx cke)) =
		case B.runBytableM (B.take =<< B.take 2) cke of
			Right (e, "") -> Just $ Epms e
			_ -> Nothing
	fromHandshake _ = Nothing
	toHandshake (Epms epms) = HClKeyEx . ClKeyEx $ B.addLen w16 epms

data Finished = Finished BS.ByteString deriving (Show, Eq)

instance HandshakeItem Finished where
	fromHandshake (HFinished f) = Just $ Finished f
	fromHandshake _ = Nothing
	toHandshake (Finished f) = HFinished f

data Type
	= THelloReq | TClHello | TSvHello  | TCert | TSvKeyEx | TCertReq | TSHDone
	| TCertVer  | TClKeyEx | TFinished | TRaw Word8 deriving Show

instance B.Bytable Type where
	decode bs = case BS.unpack bs of
		[0] -> Right THelloReq
		[1] -> Right TClHello
		[2] -> Right TSvHello
		[11] -> Right TCert
		[12] -> Right TSvKeyEx
		[13] -> Right TCertReq
		[14] -> Right TSHDone
		[15] -> Right TCertVer
		[16] -> Right TClKeyEx
		[20] -> Right TFinished
		[ht] -> Right $ TRaw ht
		_ -> Left $ modNm ++ ": Type.decode"
	encode THelloReq = BS.pack [0]
	encode TClHello = BS.pack [1]
	encode TSvHello = BS.pack [2]
	encode TCert = BS.pack [11]
	encode TSvKeyEx = BS.pack [12]
	encode TCertReq = BS.pack [13]
	encode TSHDone = BS.pack [14]
	encode TCertVer = BS.pack [15]
	encode TClKeyEx = BS.pack [16]
	encode TFinished = BS.pack [20]
	encode (TRaw w) = BS.pack [w]

w16 :: Word16; w16 = undefined
w24 :: Word24; w24 = undefined
