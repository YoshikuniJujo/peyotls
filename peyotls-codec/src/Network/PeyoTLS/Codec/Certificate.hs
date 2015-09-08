{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.Codec.Certificate (
	CertReq(..), certReq, ClCertType(..), ClKeyEx(..), DigitSigned(..)) where

import Control.Applicative ((<$>), (<*>))
import Data.Word (Word8, Word16)
import Data.Word.Word24 (Word24)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B

import Network.PeyoTLS.Codec.HSAlg (HashAlg, SignAlg)

modNm :: String
modNm = "Network.PeyoTLS.Codec.Certificate"

instance B.Bytable X509.CertificateChain where
	decode = B.evalBytableM B.parse
	encode = B.addLen w24 . cmap (B.addLen w24)
		. (\(X509.CertificateChainRaw c) -> c) . X509.encodeCertificateChain
		. (\(X509.CertificateChain cs) -> X509.CertificateChain cs)

instance B.Parsable X509.CertificateChain where
	parse = X509.decodeCertificateChain . X509.CertificateChainRaw <$>
			(flip B.list (B.take =<< B.take 3) =<< B.take 3) >>= \ecc ->
		case ecc of
			Right (X509.CertificateChain cs) ->
				return $ X509.CertificateChain cs
			Left (n, em) -> fail $ modNm ++ ": " ++
				"X509.CertificateChain.parse" ++ show n ++ " " ++ em

data CertReq = CertReq [ClCertType] [(HashAlg, SignAlg)] [X509.DistinguishedName]
	deriving Show

certReq :: [ClCertType] -> [(HashAlg, SignAlg)] -> X509.CertificateStore -> CertReq
certReq t a = CertReq t a
	. map (X509.certIssuerDN . X509.signedObject . X509.getSigned)
	. X509.listCertificates

instance B.Bytable CertReq where
	encode (CertReq t a n) = BS.concat [
		B.addLen w8 $ cmap B.encode t,
		B.addLen w16 $
			cmap (\(h, s) -> B.encode h `BS.append` B.encode s) a,
		B.addLen w16 . flip cmap n $ B.addLen w16 .
			ASN1.encodeASN1' ASN1.DER . flip ASN1.toASN1 [] ]
	decode = B.evalBytableM $ CertReq
		<$> (flip B.list (B.take 1) =<< B.take 1)
		<*> (flip B.list ((,) <$> B.take 1 <*> B.take 1) =<< B.take 2)
		<*> ((B.take 2 >>=) . flip B.list $
			either (fail . show) (return . fst) . ASN1.fromASN1 =<<
			either (fail . show) return . ASN1.decodeASN1' ASN1.DER =<<
			B.take =<< B.take 2)

data ClCertType = CTRsaSign | CTEcdsaSign | CTRaw Word8 deriving (Show, Eq)

instance B.Bytable ClCertType where
	encode CTRsaSign = "\x01"
	encode CTEcdsaSign = "\x40"
	encode (CTRaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[w] -> Right $ case w of
			1 -> CTRsaSign; 64 -> CTEcdsaSign; _ -> CTRaw w
		_ -> Left $ modNm ++ ": ClCertType.decode"

data ClKeyEx = ClKeyEx BS.ByteString deriving Show
instance B.Bytable ClKeyEx where decode = Right . ClKeyEx; encode (ClKeyEx e) = e

data DigitSigned
	= DigitSigned (HashAlg, SignAlg) BS.ByteString
	| DigitSignedRaw BS.ByteString
	deriving Show

instance B.Bytable DigitSigned where
	decode = B.evalBytableM $ DigitSigned
		<$> ((,) <$> B.take 1 <*> B.take 1) <*> (B.take =<< B.take 2)
	encode (DigitSigned (ha, sa) bs) = BS.concat
		[B.encode ha, B.encode sa, B.addLen w16 bs]
	encode (DigitSignedRaw bs) = bs

cmap :: (a -> BS.ByteString) -> [a] -> BS.ByteString
cmap = (BS.concat .) . map

w8 :: Word8; w8 = undefined
w16 :: Word16; w16 = undefined
w24 :: Word24; w24 = undefined
