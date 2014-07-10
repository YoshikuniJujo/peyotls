{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.Certificate (
	CertReq(..), certReq, ClCertType(..),
	ClientKeyEx(..), DigitallySigned(..)) where

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

import Network.PeyoTLS.HSAlg (HashAlg, SignAlg)

instance B.Bytable X509.CertificateChain where
	decode = B.evalBytableM B.parse
	encode = B.addLen w24 . cmap (B.addLen w24)
		. (\(X509.CertificateChainRaw ccr) -> ccr)
		. X509.encodeCertificateChain
		. (\(X509.CertificateChain cs) ->
			X509.CertificateChain $ cs)

instance B.Parsable X509.CertificateChain where
	parse = do
		ecc <- X509.decodeCertificateChain . X509.CertificateChainRaw <$>
			(flip B.list (B.take =<< B.take 3) =<< B.take 3)
		case ecc of
			Right (X509.CertificateChain cs) ->
				return . X509.CertificateChain $ cs
			Left (n, err) -> fail $ show n ++ " " ++ err

data CertReq = CertReq [ClCertType] [(HashAlg, SignAlg)] [X509.DistinguishedName]
	deriving Show

certReq :: [ClCertType] -> [(HashAlg, SignAlg)] ->
	X509.CertificateStore -> CertReq
certReq t a = CertReq t a
	. map (X509.certIssuerDN . X509.signedObject . X509.getSigned)
	. X509.listCertificates

instance B.Bytable CertReq where
	encode (CertReq t a n) = BS.concat [
		B.addLen w8 $ cmap B.encode t,
		B.addLen w16 . BS.concat $
			concatMap (\(h, s) -> [B.encode h, B.encode s]) a,
		B.addLen w16 . flip cmap n $ B.addLen w16 .
			ASN1.encodeASN1' ASN1.DER . flip ASN1.toASN1 [] ]
--	encode (CertReq bs) = bs
	decode = B.evalBytableM $ do
		t <- flip B.list (B.take 1) =<< B.take 1
		a <- flip B.list ((,) <$> B.take 1 <*> B.take 1) =<< B.take 2
		n <- (B.take 2 >>=) . flip B.list $ do
			bs <- B.take =<< B.take 2
			a1 <- either (fail . show) return $
				ASN1.decodeASN1' ASN1.DER bs
			either (fail . show) (return . fst) $ ASN1.fromASN1 a1
		return $ CertReq t a n

data ClCertType = CTRsaSign | CTEcdsaSign | CTRaw Word8
	deriving (Show, Eq)

instance B.Bytable ClCertType where
	encode CTRsaSign = "\x01"
	encode CTEcdsaSign = "\x40"
	encode (CTRaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[w] -> Right $ case w of
			1 -> CTRsaSign; 64 -> CTEcdsaSign; _ -> CTRaw w
		_ -> Left "Certificate: ClCertType.decode"

data ClientKeyEx = ClientKeyEx BS.ByteString deriving Show

instance B.Bytable ClientKeyEx where
	decode = Right . ClientKeyEx
	encode (ClientKeyEx epms) = epms

data DigitallySigned
	= DigitallySigned (HashAlg, SignAlg) BS.ByteString
	| DigitallySignedRaw BS.ByteString
	deriving Show

instance B.Bytable DigitallySigned where
	decode = B.evalBytableM $
		DigitallySigned
			<$> ((,) <$> B.take 1 <*> B.take 1)
			<*> (B.take =<< B.take 2)
	encode (DigitallySigned (ha, sa) bs) = BS.concat [
		B.encode ha, B.encode sa, B.addLen w16 bs ]
	encode (DigitallySignedRaw bs) = bs

w8 :: Word8; w8 = undefined
w16 :: Word16; w16 = undefined
w24 :: Word24; w24 = undefined

cmap :: (a -> BS.ByteString) -> [a] -> BS.ByteString
cmap = (BS.concat .) . map
