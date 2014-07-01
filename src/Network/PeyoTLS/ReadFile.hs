{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections #-}

module Network.PeyoTLS.ReadFile (
	CertSecretKey, readKey, readCertificateChain, readCertificateStore) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow ((***))
import Control.Monad (unless)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.BitArray as ASN1
import qualified Data.PEM as PEM
import qualified Data.X509 as X509
import qualified Data.X509.File as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA

import Network.PeyoTLS.CertSecretKey

readKey :: FilePath -> IO CertSecretKey
readKey fp = do
	rk <- readRsaKey fp
	maybe (readEcdsaKey fp) return rk

readRsaKey :: FilePath -> IO (Maybe CertSecretKey)
readRsaKey fp = do
	ks <- X509.readKeyFile fp
	case ks of
		[X509.PrivKeyRSA sk] -> return . Just $ RsaKey sk
		_ -> return Nothing -- error "ReadFile.readRsaKey: not single RSA key"

readEcdsaKey :: FilePath -> IO CertSecretKey
readEcdsaKey = (EcdsaKey . either error id . decodeEcdsaKey <$>) . BS.readFile

readCertificateChain :: FilePath -> IO X509.CertificateChain
readCertificateChain = (X509.CertificateChain <$>) . X509.readSignedObject

readCertificateStore :: [FilePath] -> IO X509.CertificateStore
readCertificateStore =
	(X509.makeCertificateStore . concat <$>) . mapM X509.readSignedObject

decodeEcdsaKey :: BS.ByteString -> Either String ECDSA.PrivateKey
decodeEcdsaKey bs = do
	pms <- either (Left . show) return $ PEM.pemParseBS bs
	pm <- fromSinglePem pms
	pmc <- case pm of
		PEM.PEM { PEM.pemName = "EC PRIVATE KEY", PEM.pemHeader = [],
			PEM.pemContent = c } -> return c
		_ -> Left $ msgp ++ "bad PEM structure"
	asn <- either (Left . show) return $ ASN1.decodeASN1' ASN1.DER pmc
	(sk, oid, pk) <- case asn of
		[ASN1.Start ASN1.Sequence,
			ASN1.IntVal 1,
			ASN1.OctetString s,
			ASN1.Start (ASN1.Container ASN1.Context 0),
				o, ASN1.End (ASN1.Container ASN1.Context 0),
			ASN1.Start (ASN1.Container ASN1.Context 1),
				ASN1.BitString (ASN1.BitArray _pl p),
				ASN1.End (ASN1.Container ASN1.Context 1),
			ASN1.End ASN1.Sequence] -> (, o, p) <$> B.decode s
		_ -> Left $ msgp ++ "bad ASN.1 structure"
	unless (oid == oidSecp256r1) . Left $ msgp ++ "not implemented curve"
	tpk <- case BS.uncons pk of
		Just (4, t) -> return t
		_ -> Left $ msgp ++ "not implemented point format"
	(x, y) <- (\(ex, ey) -> (,) <$> ex <*> ey) .
			(B.decode *** B.decode) $ BS.splitAt 32 tpk
	unless (ECC.Point x y == ECC.pointMul secp256r1 sk g) .
		Left $ msgp ++ "the public key not match"
	return $ ECDSA.PrivateKey secp256r1 sk
	where
	msgp = "ReadFile.decodeEcdsaKey: "
	fromSinglePem [x] = return x
	fromSinglePem _ = Left $ msgp ++ "not single PEM"
	g = ECC.ecc_g $ ECC.common_curve secp256r1
	secp256r1 = ECC.getCurveByName ECC.SEC_p256r1
	oidSecp256r1 = ASN1.OID [1, 2, 840, 10045, 3, 1, 7]
