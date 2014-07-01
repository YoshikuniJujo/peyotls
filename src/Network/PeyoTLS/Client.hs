{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.Client (
	run, open, names,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	PeyotlsM, PeyotlsHandle,
	TlsM, TlsHandle,
	ValidateHandle(..), CertSecretKey ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless, liftM, ap)
import Data.List (find, intersect)
import Data.HandleLike (HandleLike)
import "crypto-random" Crypto.Random (CPRG)

import qualified "monads-tf" Control.Monad.Error as E
import qualified "monads-tf" Control.Monad.Error.Class as E
import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import Network.PeyoTLS.HandshakeBase (
	PeyotlsM, PeyotlsHandle, names,
	TlsM, run, HandshakeM, execHandshakeM, CertSecretKey(..),
		withRandom, randomByteString,
	TlsHandle,
		readHandshake, getChangeCipherSpec,
		writeHandshake, putChangeCipherSpec,
	ValidateHandle(..), handshakeValidate,
	ServerKeyExEcdhe(..), ServerKeyExDhe(..), ServerHelloDone(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlg(..), SignAlg(..),
		setCipherSuite,
	CertificateRequest(..), ClientCertificateType(..),
	ClientKeyExchange(..), Epms(..),
		generateKeys, encryptRsa, rsaPadding,
	DigitallySigned(..), handshakeHash, flushCipherSuite,
	Side(..), RW(..), finishedHash,
	DhParam(..), generateKs, blindSign )

open :: (ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	TlsM h g (TlsHandle h g)
open h cscl crts ca = execHandshakeM h $ do
	(cr, sr, cs@(CipherSuite ke _)) <- hello cscl
	setCipherSuite cs
	case ke of
		RSA -> rsaHandshake cr sr crts ca
		DHE_RSA -> dheHandshake dhType cr sr crts ca
		ECDHE_RSA -> dheHandshake curveType cr sr crts ca
		ECDHE_ECDSA -> dheHandshake curveType cr sr crts ca
		_ -> error "not implemented"
	where
	dhType :: DH.Params; dhType = undefined
	curveType :: ECC.Curve; curveType = undefined

hello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g (BS.ByteString, BS.ByteString, CipherSuite)
hello cscl = do
	cr <- randomByteString 32
	writeHandshake $ ClientHello (3, 3) cr (SessionId "")
		cscl' [CompressionMethodNull] Nothing
	ServerHello _v sr _sid cs _cm _e <- readHandshake
	return (cr, sr, cs)
	where
	cscl' = if b `elem` cscl then cscl else cscl ++ [b]
	b = CipherSuite RSA AES_128_CBC_SHA

rsaHandshake :: (ValidateHandle h, CPRG g) =>
 	BS.ByteString -> BS.ByteString ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
rsaHandshake cr sr crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	vr <- handshakeValidate ca cc
	unless (null vr) $ E.throwError "TlsClient.rsaHandshake: validate failure"
	let X509.PubKeyRSA pk =
		X509.certPubKey . X509.signedObject $ X509.getSigned c
	crt <- clientCertificate crts
	pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
	generateKeys Client (cr, sr) pms
	writeHandshake . Epms =<< encryptRsa pk pms
	finishHandshake crt

dheHandshake :: (ValidateHandle h, CPRG g, KeyExchangeClass ke, Show (Secret ke),
	Show (Public ke)) =>
	ke -> BS.ByteString -> BS.ByteString ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
dheHandshake t cr sr crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA pk -> succeedHandshake t pk cr sr cc crts ca
		X509.PubKeyECDSA cv pnt ->
			succeedHandshake t (ek cv pnt) cr sr cc crts ca
		_ -> E.throwError "TlsClient.dheHandshake: not implemented"
	where
	ek cv pnt = ECDSA.PublicKey (ECC.getCurveByName cv) (point pnt)
	point s = let (x, y) = BS.splitAt 32 $ BS.drop 1 s in ECC.Point
		(either error id $ B.decode x)
		(either error id $ B.decode y)

succeedHandshake ::
	(ValidateHandle h, CPRG g, Verify pk, KeyExchangeClass ke, Show (Secret ke),
		Show (Public ke)) =>
	ke -> pk -> BS.ByteString -> BS.ByteString -> X509.CertificateChain ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
succeedHandshake t pk cr sr cc crts ca = do
	vr <- handshakeValidate ca cc
	unless (null vr) $
		E.throwError "TlsClient.succeedHandshake: validate failure"
	(ps, pv, ha, _sa, sn) <- serverKeyExchange
	let _ = ps `asTypeOf` t
	unless (verify ha pk sn $ BS.concat [cr, sr, B.encode ps, B.encode pv]) $
		E.throwError "TlsClient.succeedHandshake: verify failure"
	crt <- clientCertificate crts
	sv <- withRandom $ generateSecret ps
	generateKeys Client (cr, sr) $ calculateShared ps sv pv
	writeHandshake . ClientKeyExchange . B.encode $ calculatePublic ps sv
	finishHandshake crt

class (DhParam bs, B.Bytable bs, B.Bytable (Public bs)) => KeyExchangeClass bs where
	serverKeyExchange :: (HandleLike h, CPRG g) => HandshakeM h g
		(bs, Public bs, HashAlg, SignAlg, BS.ByteString)

instance KeyExchangeClass ECC.Curve where
	serverKeyExchange = do
		ServerKeyExEcdhe cv pnt ha sa sn <- readHandshake
		return (cv, pnt, ha, sa, sn)

instance KeyExchangeClass DH.Params where
	serverKeyExchange = do
		ServerKeyExDhe ps pv ha sa sn <- readHandshake
		return (ps, pv, ha, sa, sn)

class Verify pk where
	verify :: HashAlg -> pk -> BS.ByteString -> BS.ByteString -> Bool

instance Verify RSA.PublicKey where
	verify = rsaVerify

rsaVerify :: HashAlg -> RSA.PublicKey -> BS.ByteString -> BS.ByteString -> Bool
rsaVerify ha pk sn m = let
	(hs, oid0) = case ha of
		Sha1 -> (SHA1.hash, ASN1.OID [1, 3, 14, 3, 2, 26])
		Sha256 -> (SHA256.hash, ASN1.OID [2, 16, 840, 1, 101, 3, 4, 2, 1])
		_ -> error "not implemented"
	Right [ASN1.Start ASN1.Sequence,
		ASN1.Start ASN1.Sequence, oid, ASN1.Null, ASN1.End ASN1.Sequence,
		ASN1.OctetString o, ASN1.End ASN1.Sequence ] =
		ASN1.decodeASN1' ASN1.DER . BS.tail . BS.dropWhile (== 255) .
			BS.drop 2 $ RSA.ep pk sn in
	oid == oid0 && o == hs m

instance Verify ECDSA.PublicKey where
	verify Sha1 pk = ECDSA.verify SHA1.hash pk . either error id . B.decode
	verify Sha256 pk = ECDSA.verify SHA256.hash pk . either error id . B.decode
	verify _ _ = error "TlsClient: ECDSA.PublicKey.verify: not implemented"

clientCertificate :: (HandleLike h, CPRG g) =>
	[(CertSecretKey, X509.CertificateChain)] ->
	HandshakeM h g (Maybe (CertSecretKey, X509.CertificateChain))
clientCertificate crts = do
	shd <- readHandshake
	case shd of
		Left (CertificateRequest ca hsa dn) -> do
			ServerHelloDone <- readHandshake
			case find (isMatchedCert ca hsa dn) crts of
				Just (sk, rcc) -> do
					writeHandshake rcc
					return $ Just (sk, rcc)
				_ -> E.throwError . E.strMsg $
					"TlsClient.clientCertificate: " ++
						"no certificate"
		Right ServerHelloDone -> return Nothing
		_ -> E.throwError "TlsClient.clientCertificate"

isMatchedCert :: [ClientCertificateType] -> [(HashAlg, SignAlg)] ->
	[X509.DistinguishedName] -> (CertSecretKey, X509.CertificateChain) -> Bool
isMatchedCert ct hsa dn = (&&) <$> csk . fst <*> ccrt . snd
	where
	csk (RsaKey _) = CTRsaSign `elem` ct || Rsa `elem` map snd hsa
	csk (EcdsaKey _) = CTEcdsaSign `elem` ct || Ecdsa `elem` map snd hsa
	ccrt (X509.CertificateChain cs@(c : _)) =
		cpk pk && not (null $ intersect dn issr)
		where
		obj = X509.signedObject . X509.getSigned
		pk = X509.certPubKey $ obj c
		issr = map (X509.certIssuerDN . obj) cs
	ccrt _ = error "TlsClient.certIsOk: empty certificate chain"
	cpk X509.PubKeyRSA {} = CTRsaSign `elem` ct || Rsa `elem` map snd hsa
	cpk X509.PubKeyECDSA {} = CTEcdsaSign `elem` ct || Ecdsa `elem` map snd hsa
	cpk _ = False

finishHandshake :: (HandleLike h, CPRG g) =>
	Maybe (CertSecretKey, X509.CertificateChain) -> HandshakeM h g ()
finishHandshake crt = do
	hs <- handshakeHash
	case crt of
		Just (RsaKey sk, X509.CertificateChain (c : _)) ->
			writeHandshake $ digitallySigned sk (pubKey sk c) hs
		Just (EcdsaKey sk, X509.CertificateChain (c : _)) ->
			writeHandshake $ digitallySigned sk (pubKey sk c) hs
		_ -> return ()
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Client
	getChangeCipherSpec >> flushCipherSuite Read
	(==) `liftM` finishedHash Server `ap` readHandshake >>= flip unless
		(E.throwError "TlsClient.finishHandshake: finished hash failure")
	where
	digitallySigned sk pk hs = DigitallySigned (algorithm sk) $ sign sk pk hs

class SecretKey sk where
	type PubKey sk
	pubKey :: sk -> X509.SignedCertificate -> PubKey sk
	sign :: sk -> PubKey sk -> BS.ByteString -> BS.ByteString
	algorithm :: sk -> (HashAlg, SignAlg)

instance SecretKey RSA.PrivateKey where
	type PubKey RSA.PrivateKey = RSA.PublicKey
	pubKey _ c = case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA pk -> pk
		_ -> error "TlsClient: RSA.PrivateKey.pubKey"
	sign sk pk m = let pd = rsaPadding pk m in RSA.dp Nothing sk pd
	algorithm _ = (Sha256, Rsa)

instance SecretKey ECDSA.PrivateKey where
	type PubKey ECDSA.PrivateKey = ()
	pubKey _ _ = ()
	sign sk _ m = enc $ blindSign 0 id sk (generateKs (SHA256.hash, 64) q x m) m
		where
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
		enc (ECDSA.Signature r s) = ASN1.encodeASN1' ASN1.DER [
			ASN1.Start ASN1.Sequence,
				ASN1.IntVal r, ASN1.IntVal s,
				ASN1.End ASN1.Sequence]
	algorithm _ = (Sha256, Ecdsa)
