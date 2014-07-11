{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Base (
	PeyotlsM, TlsM, run, SettingsS,
		adGet, adGetLine, adGetContent,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		getSettingsC, setSettingsC, getSettingsS, setSettingsS,
		withRandom, randomByteString, flushAppData,
		AlertLevel(..), AlertDesc(..), throwError,
		debugCipherSuite, debug,
	ValidateHandle(..), handshakeValidate, validateAlert,
	TlsHandleBase, names,
		CertSecretKey(..), isRsaKey, isEcdsaKey,
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	Handshake(HHelloReq),
	ClientHello(..), ServerHello(..), SessionId(..), Extension(..),
		isRenegoInfo, emptyRenegoInfo,
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		getCipherSuite, setCipherSuite,
		checkClRenego, checkSvRenego, makeClRenego, makeSvRenego,
	ServerKeyEx(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
		SvSignSecretKey(..), SvSignPublicKey(..),
	CertReq(..), certReq, ClCertType(..),
	ServerHelloDone(..),
	ClientKeyEx(..), Epms(..), generateKeys,
	DigitallySigned(..), ClSignPublicKey(..), ClSignSecretKey(..),
		handshakeHash,
	RW(..), flushCipherSuite,
	Side(..), finishedHash,
	DhParam(..), makeEcdsaPubKey ) where

import Control.Applicative
import Control.Arrow (first)
import Control.Monad (unless, liftM, ap)
import "monads-tf" Control.Monad.State (gets, lift)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG, cprgGenerate)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import qualified Crypto.PubKey.HashDescr as HD
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import Network.PeyoTLS.Types (
	Handshake(..), HandshakeItem(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), Extension(..), isRenegoInfo, emptyRenegoInfo,
	ServerKeyEx(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
	CertReq(..), certReq, ClCertType(..), SignAlg(..), HashAlg(..),
	ServerHelloDone(..), ClientKeyEx(..), Epms(..),
	DigitallySigned(..), ChangeCipherSpec(..), Finished(..) )
import qualified Network.PeyoTLS.Run as RUN (
	getSettingsC, setSettingsC, finishedHash )
import Network.PeyoTLS.Run (
	TlsM, run, TlsHandleBase(..), names,
		hsGet, hsPut, updateHash, ccsGet, ccsPut,
		adGet, adGetLine, adGetContent,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		withRandom, randomByteString, flushAppData,
		SettingsS, getSettingsS, setSettingsS,
		-- getSettingsC, setSettingsC,
		getCipherSuite, setCipherSuite,
		CertSecretKey(..), isRsaKey, isEcdsaKey,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		RW(..), flushCipherSuite, generateKeys,
		Side(..), handshakeHash, -- finishedHash,
	ValidateHandle(..), handshakeValidate, validateAlert,
	AlertLevel(..), AlertDesc(..), debugCipherSuite, throwError )
import Network.PeyoTLS.Ecdsa (blindSign, generateKs, makeEcdsaPubKey)

type PeyotlsM = TlsM Handle SystemRNG

debug :: (HandleLike h, Show a) => DebugLevel h -> a -> HandshakeM h g ()
debug p x = do
	h <- gets $ tlsHandle . fst
	lift . lift . lift . hlDebug h p . BSC.pack . (++ "\n") $ show x

readHandshake :: (HandleLike h, CPRG g, HandshakeItem hi) => HandshakeM h g hi
readHandshake = do
	bs <- hsGet
	case B.decode bs of
		Right HHelloReq -> readHandshake
		Right hs -> case fromHandshake hs of
			Just i -> do
				updateHash bs
				return i
			_ -> throwError
				ALFatal ADUnexpectedMessage $ moduleName ++
				".readHandshake: type mismatch " ++ show hs
		_ -> throwError ALFatal ADInternalError "bad"

writeHandshake::
	(HandleLike h, CPRG g, HandshakeItem hi) => hi -> HandshakeM h g ()
writeHandshake hi = do
	let	hs = toHandshake hi
		bs = B.encode hs
	hsPut bs
	case hs of
		HHelloReq -> return ()
		_ -> updateHash bs

getChangeCipherSpec :: (HandleLike h, CPRG g) => HandshakeM h g ()
getChangeCipherSpec = do
	w <- ccsGet
	case B.decode $ BS.pack [w] of
		Right ChangeCipherSpec -> return ()
		_ -> throwError ALFatal ADUnexpectedMessage $
			"HandshakeBase.getChangeCipherSpec: " ++
			"not change cipher spec"

putChangeCipherSpec :: (HandleLike h, CPRG g) => HandshakeM h g ()
putChangeCipherSpec =
	ccsPut . (\[w] -> w) . BS.unpack $ B.encode ChangeCipherSpec

class DhParam b where
	type Secret b
	type Public b
	generateSecret :: CPRG g => b -> g -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateShared :: b -> Secret b -> Public b -> BS.ByteString

instance DhParam DH.Params where
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateSecret = flip DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateShared ps sn pn = B.encode .
		(\(DH.SharedKey s) -> s) $ DH.getShared ps sn pn

instance DhParam ECC.Curve where
	type Secret ECC.Curve = Integer
	type Public ECC.Curve = ECC.Point
	generateSecret c = getRangedInteger 32 1 (n - 1)
		where n = ECC.ecc_n $ ECC.common_curve c
	calculatePublic cv sn =
		ECC.pointMul cv sn . ECC.ecc_g $ ECC.common_curve cv
	calculateShared cv sn pp =
		let ECC.Point x _ = ECC.pointMul cv sn pp in B.encode x

getRangedInteger :: CPRG g => Int -> Integer -> Integer -> g -> (Integer, g)
getRangedInteger b mn mx g = let
	(n, g') = first (either error id . B.decode) $ cprgGenerate b g in
	if mn <= n && n <= mx then (n, g') else getRangedInteger b mn mx g'

finishedHash :: (HandleLike h, CPRG g) => Side -> HandshakeM h g Finished
finishedHash s = (Finished `liftM`) $ do
	fh <- RUN.finishedHash s
	case s of
		Client -> setClFinished fh
		Server -> setSvFinished fh
	return fh

checkClRenego, checkSvRenego :: HandleLike h => Extension -> HandshakeM h g ()
checkClRenego (ERenegoInfo cf) = (cf ==) `liftM` getClFinished >>= \ok ->
	unless ok . throwError ALFatal ADHsFailure $
		"Network.PeyoTLS.Base.checkClientRenego: bad renegotiation"
checkClRenego _ = throwError ALFatal ADInternalError "bad"
checkSvRenego (ERenegoInfo ri) = do
	cf <- getClFinished
	sf <- getSvFinished
	unless (ri == cf `BS.append` sf) $ throwError
		ALFatal ADHsFailure
		"Network.PeyoTLS.Base.checkServerRenego: bad renegotiation"
checkSvRenego _ = throwError ALFatal ADInternalError "bad"

makeClRenego, makeSvRenego :: HandleLike h => HandshakeM h g Extension
makeClRenego = ERenegoInfo `liftM` getClFinished
makeSvRenego = ERenegoInfo `liftM`
	(BS.append `liftM` getClFinished `ap` getSvFinished)

type SettingsC = (
	[CipherSuite],
	[(CertSecretKey, X509.CertificateChain)],
	X509.CertificateStore )

getSettingsC :: HandleLike h => HandshakeM h g SettingsC
getSettingsC = do
	(css, crts, mcs) <- RUN.getSettingsC
	case mcs of
		Just cs -> return (css, crts, cs)
		_ -> throwError ALFatal ADInternalError
			"Network.PeyoTLS.Base.getSettingsC"

setSettingsC :: HandleLike h => SettingsC -> HandshakeM h g ()
setSettingsC (css, crts, cs) = RUN.setSettingsC (css, crts, Just cs)

moduleName :: String
moduleName = "Network.PeyoTLS.Base"

class SvSignPublicKey pk where
	svpAlgorithm :: pk -> SignAlg
	verify :: HashAlg -> pk -> BS.ByteString -> BS.ByteString -> Bool

instance SvSignPublicKey RSA.PublicKey where
	svpAlgorithm _ = Rsa
	verify = rsaVerify

rsaVerify :: HashAlg -> RSA.PublicKey -> BS.ByteString -> BS.ByteString -> Bool
rsaVerify ha pk sn m = let
	(hs, oid0) = case ha of
		Sha1 -> (SHA1.hash, ASN1.OID [1, 3, 14, 3, 2, 26])
		Sha256 -> (SHA256.hash, ASN1.OID [2, 16, 840, 1, 101, 3, 4, 2, 1])
		_ -> error "not implemented"
	(o, oid) = case ASN1.decodeASN1' ASN1.DER . BS.tail
		. BS.dropWhile (== 255) . BS.drop 2 $ RSA.ep pk sn of
		Right [ASN1.Start ASN1.Sequence,
			ASN1.Start ASN1.Sequence, oid_, ASN1.Null, ASN1.End ASN1.Sequence,
			ASN1.OctetString o_, ASN1.End ASN1.Sequence ] -> (o_, oid_)
		e -> error $ show e in
	oid == oid0 && o == hs m

instance SvSignPublicKey ECDSA.PublicKey where
	svpAlgorithm _ = Ecdsa
	verify Sha1 pk = ECDSA.verify SHA1.hash pk . either error id . B.decode
	verify Sha256 pk = ECDSA.verify SHA256.hash pk . either error id . B.decode
	verify _ _ = error "TlsClient: ECDSA.PublicKey.verify: not implemented"

class SvSignSecretKey sk where
	type Blinder sk
	generateBlinder :: CPRG g => sk -> g -> (Blinder sk, g)
	sign :: HashAlg -> Blinder sk -> sk -> BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignAlg

instance SvSignSecretKey RSA.PrivateKey where
	type Blinder RSA.PrivateKey = RSA.Blinder
	generateBlinder sk rng =
		RSA.generateBlinder rng . RSA.public_n $ RSA.private_pub sk
	sign hs bl sk bs = let
		(h, oid) = first ($ bs) $ case hs of
			Sha1 -> (SHA1.hash,
				ASN1.OID [1, 3, 14, 3, 2, 26])
			Sha256 -> (SHA256.hash,
				ASN1.OID [2, 16, 840, 1, 101, 3, 4, 2, 1])
			_ -> error $ "HandshakeBase: " ++
				"not implemented bulk encryption type"
		a = [ASN1.Start ASN1.Sequence,
			ASN1.Start ASN1.Sequence,
				oid, ASN1.Null, ASN1.End ASN1.Sequence,
			ASN1.OctetString h, ASN1.End ASN1.Sequence]
		b = ASN1.encodeASN1' ASN1.DER a
		pd = BS.concat [ "\x00\x01",
			BS.replicate (ps - 3 - BS.length b) 0xff, "\NUL", b ]
		ps = RSA.public_size $ RSA.private_pub sk in
		RSA.dp (Just bl) sk pd
	signatureAlgorithm _ = Rsa

instance SvSignSecretKey ECDSA.PrivateKey where
	type Blinder ECDSA.PrivateKey = Integer
	generateBlinder _ rng = let
		(Right bl, rng') = first B.decode $ cprgGenerate 32 rng in
		(bl, rng')
	sign ha bl sk = B.encode .
		(($) <$> blindSign bl hs sk . generateKs (hs, bls) q x <*> id)
		where
		(hs, bls) = case ha of
			Sha1 -> (SHA1.hash, 64)
			Sha256 -> (SHA256.hash, 64)
			_ -> error $ "HandshakeBase: " ++
				"not implemented bulk encryption type"
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
	signatureAlgorithm _ = Ecdsa

class ClSignSecretKey sk where
	csSign :: sk -> BS.ByteString -> BS.ByteString
	csAlgorithm :: sk -> (HashAlg, SignAlg)

instance ClSignSecretKey RSA.PrivateKey where
	csSign sk m = let pd = rsaPadding (RSA.private_pub sk) m in RSA.dp Nothing sk pd
	csAlgorithm _ = (Sha256, Rsa)

rsaPadding :: RSA.PublicKey -> BS.ByteString -> BS.ByteString
rsaPadding pk bs = case RSA.padSignature (RSA.public_size pk) $
			HD.digestToASN1 HD.hashDescrSHA256 bs of
		Right pd -> pd; Left m -> error $ show m

instance ClSignSecretKey ECDSA.PrivateKey where
	csSign sk m = enc $ blindSign 0 id sk (generateKs (SHA256.hash, 64) q x m) m
		where
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
		enc (ECDSA.Signature r s) = ASN1.encodeASN1' ASN1.DER [
			ASN1.Start ASN1.Sequence,
				ASN1.IntVal r, ASN1.IntVal s,
				ASN1.End ASN1.Sequence]
	csAlgorithm _ = (Sha256, Ecdsa)

class ClSignPublicKey pk where
	cspAlgorithm :: pk -> SignAlg
	csVerify :: pk -> BS.ByteString -> BS.ByteString -> Bool

instance ClSignPublicKey RSA.PublicKey where
	cspAlgorithm _ = Rsa
	csVerify k s h = RSA.ep k s == rsaPadding k h

instance ClSignPublicKey ECDSA.PublicKey where
	cspAlgorithm _ = Ecdsa
	csVerify k = ECDSA.verify id k . either error id . B.decode
