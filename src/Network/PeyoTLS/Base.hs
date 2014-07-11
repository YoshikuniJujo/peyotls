{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Base (
	PeyotlsM, TlsM, run, SettingsS,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		getSettingsC, setSettingsC, getSettingsS, setSettingsS,
		withRandom, flushAppData,
		AlertLevel(..), AlertDesc(..), throw,
		debugCipherSuite, debug,
	ValidateHandle(..), handshakeValidate, validateAlert,
	TlsHandleBase, names,
		CertSecretKey(..), isRsaKey, isEcdsaKey,
		readHandshake, writeHandshake,
		ChangeCipherSpec(..),
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
	DhParam(..), ecdsaPubKey ) where

import Control.Arrow (first)
import Control.Monad (unless, liftM, ap)
import "monads-tf" Control.Monad.State (gets, lift)
import Data.Bits (shiftR)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG, cprgGenerate)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
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
import qualified Network.PeyoTLS.Run as RUN (finishedHash)
import Network.PeyoTLS.Run (
	TlsM, run, TlsHandleBase(..),
		chGet, hsPut, updateHash, ccsPut,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		withRandom, flushAppData,
		SettingsS, getSettingsS, setSettingsS,
		getSettingsC, setSettingsC,
		getCipherSuite, setCipherSuite,
		CertSecretKey(..), isRsaKey, isEcdsaKey,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		RW(..), flushCipherSuite, generateKeys,
		Side(..), handshakeHash, -- finishedHash,
	ValidateHandle(..), handshakeValidate, validateAlert,
	AlertLevel(..), AlertDesc(..), debugCipherSuite, throw )
import Network.PeyoTLS.Ecdsa (blSign, makeKs, ecdsaPubKey)

moduleName :: String
moduleName = "Network.PeyoTLS.Base"

type PeyotlsM = TlsM Handle SystemRNG

debug :: (HandleLike h, Show a) => DebugLevel h -> a -> HandshakeM h g ()
debug p x = do
	h <- gets $ tlsHandle . fst
	lift . lift . lift . hlDebug h p . BSC.pack . (++ "\n") $ show x

readHandshake :: (HandleLike h, CPRG g, HandshakeItem hi) => HandshakeM h g hi
readHandshake = do
	ch <- chGet
	case ch of
		Left 1 -> case fromHandshake HCCSpec of
			Just i -> return i
			_ -> throw ALFatal ADUnexpectedMessage $
				moduleName ++ ".readHandshake: " ++ show HCCSpec
		Right bs -> case B.decode bs of
			Right HHelloReq -> readHandshake
			Right hs -> case fromHandshake hs of
				Just i -> updateHash bs >> return i
				_ -> throw ALFatal ADUnexpectedMessage $
					moduleName ++ ".readHandshake: " ++ show hs
			Left em -> throw ALFatal ADInternalError $
				moduleName ++ ".readHandshake: " ++ em
		_ -> throw ALFatal ADUnexpectedMessage $
			moduleName ++ ".readHandshake: bad change cipher spec"

writeHandshake:: (HandleLike h, CPRG g, HandshakeItem hi) => hi -> HandshakeM h g ()
writeHandshake hi = do
	case hs of
		HHelloReq -> hsPut bs
		HCCSpec -> ccsPut . (\[w] -> w) $ BS.unpack bs
		_ -> hsPut bs >> updateHash bs
	where
	hs = toHandshake hi
	bs = B.encode hs

finishedHash :: (HandleLike h, CPRG g) => Side -> HandshakeM h g Finished
finishedHash s = Finished `liftM` do
	fh <- RUN.finishedHash s
	case s of Client -> setClFinished fh; Server -> setSvFinished fh
	return fh

checkClRenego, checkSvRenego :: HandleLike h => Extension -> HandshakeM h g ()
checkClRenego (ERenegoInfo ri) = do
	ok <- (ri ==) `liftM` getClFinished
	unless ok . throw ALFatal ADHsFailure $
		moduleName ++ ".checkClRenego: renego info is not match"
checkClRenego _ = throw ALFatal ADInternalError $
	moduleName ++ ".checkClRenego: not renego info"
checkSvRenego (ERenegoInfo ri) = do
	ok <- (ri ==) `liftM` (BS.append `liftM` getClFinished `ap` getSvFinished)
	unless ok . throw ALFatal ADHsFailure $
		moduleName ++ ".checkSvRenego: renego info is not match"
checkSvRenego _ = throw ALFatal ADInternalError $
	moduleName ++ ".checkSvRenego: not renego info"

makeClRenego, makeSvRenego :: HandleLike h => HandshakeM h g Extension
makeClRenego = ERenegoInfo `liftM` getClFinished
makeSvRenego =
	ERenegoInfo `liftM` (BS.append `liftM` getClFinished `ap` getSvFinished)

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
	calculateShared =
		(((B.encode . (\(DH.SharedKey s) -> s)) .) .) . DH.getShared

instance DhParam ECC.Curve where
	type Secret ECC.Curve = Integer
	type Public ECC.Curve = ECC.Point
	generateSecret c = rec
		where
		rec g = let
			(bs, g') = cprgGenerate bl g
			i = either error id $ B.decode bs in
			if 1 <= i && i <= mx then (i, g') else rec g'
		bl = len mx `div` 8 + signum (len mx `mod` 8)
		mx = ECC.ecc_n (ECC.common_curve c) - 1
		len 0 = 0; len i = succ . len $ i `shiftR` 1
	calculatePublic cv sn = ECC.pointMul cv sn . ECC.ecc_g $ ECC.common_curve cv
	calculateShared cv sn pp =
		let ECC.Point x _ = ECC.pointMul cv sn pp in B.encode x


sha1, sha256 :: ASN1.ASN1
sha1 = ASN1.OID [1, 3, 14, 3, 2, 26]
sha256 = ASN1.OID [2, 16, 840, 1, 101, 3, 4, 2, 1]

padding :: RSA.PublicKey -> BS.ByteString -> BS.ByteString
padding pk bs = case RSA.padSignature (RSA.public_size pk) $
				HD.digestToASN1 HD.hashDescrSHA256 bs of
	Left m -> error $ show m; Right pd -> pd

class SvSignPublicKey pk where
	sspAlgorithm :: pk -> SignAlg
	ssVerify :: HashAlg -> pk -> BS.ByteString -> BS.ByteString -> Bool

instance SvSignPublicKey RSA.PublicKey where
	sspAlgorithm _ = Rsa
	ssVerify ha pk sn m = oid == oid0 && e == hs m
		where
		(hs, oid0) = case ha of
			Sha1 -> (SHA1.hash, sha1); Sha256 -> (SHA256.hash, sha256)
			_ -> error $ moduleName ++ ": RSA.PublicKey.ssVerify"
		(e, oid) = case ASN1.decodeASN1' ASN1.DER . BS.tail
			. BS.dropWhile (== 255) . BS.drop 2 $ RSA.ep pk sn of
			Right [ASN1.Start ASN1.Sequence,
				ASN1.Start ASN1.Sequence,
					i, ASN1.Null, ASN1.End ASN1.Sequence,
				ASN1.OctetString o,
				ASN1.End ASN1.Sequence ] -> (o, i)
			em -> error $
				moduleName ++ ": RSA.PublicKey.ssVerify" ++ show em

instance SvSignPublicKey ECDSA.PublicKey where
	sspAlgorithm _ = Ecdsa
	ssVerify Sha1 pk = ECDSA.verify SHA1.hash pk . either error id . B.decode
	ssVerify Sha256 pk =
		ECDSA.verify SHA256.hash pk . either error id . B.decode
	ssVerify _ _ = error $ moduleName ++ ": ECDSA.PublicKey.verify"

class SvSignSecretKey sk where
	type Blinder sk
	sssAlgorithm :: sk -> SignAlg
	generateBlinder :: CPRG g => sk -> g -> (Blinder sk, g)
	ssSign :: sk -> HashAlg -> Blinder sk -> BS.ByteString -> BS.ByteString

instance SvSignSecretKey RSA.PrivateKey where
	type Blinder RSA.PrivateKey = RSA.Blinder
	sssAlgorithm _ = Rsa
	generateBlinder sk g =
		RSA.generateBlinder g . RSA.public_n $ RSA.private_pub sk
	ssSign sk ha bl m = RSA.dp (Just bl) sk e
		where
		(hs, oid) = first ($ m) $ case ha of
			Sha1 -> (SHA1.hash, sha1); Sha256 -> (SHA256.hash, sha256)
			_ -> error $ moduleName ++ ": RSA.PrivateKey.ssSign"
		b = ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence,
			ASN1.Start ASN1.Sequence,
				oid, ASN1.Null, ASN1.End ASN1.Sequence,
			ASN1.OctetString hs, ASN1.End ASN1.Sequence]
		e = BS.concat ["\0\1", BS.replicate (s - BS.length b) 255, "\0", b]
		s = RSA.public_size (RSA.private_pub sk) - 3

instance SvSignSecretKey ECDSA.PrivateKey where
	type Blinder ECDSA.PrivateKey = Integer
	sssAlgorithm _ = Ecdsa
	generateBlinder _ g = (bl, g')
		where
		bl = either error id $ B.decode bs; (bs, g') = cprgGenerate 32 g
	ssSign sk ha bl m = B.encode $ blSign sk hs (makeKs (hs, bls) q x m) bl m
		where
		(hs, bls) = case ha of
			Sha1 -> (SHA1.hash, 64); Sha256 -> (SHA256.hash, 64)
			_ -> error $ moduleName ++ ": ECDSA.PrivateKey.ssSign"
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk

class ClSignPublicKey pk where
	cspAlgorithm :: pk -> SignAlg
	csVerify :: pk -> BS.ByteString -> BS.ByteString -> Bool

instance ClSignPublicKey RSA.PublicKey where
	cspAlgorithm _ = Rsa
	csVerify pk s h = RSA.ep pk s == padding pk h

instance ClSignPublicKey ECDSA.PublicKey where
	cspAlgorithm _ = Ecdsa
	csVerify pk = ECDSA.verify id pk . either error id . B.decode

class ClSignSecretKey sk where
	cssAlgorithm :: sk -> (HashAlg, SignAlg)
	csSign :: sk -> BS.ByteString -> BS.ByteString

instance ClSignSecretKey RSA.PrivateKey where
	cssAlgorithm _ = (Sha256, Rsa)
	csSign sk m = RSA.dp Nothing sk $ padding (RSA.private_pub sk) m

instance ClSignSecretKey ECDSA.PrivateKey where
	cssAlgorithm _ = (Sha256, Ecdsa)
	csSign sk m = enc $ blSign sk id (makeKs (SHA256.hash, 64) q x m) 0 m
		where
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
		enc (ECDSA.Signature r s) = ASN1.encodeASN1' ASN1.DER [
			ASN1.Start ASN1.Sequence,
				ASN1.IntVal r, ASN1.IntVal s,
				ASN1.End ASN1.Sequence]
