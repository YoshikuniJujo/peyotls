{-|

Module		: Network.PeyoTLS.Server
Copyright	: (c) Yoshikuni Jujo, 2014
License		: BSD3
Maintainer	: PAF01143@nifty.ne.jp
Stability	: Experimental

-}

{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.Client (
	-- * Basic
	PeyotlsM, PeyotlsHandle, TlsM, TlsHandle, run, open, names,
	-- * Renegotiation
	renegotiate, setCipherSuites, setKeyCerts, setCertificateStore,
	-- * Cipher Suite
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	-- * Others
	ValidateHandle(..), CertSecretKey(..) ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (when, unless, liftM, ap)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Maybe (fromMaybe)
import Data.List (find, intersect)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified "monads-tf" Control.Monad.Error as E

import qualified Network.PeyoTLS.Base as BASE (names)
import Network.PeyoTLS.Base ( debug,
	PeyotlsM, TlsM, run,
		getSettingsC, setSettingsC,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		withRandom, randomByteString, flushAppData,
		AlertLevel(..), AlertDesc(..), throw,
	ValidateHandle(..), handshakeValidate, validateAlert,
	TlsHandleBase, CertSecretKey(..),
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	ClientHello(..), ServerHello(..), SessionId(..), isRenegoInfo,
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		setCipherSuite,
		checkSvRenego, makeClRenego,
	ServerKeyExEcdhe(..), ServerKeyExDhe(..), SvSignPublicKey(..),
	CertReq(..), ClCertType(..),
	ServerHelloDone(..),
	ClientKeyEx(..), Epms(..), generateKeys, -- encryptRsa,
	DigitallySigned(..), ClSignSecretKey(..), handshakeHash,
	Side(..), RW(..), finishedHash, flushCipherSuite,
	DhParam(..), ecdsaPubKey )

type PeyotlsHandle = TlsHandle Handle SystemRNG

newtype TlsHandle h g = TlsHandleC { tlsHandleC :: TlsHandleBase h g } deriving Show

instance (ValidateHandle h, CPRG g) => HandleLike (TlsHandle h g) where
	type HandleMonad (TlsHandle h g) = TlsM h g
	type DebugLevel (TlsHandle h g) = DebugLevel h
	hlPut = adPut . tlsHandleC
	hlGet = adGet rehandshake . tlsHandleC
	hlGetLine = adGetLine rehandshake . tlsHandleC
	hlGetContent = adGetContent rehandshake . tlsHandleC
	hlDebug = adDebug . tlsHandleC
	hlClose = adClose . tlsHandleC

moduleName :: String
moduleName = "Network.PeyoTLS.Client"

names :: TlsHandle h g -> [String]
names = BASE.names . tlsHandleC

open :: (ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	TlsM h g (TlsHandle h g)
open h cscl crts ca = (TlsHandleC `liftM`) . execHandshakeM h $ do
	setSettingsC (cscl, crts, ca)
	handshake crts ca =<< clientHello cscl

renegotiate :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
renegotiate (TlsHandleC t) = rerunHandshakeM t $ do
	(cscl, crts, ca) <- getSettingsC
	clientHello cscl >>= \cr ->
		flushAppData >>= flip when (handshake crts ca cr)

setCipherSuites :: (ValidateHandle h, CPRG g) => TlsHandle h g ->
	[CipherSuite] -> TlsM h g ()
setCipherSuites (TlsHandleC t) cscl = rerunHandshakeM t $ do
	(_, crts, cs) <- getSettingsC
	setSettingsC (cscl, crts, cs)

setKeyCerts :: (ValidateHandle h, CPRG g) => TlsHandle h g ->
	[(CertSecretKey, X509.CertificateChain)] -> TlsM h g ()
setKeyCerts (TlsHandleC t) crts = rerunHandshakeM t $ do
	(cscl, _, cs) <- getSettingsC
	setSettingsC (cscl, crts, cs)

setCertificateStore :: (ValidateHandle h, CPRG g) => TlsHandle h g ->
	X509.CertificateStore -> TlsM h g ()
setCertificateStore (TlsHandleC t) cs = rerunHandshakeM t $ do
	(cscl, crts, _) <- getSettingsC
	setSettingsC (cscl, crts, cs)

rehandshake :: (ValidateHandle h, CPRG g) => TlsHandleBase h g -> TlsM h g ()
rehandshake t = rerunHandshakeM t $ do
	(cscl, crts, ca) <- getSettingsC
	handshake crts ca =<< clientHello cscl

clientHello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g BS.ByteString
clientHello cscl = do
	cr <- randomByteString 32
	((>>) <$> writeHandshake <*> debug "low")
		. ClientHello (3, 3) cr (SessionId "") cscl [CompMethodNull]
		. Just . (: []) =<< makeClRenego
	return cr

handshake :: (ValidateHandle h, CPRG g) =>
	[(CertSecretKey, X509.CertificateChain)] ->
	X509.CertificateStore -> BS.ByteString -> HandshakeM h g ()
handshake crts ca cr = do
	(sr, ke) <- serverHello
	($ ca) . ($ crts) . ($ (cr, sr)) $ case ke of
		RSA -> rsaHandshake
		DHE_RSA -> dheHandshake (undefined :: DH.Params)
		ECDHE_RSA -> dheHandshake (undefined :: ECC.Curve)
		ECDHE_ECDSA -> dheHandshake (undefined :: ECC.Curve)
		_ -> \_ _ _ -> throw ALFatal ADHsFailure $
			moduleName ++ ".handshake: not implemented"

serverHello :: (HandleLike h, CPRG g) => HandshakeM h g (BS.ByteString, KeyEx)
serverHello = do
	ServerHello v sr _sid cs@(CipherSuite ke _) cm e <- readHandshake
	case v of
		(3, 3) -> return ()
		_ -> throw ALFatal ADProtocolVersion $
			moduleName ++ ".serverHello: only TLS 1.2"
	case cm of
		CompMethodNull -> return ()
		_ -> throw ALFatal ADHsFailure $
			moduleName ++ ".serverHello: only compression method null"
	case find isRenegoInfo $ fromMaybe [] e of
		Just ri -> checkSvRenego ri
		_ -> throw ALFatal ADInsufficientSecurity $
			moduleName ++ ".serverHello: require secure renegotiation"
	setCipherSuite cs
	return (sr, ke)

rsaHandshake :: (ValidateHandle h, CPRG g) => (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
rsaHandshake rs crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	vr <- handshakeValidate ca cc
	unless (null vr) . throw ALFatal (validateAlert vr) $
		moduleName ++ ".rsaHandshake: validate failure"
	pk <- case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA k -> return k
		_ -> throw ALFatal ADIllegalParameter $
			moduleName ++ ".rsaHandshake: require RSA public key"
	crt <- clientCertificate crts
	pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
	generateKeys Client rs pms
	writeHandshake . Epms =<< encryptRsa pk pms
	finishHandshake crt

encryptRsa :: (HandleLike h, CPRG g) =>
	RSA.PublicKey -> BS.ByteString -> HandshakeM h g BS.ByteString
encryptRsa pk p = either (E.throwError . strMsg . show) return =<<
	withRandom (\g -> RSA.encrypt g pk p)

dheHandshake :: (ValidateHandle h, CPRG g,
		KeyExchangeClass ke, Show (Secret ke), Show (Public ke)) =>
	ke -> (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
dheHandshake t rs crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	vr <- handshakeValidate ca cc
	unless (null vr) . throw ALFatal (validateAlert vr) $
		moduleName ++ ".succeed: validate failure"
	case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA pk -> succeed t pk rs crts
		X509.PubKeyECDSA cv pt -> succeed t (ecdsaPubKey cv pt) rs crts
		_ -> throw ALFatal ADHsFailure $
			moduleName ++ ".dheHandshake: not implemented"

succeed :: (ValidateHandle h, CPRG g, SvSignPublicKey pk,
		KeyExchangeClass ke, Show (Secret ke), Show (Public ke)) =>
	ke -> pk -> (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> HandshakeM h g ()
succeed t pk rs@(cr, sr) crts = do
	(ps, pv, ha, sa, sn) <- serverKeyExchange
	let _ = ps `asTypeOf` t
	unless (sa == sspAlgorithm pk) . throw ALFatal ADHsFailure $
		pre ++ "sign algorithm unmatch"
	unless (ssVerify ha pk sn $ BS.concat [cr, sr, B.encode ps, B.encode pv]) .
		throw ALFatal ADDecryptError $ pre ++ "verify failure"
	crt <- clientCertificate crts
	sv <- withRandom $ generateSecret ps
	generateKeys Client rs $ calculateShared ps sv pv
	writeHandshake . ClientKeyEx . B.encode $ calculatePublic ps sv
	finishHandshake crt
	where pre = moduleName ++ ".succeed: "

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

clientCertificate :: (HandleLike h, CPRG g) =>
	[(CertSecretKey, X509.CertificateChain)] ->
	HandshakeM h g (Maybe (CertSecretKey, X509.CertificateChain))
clientCertificate crts = do
	h <- readHandshake
	(\p -> either p (\SHDone -> return Nothing) h) $ \(CertReq cct a dn) -> do
		SHDone <- readHandshake
		case find (isMatchedCert cct a dn) crts of
			Just c ->
				(>>) <$> writeHandshake . snd <*> return . Just $ c
			_ -> throw ALFatal ADUnknownCa $ moduleName ++
				".clientCertificate: no certificate"

isMatchedCert :: [ClCertType] -> [(HashAlg, SignAlg)] ->
	[X509.DistinguishedName] -> (CertSecretKey, X509.CertificateChain) -> Bool
isMatchedCert ct hsa dn = (&&) <$> csk . fst <*> ccrt . snd
	where
	obj = X509.signedObject . X509.getSigned
	rsa = CTRsaSign `elem` ct || Rsa `elem` map snd hsa
	ecdsa = CTEcdsaSign `elem` ct || Ecdsa `elem` map snd hsa
	csk (RsaKey _) = rsa; csk (EcdsaKey _) = ecdsa
	ccrt (X509.CertificateChain cs@(c : _)) =
		cpk (X509.certPubKey $ obj c) &&
		not (null . intersect dn $ map (X509.certIssuerDN . obj) cs)
	ccrt _ = error $ moduleName ++ ".isMatchedCert: empty certificate chain"
	cpk X509.PubKeyRSA{} = rsa; cpk X509.PubKeyECDSA{} = ecdsa; cpk _ = False

finishHandshake :: (HandleLike h, CPRG g) =>
	Maybe (CertSecretKey, X509.CertificateChain) -> HandshakeM h g ()
finishHandshake crt = do
	hs <- handshakeHash
	case fst <$> crt of
		Just (RsaKey sk) -> writeHandshake $
			DigitallySigned (cssAlgorithm sk) $ csSign sk hs
		Just (EcdsaKey sk) -> writeHandshake $
			DigitallySigned (cssAlgorithm sk) $ csSign sk hs
		_ -> return ()
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Client
	getChangeCipherSpec >> flushCipherSuite Read
	(==) `liftM` finishedHash Server `ap` readHandshake >>= flip unless
		(throw ALFatal ADDecryptError $
			moduleName ++ ".finishHandshake: finished hash failure")
