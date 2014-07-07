{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.Server (
	PeyotlsM, PeyotlsHandleS, TlsM, TlsHandleS, run, open, renegotiate, names,
	CipherSuite(..), KeyEx(..), BulkEnc(..), ValidateHandle(..), CertSecretKey
	) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first)
import Control.Monad (when, unless, liftM, ap)
import "monads-tf" Control.Monad.Error (catchError)
import Data.List (find)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import qualified Network.PeyoTLS.Base as HB (names)
import Network.PeyoTLS.Base (
	PeyotlsM, TlsM, run,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		throwError, debug, debugCipherSuite,
		withRandom, randomByteString,
	ValidateHandle(..), handshakeValidate,
	TlsHandle, CertSecretKey(..), isRsaKey, isEcdsaKey,
		readHandshake, getChangeCipherSpec,
		writeHandshake, putChangeCipherSpec,
		writeHandshakeNH,
	AlertLevel(..), AlertDesc(..),
	ClientHello(..), ServerHello(..), SessionId(..), Extension(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		getCipherSuite, setCipherSuite,
		getClientFinished, getServerFinished,
	ServerKeyExchange(..),
	certificateRequest, ClientCertificateType(..), SecretKey(..),
	ServerHelloDone(..),
	ClientKeyExchange(..), Epms(..),
		generateKeys, decryptRsa, rsaPadding,
	DigitallySigned(..), handshakeHash,
	RW(..), flushCipherSuite,
	Side(..), finishedHash,
	DhParam(..), dh3072Modp, secp256r1,

	Handshake(HHelloReq), getSettings, setSettings, flushAppData,
	hlGetRn, hlGetLineRn, hlGetContentRn )

type PeyotlsHandleS = TlsHandleS Handle SystemRNG

newtype TlsHandleS h g = TlsHandleS { tlsHandleS :: TlsHandle h g } deriving Show

instance (ValidateHandle h, CPRG g) => HandleLike (TlsHandleS h g) where
	type HandleMonad (TlsHandleS h g) = TlsM h g
	type DebugLevel (TlsHandleS h g) = DebugLevel h
	hlPut (TlsHandleS t) = hlPut t
	hlGet = hlGetRn rehandshake . tlsHandleS
	hlGetLine = hlGetLineRn rehandshake . tlsHandleS
	hlGetContent = hlGetContentRn rehandshake . tlsHandleS
	hlDebug (TlsHandleS t) = hlDebug t
	hlClose (TlsHandleS t) = hlClose t

type Version = (Word8, Word8)
type Settings = (
	[CipherSuite],
	Maybe (RSA.PrivateKey, X509.CertificateChain),
	Maybe (ECDSA.PrivateKey, X509.CertificateChain),
	Maybe X509.CertificateStore )

version :: Version
version = (3, 3)

names :: TlsHandleS h g -> [String]
names = HB.names . tlsHandleS

open :: (ValidateHandle h, CPRG g) => h ->
	[CipherSuite] -> [(CertSecretKey, X509.CertificateChain)] ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandleS h g)
open h cssv crts mcs = liftM TlsHandleS . execHandshakeM h $
	((>>) <$> setSettings <*> handshake) (cssv',
		first rsaKey <$> find (isRsaKey . fst) crts,
		first ecdsaKey <$> find (isEcdsaKey . fst) crts, mcs )
	where
	cssv' = filter iscs $ case find (isEcdsaKey . fst) crts of
		Just _ -> cssv
		_ -> flip filter cssv $ \cs -> case cs of
			CipherSuite ECDHE_ECDSA _ -> False
			_ -> True
	iscs (CipherSuiteRaw _ _) = False
	iscs TLS_EMPTY_RENEGOTIATION_INFO_SCSV = False
	iscs _ = True

renegotiate :: (ValidateHandle h, CPRG g) => TlsHandleS h g -> TlsM h g ()
renegotiate (TlsHandleS t) = rerunHandshakeM t $ writeHandshakeNH HHelloReq >>
		flushAppData >>= flip when (handshake =<< getSettings)

rehandshake :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
rehandshake t = rerunHandshakeM t $ handshake =<< getSettings

handshake :: (ValidateHandle h, CPRG g) => Settings -> HandshakeM h g ()
handshake (cssv, rcrt, ecrt, mcs) = do
	(ke, be, cr, cv, rn) <- clientHello cssv
	sr <- serverHello (snd <$> rcrt) (snd <$> ecrt) rn
	ha <- case be of
		AES_128_CBC_SHA -> return Sha1
		AES_128_CBC_SHA256 -> return Sha256
		_ -> throwError ALFatal ADInternalError $
			pre ++ "not implemented bulk encryption type"
	mpk <- ($ mcs) . ($ (cr, sr)) $ case (ke, rcrt, ecrt) of
		(RSA, Just (rsk, _), _) -> rsaKeyExchange rsk cv
		(DHE_RSA, Just (rsk, _), _) -> dhKeyExchange ha dh3072Modp rsk
		(ECDHE_RSA, Just (rsk, _), _) -> dhKeyExchange ha secp256r1 rsk
		(ECDHE_ECDSA, _, Just (esk, _)) -> dhKeyExchange ha secp256r1 esk
		_ -> \_ _ -> throwError ALFatal ADInternalError $
			pre ++ "no implemented key exchange type or " ++
				"no applicable certificate files"
	maybe (return ()) certificateVerify mpk
	getChangeCipherSpec >> flushCipherSuite Read
	(==) `liftM` finishedHash Client `ap` readHandshake >>= \ok ->
		unless ok $ throwError ALFatal ADDecryptError $
			pre ++ "wrong finished hash"
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Server
	where pre = "Network.PeyoTLS.Server.handshake: "

clientHello :: (HandleLike h, CPRG g) => [CipherSuite] ->
	HandshakeM h g (KeyEx, BulkEnc, BS.ByteString, Version, Bool)
clientHello cssv = do
	cf0 <- getClientFinished
	ch@(ClientHello cv cr _sid cscl cms me) <- readHandshake
	let (cf, rn) = case me of
		Nothing -> ("", False)
		Just e -> case getRenegoInfo cscl e of
			Nothing -> ("", False)
			Just c -> (c, True)
	debug "medium" ch
	unless (cf == cf0) $ throwError ALFatal ADHandshakeFailure
		"Network.PeyoTLS.Server.clientHello: bad renegotiation"
	chk cv cscl cms
	setCipherSuite $ merge cssv cscl
	(ke, be) <- case merge cssv cscl of
		CipherSuite k b -> return (k, b)
		_ -> throwError ALFatal ADInternalError $ pre ++ "never occur"
	return (ke, be, cr, cv, rn)
	where
	pre = "Network.PeyoTLS.Server.clientHello: "
	merge sv cl = case find (`elem` cl) sv of
		Just cs -> cs; _ -> CipherSuite RSA AES_128_CBC_SHA
	chk cv _css cms
		| cv < version = throwError ALFatal ADProtocolVersion $
			pmsg ++ "client version should 3.3 or more"
		| CompMethodNull `notElem` cms =
			throwError ALFatal ADDecodeError $
				pmsg ++ "compression method NULL must be supported"
		| otherwise = return ()
		where pmsg = "TlsServer.clientHello: "
	getRenegoInfo [] [] = Nothing
	getRenegoInfo (TLS_EMPTY_RENEGOTIATION_INFO_SCSV : _) _ = Just ""
	getRenegoInfo (_ : css) e = getRenegoInfo css e
	getRenegoInfo [] (ERenegoInfo rn : _) = Just rn
	getRenegoInfo [] (_ : es) = getRenegoInfo [] es

serverHello :: (HandleLike h, CPRG g) =>
	Maybe X509.CertificateChain -> Maybe X509.CertificateChain -> Bool ->
	HandshakeM h g BS.ByteString
serverHello rcc ecc rn = do
	cs@(CipherSuite ke _) <- getCipherSuite
	sr <- randomByteString 32
	cf <- getClientFinished
	sf <- getServerFinished
	writeHandshake . ServerHello
		version sr (SessionId "") cs CompMethodNull $ if rn
			then Just [ERenegoInfo $ cf `BS.append` sf]
			else Nothing
	debug "critical" ("SERVER HASH AFTER SERVERHELLO" :: String)
	debug "critical" =<< handshakeHash
	writeHandshake $ case (ke, rcc, ecc) of
		(ECDHE_ECDSA, _, Just c) -> c
		(_, Just c, _) -> c
		_ -> error "serverHello"
	return sr
	{-
serverHello _ _ _ _ = throwError ALFatal ADInternalError
	"Network.PeyoTLS.Server.serverHello: never occur"
	-}

rsaKeyExchange :: (ValidateHandle h, CPRG g) => RSA.PrivateKey -> Version ->
	(BS.ByteString, BS.ByteString) -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
rsaKeyExchange rsk cv rs mcs = return const
	`ap` requestAndCertificate mcs
	`ap` rsaClientKeyExchange rsk cv rs

dhKeyExchange :: (ValidateHandle h, CPRG g, SecretKey sk, Show (Secret dp),
		Show (Public dp),
		DhParam dp, B.Bytable dp, B.Bytable (Public dp)) =>
	HashAlg -> dp -> sk ->
	(BS.ByteString, BS.ByteString) -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
dhKeyExchange ha dp ssk rs mcs = do
	sv <- withRandom $ generateSecret dp
	serverKeyExchange ha dp sv ssk rs
	return const
		`ap` requestAndCertificate mcs
		`ap` dhClientKeyExchange dp sv rs

serverKeyExchange :: (HandleLike h, CPRG g, SecretKey sk,
		DhParam dp, B.Bytable dp, B.Bytable (Public dp)) =>
	HashAlg -> dp -> Secret dp -> sk ->
	(BS.ByteString, BS.ByteString) -> HandshakeM h g ()
serverKeyExchange ha dp sv ssk (cr, sr) = do
	bl <- withRandom $ generateBlinder ssk
	writeHandshake
		. ServerKeyEx edp pv ha (signatureAlgorithm ssk)
		. sign ha bl ssk $ BS.concat [cr, sr, edp, pv]
	where
	edp = B.encode dp
	pv = B.encode $ calculatePublic dp sv

requestAndCertificate :: (ValidateHandle h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
requestAndCertificate mcs = do
	flip (maybe $ return ()) mcs $ writeHandshake . certificateRequest
		[CTRsaSign, CTEcdsaSign] [(Sha256, Rsa), (Sha256, Ecdsa)]
	writeHandshake ServerHelloDone
	debug "high" ("SERVER HASH AFTER SERVERHELLODONE" :: String)
	debug "high" =<< handshakeHash
	maybe (return Nothing) (liftM Just . clientCertificate) mcs

clientCertificate :: (ValidateHandle h, CPRG g) =>
	X509.CertificateStore -> HandshakeM h g X509.PubKey
clientCertificate cs = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	chk cc
	return . X509.certPubKey $ X509.getCertificate c
	where
	chk cc = do
		rs <- handshakeValidate cs cc
		unless (null rs) . throwError ALFatal (selectAlert rs) $
			"TlsServer.clientCertificate: " ++ show rs
	selectAlert rs
		| X509.UnknownCA `elem` rs = ADUnknownCa
		| X509.Expired `elem` rs = ADCertificateExpired
		| X509.InFuture `elem` rs = ADCertificateExpired
		| otherwise = ADCertificateUnknown

rsaClientKeyExchange :: (HandleLike h, CPRG g) => RSA.PrivateKey ->
	Version -> (BS.ByteString, BS.ByteString) -> HandshakeM h g ()
rsaClientKeyExchange sk (cvj, cvn) rs = do
	Epms epms <- readHandshake
	debug "low" ("EPMS" :: String)
	debug "low" epms
	generateKeys Server rs =<< mkpms epms `catchError` const
		((BS.cons cvj . BS.cons cvn) `liftM` randomByteString 46)
	where
	mkpms epms = do
		pms <- decryptRsa sk epms
		unless (BS.length pms == 48) $
			throwError ALFatal ADHandshakeFailure ""
		case BS.unpack $ BS.take 2 pms of
			[pvj, pvn] -> unless (pvj == cvj && pvn == cvn) $
				throwError ALFatal ADHandshakeFailure ""
			_ -> error $ "Network.PeyoTLS.Server." ++
				"rsaClientKeyExchange: never occur"
		debug "low" ("PMS" :: String)
		debug "low" pms
		return pms

dhClientKeyExchange :: (HandleLike h, CPRG g, DhParam dp, B.Bytable (Public dp),
	Show (Public dp)) =>
	dp -> Secret dp -> (BS.ByteString, BS.ByteString) -> HandshakeM h g ()
dhClientKeyExchange dp sv rs = do
	ClientKeyExchange cke <- readHandshake
	let Right pv = B.decode cke
	generateKeys Server rs =<< case Right $ calculateShared dp sv pv of
		Left em -> throwError ALFatal ADInternalError $
			"Network.PeyoTLS.Server.dhClientKeyExchange: " ++ em
		Right sh -> return sh

certificateVerify :: (HandleLike h, CPRG g) => X509.PubKey -> HandshakeM h g ()
certificateVerify (X509.PubKeyRSA pk) = do
	debugCipherSuite "RSA"
	hs0 <- rsaPadding pk `liftM` handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(Sha256, Rsa) -> return ()
		_ -> throwError ALFatal ADDecodeError $
			"TlsServer.certificateVEerify: not implement: " ++ show a
	unless (RSA.ep pk s == hs0) $ throwError ALFatal ADDecryptError
		"TlsServer.certificateVerify: client auth failed "
certificateVerify (X509.PubKeyECDSA ECC.SEC_p256r1 xy) = do
	debugCipherSuite "ECDSA"
	hs0 <- handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(Sha256, Ecdsa) -> return ()
		_ -> throwError ALFatal ADDecodeError $
			"TlsServer.certificateverify: not implement: " ++ show a
	unless (ECDSA.verify id
		(ECDSA.PublicKey secp256r1 $ pnt xy)
		(either error id $ B.decode s) hs0) $ throwError
			ALFatal ADDecryptError
			"TlsServer.certificateverify: client auth failed"
	where
	pnt s = let (x, y) = BS.splitAt 32 $ BS.drop 1 s in ECC.Point
		(either error id $ B.decode x)
		(either error id $ B.decode y)
certificateVerify p = throwError ALFatal ADUnsupportedCertificate $
	"TlsServer.certificateVerify: not implement: " ++ show p
