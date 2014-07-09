{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.Server (
	PeyotlsM, PeyotlsHandleS, TlsM, TlsHandleS, run, open, renegotiate, names,
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	ValidateHandle(..), CertSecretKey(..) ) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first)
import Control.Monad (when, unless, liftM, ap)
import "monads-tf" Control.Monad.Error (catchError)
import Data.Maybe (listToMaybe, mapMaybe)
import Data.List (find)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.PubKey.RSA as RSA

import qualified Network.PeyoTLS.Base as BASE (names)
import Network.PeyoTLS.Base (
	PeyotlsM, TlsM, run,
		SettingsS, getSettings, setSettings,
		hlGetRn, hlGetLineRn, hlGetContentRn,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		withRandom, randomByteString, flushAppData,
		throwError, debugCipherSuite,
	ValidateHandle(..), handshakeValidate, validateAlert,
	TlsHandle, CertSecretKey(..), isRsaKey, isEcdsaKey,
		readHandshake, getChangeCipherSpec,
		writeHandshake, writeHandshakeNH, putChangeCipherSpec,
	AlertLevel(..), AlertDesc(..),
	Handshake(HHelloReq),
	ClientHello(..), ServerHello(..), SessionId(..),
		Extension(..), eRenegoInfo,
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		getCipherSuite, setCipherSuite,
		checkClientRenego, makeServerRenego,
	ServerKeyExchange(..),
	certificateRequest, ClientCertificateType(..),
	ServerHelloDone(..),
	ClientKeyExchange(..), Epms(..), SecretKey(..), generateKeys, decryptRsa,
	DigitallySigned(..), ClSignPublicKey(..), handshakeHash,
	RW(..), flushCipherSuite,
	Side(..), finishedHash,
	DhParam(..), makeEcdsaPubKey, dh3072Modp, secp256r1 )

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

version :: Version
version = (3, 3)

moduleName :: String
moduleName = "Network.PeyoTLS.Server"

names :: TlsHandleS h g -> [String]
names = BASE.names . tlsHandleS

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
	iscs EMPTY_RENEGOTIATION_INFO = False
	iscs _ = True

renegotiate :: (ValidateHandle h, CPRG g) => TlsHandleS h g -> TlsM h g ()
renegotiate (TlsHandleS t) = rerunHandshakeM t $ writeHandshakeNH HHelloReq >>
		flushAppData >>= flip when (handshake =<< getSettings)

rehandshake :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
rehandshake t = rerunHandshakeM t $ handshake =<< getSettings

handshake :: (ValidateHandle h, CPRG g) => SettingsS -> HandshakeM h g ()
handshake (cssv, rcrt, ecrt, mcs) = do
	(ke, be, cr, cv) <- clientHello cssv
	sr <- serverHello (snd <$> rcrt) (snd <$> ecrt)
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
	case mpk of
		Just (X509.PubKeyRSA pk) -> certVerify pk
		Just (X509.PubKeyECDSA c xy) -> certVerify $ makeEcdsaPubKey c xy
		Just pk -> throwError ALFatal ADUnsupportedCertificate $
			pre ++ "not implement: " ++ show pk
		Nothing -> return ()
	getChangeCipherSpec >> flushCipherSuite Read
	(==) `liftM` finishedHash Client `ap` readHandshake >>= \ok -> unless ok .
		throwError ALFatal ADDecryptError $ pre ++ "wrong finished hash"
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Server
	where pre = moduleName ++ ".handshake: "

clientHello :: (HandleLike h, CPRG g) => [CipherSuite] ->
	HandshakeM h g (KeyEx, BulkEnc, BS.ByteString, Version)
clientHello cssv = do
	ClientHello cv cr _sid cscl cms me <- readHandshake
	checkRenegoInfo cscl me
	unless (cv >= version) . throwError ALFatal ADProtocolVersion $
		pre ++ "client version should 3.3 or more"
	unless (CompMethodNull `elem` cms) . throwError ALFatal ADDecodeError $
		pre ++ "compression method NULL must be supported"
	(ke, be) <- case find (`elem` cscl) cssv of
		Just cs@(CipherSuite k b) -> setCipherSuite cs >> return (k, b)
		_ -> throwError ALFatal ADHsFailure $
			pre ++ "no acceptable set of security parameters: \n\t" ++
			"cscl: " ++ show cscl ++ "\n\t" ++
			"cssv: " ++ show cssv ++ "\n\t"
	return (ke, be, cr, cv)
	where pre = moduleName ++ ".clientHello: "

checkRenegoInfo ::
	HandleLike h => [CipherSuite] -> Maybe [Extension] -> HandshakeM h g ()
checkRenegoInfo cscl me = (\n -> maybe n checkClientRenego mcf) . throwError
	ALFatal ADInsufficientSecurity $
		moduleName ++ ".checkRenego: require secure renegotiation"
	where mcf = case (EMPTY_RENEGOTIATION_INFO `elem` cscl, me) of
		(True, _) -> Just ""
		(_, Just e) -> listToMaybe $ mapMaybe eRenegoInfo e
		(_, _) -> Nothing

serverHello :: (HandleLike h, CPRG g) =>
	Maybe X509.CertificateChain -> Maybe X509.CertificateChain ->
	HandshakeM h g BS.ByteString
serverHello rcc ecc = do
	cs <- getCipherSuite
	ke <- case cs of
		CipherSuite k _ -> return k
		_ -> throwError ALFatal ADInternalError $
			moduleName ++ ".serverHello: never occur"
	sr <- randomByteString 32
	writeHandshake
		. ServerHello version sr (SessionId "") cs CompMethodNull
		. Just . (: []) =<< makeServerRenego
	writeHandshake =<< case (ke, rcc, ecc) of
		(ECDHE_ECDSA, _, Just c) -> return c
		(_, Just c, _) -> return c
		_ -> throwError ALFatal ADInternalError $
			moduleName ++ ".serverHello: cert files not match"
	return sr

rsaKeyExchange :: (ValidateHandle h, CPRG g) => RSA.PrivateKey -> Version ->
	(BS.ByteString, BS.ByteString) -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
rsaKeyExchange sk (vj, vn) rs mcs = const `liftM` reqAndCert mcs `ap` do
	Epms epms <- readHandshake
	generateKeys Server rs =<< mkpms epms `catchError` const
		((BS.cons vj . BS.cons vn) `liftM` randomByteString 46)
	where mkpms epms = do
		pms <- decryptRsa sk epms
		unless (BS.length pms == 48) $ throwError ALFatal ADHsFailure ""
		let [pvj, pvn] = BS.unpack $ BS.take 2 pms
		unless (pvj == vj && pvn == vn) $ throwError ALFatal ADHsFailure ""
		return pms

dhKeyExchange :: (ValidateHandle h, CPRG g, SecretKey sk,
		DhParam dp, B.Bytable dp, B.Bytable (Public dp)) =>
	HashAlg -> dp -> sk -> (BS.ByteString, BS.ByteString) ->
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
dhKeyExchange ha dp sk rs@(cr, sr) mcs = do
	sv <- withRandom $ generateSecret dp
	bl <- withRandom $ generateBlinder sk
	let pvs = B.encode $ calculatePublic dp sv
	writeHandshake
		. ServerKeyEx edp pvs ha (signatureAlgorithm sk)
		. sign ha bl sk $ BS.concat [cr, sr, edp, pvs]
	const `liftM` reqAndCert mcs `ap` do
		ClientKeyExchange cke <- readHandshake
		pvc <- case B.decode cke of
			Left em -> throwError ALFatal ADInternalError $ pre ++ em
			Right pv -> return pv
		generateKeys Server rs =<< case Right $ calculateShared dp sv pvc of
			Left em -> throwError ALFatal ADInternalError $ pre ++ em
			Right sh -> return sh
	where
	edp = B.encode dp
	pre = "Network.PeyoTLS.Server.dhKeyExchange: "

reqAndCert :: (ValidateHandle h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
reqAndCert mcs = do
	flip (maybe $ return ()) mcs $ writeHandshake . certificateRequest
		[CTRsaSign, CTEcdsaSign] [(Sha256, Rsa), (Sha256, Ecdsa)]
	writeHandshake ServerHelloDone
	flip (maybe $ return Nothing) mcs $ liftM Just . \cs -> do
		cc@(X509.CertificateChain (c : _)) <- readHandshake
		vr <- handshakeValidate cs cc
		unless (null vr) . throwError ALFatal (validateAlert vr) $
			"Network.PeyoTLS.Server.reqAndCert: " ++ show vr
		return . X509.certPubKey $ X509.getCertificate c

certVerify :: (HandleLike h, CPRG g, ClSignPublicKey pk) =>
	pk -> HandshakeM h g ()
certVerify pk = do
	debugCipherSuite . show $ clspAlgorithm pk
	hs0 <- handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(Sha256, sa)
			| sa == clspAlgorithm pk -> return ()
		_ -> throwError ALFatal ADDecodeError $
			moduleName ++ ".certVerify: not implement: " ++ show a
	unless (clsVerify pk s hs0) . throwError ALFatal ADDecryptError $
		moduleName ++ ".certVerify: client auth failed "
