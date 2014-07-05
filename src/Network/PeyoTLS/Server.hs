{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	UndecidableInstances, PackageImports #-}

module Network.PeyoTLS.Server (
	PeyotlsM, PeyotlsHandleS, TlsM, TlsHandleS,
	run, open, renegotiate, names,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..), CertSecretKey ) where

import Control.Monad (when, unless, liftM, ap)
import Data.List (find)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG)

import qualified "monads-tf" Control.Monad.Error as E
import qualified "monads-tf" Control.Monad.Error.Class as E
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

import qualified Network.PeyoTLS.HandshakeBase as HB
import Network.PeyoTLS.HandshakeBase (
	PeyotlsM, TlsM, run,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		setCipherSuite, withRandom, randomByteString,
	ValidateHandle(..), handshakeValidate,
	TlsHandle, CertSecretKey(..),
		readHandshake, getChangeCipherSpec,
		writeHandshake, putChangeCipherSpec,
		writeHandshakeNoHash,
	AlertLevel(..), AlertDesc(..),
	ClientHello(..), ServerHello(..), SessionId(..), Extension(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlg(..), SignAlg(..),
		getClientFinished, setClientFinished,
		getServerFinished, setServerFinished,
	ServerKeyExchange(..),
	certificateRequest, ClientCertificateType(..), SecretKey(..),
	ServerHelloDone(..),
	ClientKeyExchange(..), Epms(..),
		generateKeys, decryptRsa, rsaPadding, debugCipherSuite,
	DigitallySigned(..), handshakeHash, flushCipherSuite,
	Finished(..), Side(..), RW(..), finishedHash,
	DhParam(..), dh3072Modp, secp256r1, throwError,

	hlGetRn, hlGetLineRn, hlGetContentRn, debug )

type PeyotlsHandleS = TlsHandleS Handle SystemRNG

names :: TlsHandleS h g -> [String]
names = HB.names . tlsHandleS

open :: (ValidateHandle h, CPRG g) =>
	h -> [CipherSuite] -> [(CertSecretKey, X509.CertificateChain)] ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandleS h g)
open h cssv crts mcs = (TlsHandleS `liftM`) . execHandshakeM h $ do
	HB.setInitSet (cssv, crts, mcs)
	(cs, cr, cv, rn) <- clientHello $ filterCS crts cssv
	succeed cs cr cv crts mcs rn

renegotiate ::
	(ValidateHandle h, CPRG g) => TlsHandleS h g -> TlsM h g ()
renegotiate (TlsHandleS t) = rerunHandshakeM t $ do
	writeHandshakeNoHash HB.HHelloRequest
	(ret, ne) <- HB.flushAppData
	bf <- HB.getAdBufH
	HB.setAdBufH $ bf `BS.append` ret
	when ne $ handshake

rehandshake :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
rehandshake t = rerunHandshakeM t handshake

handshake :: (ValidateHandle h, CPRG g) => HandshakeM h g ()
handshake = do
	(cssv, crts, mcs) <- HB.getInitSet
	(cs, cr, cv, rn) <- clientHello $ filterCS crts cssv
	debug "critical" ("SERVER HASH AFTER CLIENTHELLO" :: String)
	debug "critical" =<< handshakeHash
	succeed cs cr cv crts mcs rn

clientHello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g (CipherSuite, BS.ByteString, Version, Bool)
clientHello cssv = do
	cf0 <- getClientFinished
	ch@(ClientHello cv cr _sid cscl cms me) <- readHandshake
	let (cf, rn) = case me of
		Nothing -> ("", False)
		Just e -> case getRenegoInfo cscl e of
			Nothing -> ("", False)
			Just c -> (c, True)
	debug "medium" ch
	unless (cf == cf0) $ E.throwError "clientHello"
	chk cv cscl cms >> return (merge cssv cscl, cr, cv, rn)
	where
	merge sv cl = case find (`elem` cl) sv of
		Just cs -> cs; _ -> CipherSuite RSA AES_128_CBC_SHA
	chk cv _css cms
		| cv < version = throwError ALFatal ADProtocolVersion $
			pmsg ++ "client version should 3.3 or more"
		| CompressionMethodNull `notElem` cms =
			throwError ALFatal ADDecodeError $
				pmsg ++ "compression method NULL must be supported"
		| otherwise = return ()
		where pmsg = "TlsServer.clientHello: "
	getRenegoInfo [] [] = Nothing
	getRenegoInfo (TLS_EMPTY_RENEGOTIATION_INFO_SCSV : _) _ = Just ""
	getRenegoInfo (_ : css) e = getRenegoInfo css e
	getRenegoInfo [] (ERenegoInfo rn : _) = Just rn
	getRenegoInfo [] (_ : es) = getRenegoInfo [] es

serverHello :: (HandleLike h, CPRG g) => CipherSuite ->
	X509.CertificateChain -> X509.CertificateChain -> Bool ->
	HandshakeM h g BS.ByteString
serverHello cs@(CipherSuite ke _) rcc ecc rn = do
	sr <- randomByteString 32
	cf <- getClientFinished
	sf <- getServerFinished
	writeHandshake . ServerHello
		version sr (SessionId "") cs CompressionMethodNull $ if rn
			then Just [ERenegoInfo $ cf `BS.append` sf]
			else Nothing
	debug "critical" ("SERVER HASH AFTER SERVERHELLO" :: String)
	debug "critical" =<< handshakeHash
	writeHandshake $ case ke of ECDHE_ECDSA -> ecc; _ -> rcc
	return sr
serverHello _ _ _ _ = E.throwError "TlsServer.serverHello: never occur"

succeed :: (ValidateHandle h, CPRG g) => CipherSuite -> BS.ByteString ->
	Version -> [(CertSecretKey, X509.CertificateChain)] ->
	Maybe X509.CertificateStore -> Bool -> HandshakeM h g ()
succeed cs@(CipherSuite ke be) cr cv crts mcs rn = do
	sr <- serverHello cs rcc ecc rn
	setCipherSuite cs
	ha <- case be of
		AES_128_CBC_SHA -> return Sha1
		AES_128_CBC_SHA256 -> return Sha256
		_ -> E.throwError
			"TlsServer.succeed: not implemented bulk encryption type"
	mpk <- (\kep -> kep (cr, sr) mcs) $ case ke of
		RSA -> rsaKeyExchange rsk cv
		DHE_RSA -> dhKeyExchange ha dh3072Modp rsk
		ECDHE_RSA -> dhKeyExchange ha secp256r1 rsk
		ECDHE_ECDSA -> dhKeyExchange ha secp256r1 esk
		_ -> \_ _ -> E.throwError
			"TlsServer.succeed: not implemented key exchange type"
	maybe (return ()) certificateVerify mpk
	getChangeCipherSpec >> flushCipherSuite Read
	cf@(Finished cfb) <- finishedHash Client
	rcf <- readHandshake
	debug "low" ("client finished hash" :: String)
	debug "low" cf
	debug "low" rcf
	unless (cf == rcf) $ throwError ALFatal ADDecryptError
		"TlsServer.succeed: wrong finished hash"
	setClientFinished cfb
	putChangeCipherSpec >> flushCipherSuite Write
	sf@(Finished sfb) <- finishedHash Server
	setServerFinished sfb
	writeHandshake sf
	where
	Just (RsaKey rsk, rcc) = find isRsa crts
	Just (EcdsaKey esk, ecc) = find isEcdsa crts
	isRsa (RsaKey _, _) = True
	isRsa _ = False
succeed _ _ _ _ _ _ = E.throwError "Network.PeyoTLS.Server.succeed: not implemented"

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
	generateKeys Server rs =<< mkpms epms `E.catchError` const
		((BS.cons cvj . BS.cons cvn) `liftM` randomByteString 46)
	where
	mkpms epms = do
		pms <- decryptRsa sk epms
		unless (BS.length pms == 48) $ E.throwError "mkpms: length"
		case BS.unpack $ BS.take 2 pms of
			[pvj, pvn] -> unless (pvj == cvj && pvn == cvn) $
				E.throwError "mkpms: version"
			_ -> E.throwError "mkpms: never occur"
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
		Left em -> E.throwError . E.strMsg $
			"TlsServer.dhClientKeyExchange: " ++ em
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

newtype TlsHandleS h g = TlsHandleS { tlsHandleS :: TlsHandle h g }

instance (ValidateHandle h, CPRG g) => HandleLike (TlsHandleS h g) where
	type HandleMonad (TlsHandleS h g) = HandleMonad (TlsHandle h g)
	type DebugLevel (TlsHandleS h g) = DebugLevel (TlsHandle h g)
	hlPut (TlsHandleS t) = hlPut t
	hlGet = hlGet_ -- hlGetRn rehandshake . tlsHandleS
	hlGetLine = hlGetLine_ -- hlGetLineRn rehandshake . tlsHandleS
	hlGetContent = hlGetContent_ -- hlGetContentRn rehandshake . tlsHandleS
	hlDebug (TlsHandleS t) = hlDebug t
	hlClose (TlsHandleS t) = hlClose t

hlGet_ :: (ValidateHandle h, CPRG g) =>
	TlsHandleS h g -> Int -> TlsM h g BS.ByteString
hlGet_ (TlsHandleS t) n = do
	bf <- HB.getAdBuf t
	if (BS.length bf >= 0)
	then do	let (ret, rest) = BS.splitAt n bf
		HB.setAdBuf t rest
		return ret
	else (bf `BS.append`) `liftM` hlGetRn rehandshake t (n - BS.length bf)

hlGetLine_ :: (ValidateHandle h, CPRG g) =>
	TlsHandleS h g -> TlsM h g BS.ByteString
hlGetLine_ (TlsHandleS t) = do
	bf <- HB.getAdBuf t
	if (10 `BS.elem` bf)
	then do	let (ret, rest) = BS.span (/= 10) bf
		HB.setAdBuf t $ BS.tail rest
		return ret
	else (bf `BS.append`) `liftM` hlGetLineRn rehandshake t

hlGetContent_ :: (ValidateHandle h, CPRG g) =>
	TlsHandleS h g -> TlsM h g BS.ByteString
hlGetContent_ (TlsHandleS t) = do
	bf <- HB.getAdBuf t
	if BS.null bf
	then hlGetContentRn rehandshake t
	else do	HB.setAdBuf t ""
		return bf

type Version = (Word8, Word8)

version :: Version
version = (3, 3)

filterCS :: [(CertSecretKey, X509.CertificateChain)] ->
	[CipherSuite] -> [CipherSuite]
filterCS crts cs = case find isEcdsa crts of
	Just _ -> cs
	_ -> filter (not . isEcdsaCS) cs
	where
	isEcdsaCS (CipherSuite ECDHE_ECDSA _) = True
	isEcdsaCS _ = False

isEcdsa :: (CertSecretKey, X509.CertificateChain) -> Bool
isEcdsa (EcdsaKey _, _) = True
isEcdsa _ = False
