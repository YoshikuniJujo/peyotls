{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	PackageImports, UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.Server (
	run, open, names,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	PeyotlsM, PeyotlsHandle,
	TlsM, TlsHandle,
	ValidateHandle(..), CertSecretKey ) where

import Control.Applicative
import Control.Monad (unless, liftM, ap)
import "monads-tf" Control.Monad.Error (catchError)
import qualified "monads-tf" Control.Monad.Error as E (throwError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.List (find)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

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

import Network.PeyoTLS.HandshakeBase ( debug, Extension(..),
	PeyotlsM, PeyotlsHandle,
	TlsM, run, HandshakeM, execHandshakeM, oldHandshakeM,
	withRandom, randomByteString,
	TlsHandle,
		readHandshake, getChangeCipherSpec,
		writeHandshake, putChangeCipherSpec,
	ValidateHandle(..), handshakeValidate,
	AlertLevel(..), AlertDesc(..),
	ServerKeyExchange(..), ServerHelloDone(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlg(..), SignAlg(..),
		setCipherSuite,
	certificateRequest, ClientCertificateType(..), SecretKey(..),
	ClientKeyExchange(..), Epms(..),
		generateKeys, decryptRsa, rsaPadding, debugCipherSuite,
	DigitallySigned(..), handshakeHash, flushCipherSuite,
	Side(..), RW(..), finishedHash,
	DhParam(..), dh3072Modp, secp256r1, throwError,
	CertSecretKey(..),
	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,
	Finished(..),
	ContentType(..),
	tlsPut_, tGetContent_,
	tlsGet_, tGetLine_,
	)

import Network.PeyoTLS.ReadFile

names :: TlsHandleS h g -> [String]
names = HB.names . tlsHandleS

type Version = (Word8, Word8)

version :: Version
version = (3, 3)

filterCS :: [(CertSecretKey, X509.CertificateChain)] ->
	[CipherSuite] -> [CipherSuite]
filterCS crts cs = case find isEcdsa crts of
	Just _ -> cs
	_ -> filter (not . isEcdsaCS) cs

isEcdsa :: (CertSecretKey, X509.CertificateChain) -> Bool
isEcdsa (EcdsaKey _, _) = True
isEcdsa _ = False

isRsa :: (CertSecretKey, X509.CertificateChain) -> Bool
isRsa (RsaKey _, _) = True
isRsa _ = False

isEcdsaCS :: CipherSuite -> Bool
isEcdsaCS (CipherSuite ECDHE_ECDSA _) = True
isEcdsaCS _ = False

open :: (ValidateHandle h, CPRG g) => h ->
	[CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandleS h g)
open h cssv crts mcs = (TlsHandleS `liftM`) . execHandshakeM h $ do
	HB.setInitSet (cssv, crts, mcs)
	(cs, cr, cv, rn) <- clientHello $ filterCS crts cssv
	succeed cs cr cv crts mcs rn

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
			"TlsServer.open: not implemented bulk encryption type"
--	debug "medium" . RSA.public_size $ RSA.private_pub rsk
	mpk <- (\kep -> kep (cr, sr) mcs) $ case ke of
		RSA -> rsaKeyExchange rsk cv
		DHE_RSA -> dhKeyExchange ha dh3072Modp rsk
		ECDHE_RSA -> dhKeyExchange ha secp256r1 rsk
		ECDHE_ECDSA -> dhKeyExchange ha secp256r1 esk
		_ -> \_ _ -> E.throwError
			"TlsServer.open: not implemented key exchange type"
	maybe (return ()) certificateVerify mpk
	debug "low" ("before getChangeCipherSpec" :: String)
	getChangeCipherSpec >> flushCipherSuite Read
	cf@(Finished cfb) <- finishedHash Client
	debug "low" ("client finished" :: String)
	debug "low" cf
	rcf <- readHandshake
	debug "low" rcf
	unless (cf == rcf) $ throwError ALFatal ADDecryptError
		"TlsServer.open: wrong finished hash"
	setClientFinished cfb
	putChangeCipherSpec >> flushCipherSuite Write
	sf@(Finished sfb) <- finishedHash Server
	setServerFinished sfb
	writeHandshake sf
	where
	Just (RsaKey rsk, rcc) = find isRsa crts
	Just (EcdsaKey esk, ecc) = find isEcdsa crts
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

{-
fromClientHello :: [CipherSuite] -> Handshake -> (CipherSuite, BS.ByteString, Version, Bool)
fromClientHello cssv (HClientHello (ClientHello cv cr _sid cscl _cms _e)) =
	(merge cssv cscl, cr, cv, True)
	where
	merge sv cl = case find (`elem` cl) sv of
		Just cs -> cs; _ -> CipherSuite RSA AES_128_CBC_SHA
fromClientHello _ _ = error "Server.fromClientHello: bad"
-}

getRenegoInfo :: [CipherSuite] -> [Extension] -> Maybe BS.ByteString
getRenegoInfo [] [] = Nothing
getRenegoInfo (TLS_EMPTY_RENEGOTIATION_INFO_SCSV : _) _ = Just ""
getRenegoInfo (_ : css) e = getRenegoInfo css e
getRenegoInfo [] (ERenegoInfo rn : _) = Just rn
getRenegoInfo [] (_ : es) = getRenegoInfo [] es

clientHello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g (CipherSuite, BS.ByteString, Version, Bool)
clientHello cssv = do
	cf0 <- getClientFinished
	ch@(ClientHello cv cr _sid cscl cms me) <- readHandshake
--	let Just cf = getRenegoInfo me
--	let rn = True
	let (cf, rn) = case me of
		Nothing -> ("", False)
		Just e -> case getRenegoInfo cscl e of
			Nothing -> ("", False)
			Just c -> (c, True)
	debug "medium" ch
--	debug "medium" e
--	let rn = maybe False (ERenegoInfo "" `elem`) e
--	debug "medium" rn
	debug "low" ("CLIENT FINISHES" :: String)
	debug "low" cf
	debug "low" cf0
	unless (cf == cf0) $ E.throwError "clientHello"
	chk cv cscl cms >> return (merge cssv cscl, cr, cv, rn)
	where
	merge sv cl = case find (`elem` cl) sv of
		Just cs -> cs; _ -> CipherSuite RSA AES_128_CBC_SHA
	chk cv _css cms
		| cv < version = throwError ALFatal ADProtocolVersion $
			pmsg ++ "client version should 3.3 or more"
			{-
		| CipherSuite RSA AES_128_CBC_SHA `notElem` css =
			throwError ALFatal ADIllegalParameter $
				pmsg ++ "TLS_RSA_AES_128_CBC_SHA must be supported"
				-}
		| CompressionMethodNull `notElem` cms =
			throwError ALFatal ADDecodeError $
				pmsg ++ "compression method NULL must be supported"
		| otherwise = return ()
		where pmsg = "TlsServer.clientHello: "

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
	writeHandshake $ case ke of ECDHE_ECDSA -> ecc; _ -> rcc
	return sr
serverHello _ _ _ _ = E.throwError "TlsServer.serverHello: never occur"

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
	maybe (return Nothing) (liftM Just . clientCertificate) mcs

clientCertificate :: (ValidateHandle h, CPRG g) =>
	X509.CertificateStore -> HandshakeM h g X509.PubKey
clientCertificate cs = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	chk cc -- >> setClientNames (certNames $ X509.getCertificate c)
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
		Left em -> E.throwError . strMsg $
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
	hlGet = hlGet_
	hlGetLine = hlGetLine_
	hlGetContent = hlGetContent_
	hlDebug (TlsHandleS t) = hlDebug t
	hlClose (TlsHandleS t) = hlClose t

hlGet_ :: (ValidateHandle h, CPRG g) =>
	TlsHandleS h g -> Int -> TlsM h g BS.ByteString
hlGet_ = (.) <$> checkAppData <*> ((fst `liftM`) .) . tlsGet_ rehandshake
	. (, undefined) . tlsHandleS

hlGetLine_, hlGetContent_ ::
	(ValidateHandle h, CPRG g) => TlsHandleS h g -> TlsM h g BS.ByteString
hlGetLine_ = ($) <$> checkAppData <*> tGetLine_ rehandshake . tlsHandleS
hlGetContent_ = ($) <$> checkAppData <*> tGetContent_ rehandshake . tlsHandleS

checkAppData :: (ValidateHandle h, CPRG g) => TlsHandleS h g ->
	TlsM h g (ContentType, BS.ByteString) -> TlsM h g BS.ByteString
checkAppData (TlsHandleS t) m = m >>= \cp -> case cp of
	(CTAppData, ad) -> return ad
	(CTAlert, "\SOH\NUL") -> do
		_ <- tlsPut_ (t, undefined) CTAlert "\SOH\NUL"
		E.throwError "TlsHandle.checkAppData: EOF"
		{-
	(CTHandshake, hs) -> do
		lift . lift $ hlDebug (tlsHandle t) "low" "renegotiation?"
		lift . lift $ hlDebug (tlsHandle t) "low" . BSC.pack $ show hs
		lift . lift $ hlDebug (tlsHandle t) "low" . BSC.pack .
			show $ (B.decode hs :: Either String Handshake)
--		renegotiation t hs
		return ""
		-}
	_ -> do	_ <- tlsPut_ (t, undefined) CTAlert "\2\10"
		E.throwError "TlsHandle.checkAppData: not application data"

handshake :: (ValidateHandle h, CPRG g) =>
	[CipherSuite] -> [(CertSecretKey, X509.CertificateChain)] ->
	Maybe X509.CertificateStore -> HandshakeM h g ()
handshake _cssv _crts _mcs = do
	(cssv, crts, mcs) <- HB.getInitSet
	(cs, cr, cv, rn) <- clientHello $ filterCS crts cssv
	succeed cs cr cv crts mcs rn

rehandshake :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
rehandshake t = do
	oldHandshakeM t "" $ handshake undefined undefined undefined
	return ()

{-
renegotiation ::
	(ValidateHandle h, CPRG g) => TlsHandle h g -> BS.ByteString -> TlsM h g ()
renegotiation t hs = do
	let	Right ch = B.decode hs
		(cs, cr, cv, rn) = fromClientHello cipherSuites ch
	oldHandshakeM t hs $ succeed cs cr cv certificateSets Nothing rn
	return ()
	-}
