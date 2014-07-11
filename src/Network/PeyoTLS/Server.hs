{-|

Module		: Network.PeyoTLS.Server
Copyright	: (c) Yoshikuni Jujo, 2014
License		: BSD3
Maintainer	: PAF01143@nifty.ne.jp
Stability	: Experimental

-}

{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.Server (
	-- * Basic
	PeyotlsM, PeyotlsHandle, TlsM, TlsHandle, run, open, names,
	-- * Renegotiation
	renegotiate, setCipherSuites, setKeyCerts, setCertificateStore,
	-- * Cipher Suite
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	-- * Others
	ValidateHandle(..), CertSecretKey(..) ) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first)
import Control.Monad (when, unless, liftM, ap)
import "monads-tf" Control.Monad.Error (catchError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.List (find)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import Numeric (readHex)
import "crypto-random" Crypto.Random (CPRG, SystemRNG)

import qualified "monads-tf" Control.Monad.Error as E
import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import qualified Network.PeyoTLS.Base as BASE (names)
import Network.PeyoTLS.Base ( debug,
	PeyotlsM, TlsM, run,
		SettingsS, getSettingsS, setSettingsS,
		adGet, adGetLine, adGetContent,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		withRandom, randomByteString, flushAppData,
		AlertLevel(..), AlertDesc(..), throwError, debugCipherSuite,
	ValidateHandle(..), handshakeValidate, validateAlert,
	TlsHandleBase, CertSecretKey(..), isRsaKey, isEcdsaKey,
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	Handshake(HHelloReq),
	ClientHello(..), ServerHello(..), SessionId(..), Extension(..),
		isRenegoInfo, emptyRenegoInfo,
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		getCipherSuite, setCipherSuite,
		checkClRenego, makeSvRenego,
	ServerKeyEx(..), SvSignSecretKey(..),
	certReq, ClCertType(..),
	ServerHelloDone(..),
	ClientKeyEx(..), Epms(..), generateKeys,
	DigitallySigned(..), ClSignPublicKey(..), handshakeHash,
	RW(..), flushCipherSuite,
	Side(..), finishedHash,
	DhParam(..), makeEcdsaPubKey )

type PeyotlsHandle = TlsHandle Handle SystemRNG

newtype TlsHandle h g = TlsHandleS { tlsHandleS :: TlsHandleBase h g } deriving Show

instance (ValidateHandle h, CPRG g) => HandleLike (TlsHandle h g) where
	type HandleMonad (TlsHandle h g) = TlsM h g
	type DebugLevel (TlsHandle h g) = DebugLevel h
	hlPut (TlsHandleS t) = hlPut t
	hlGet = adGet rehandshake . tlsHandleS
	hlGetLine = adGetLine rehandshake . tlsHandleS
	hlGetContent = adGetContent rehandshake . tlsHandleS
	hlDebug (TlsHandleS t) = hlDebug t
	hlClose (TlsHandleS t) = hlClose t

type Version = (Word8, Word8)

version :: Version
version = (3, 3)

moduleName :: String
moduleName = "Network.PeyoTLS.Server"

names :: TlsHandle h g -> [String]
names = BASE.names . tlsHandleS

open :: (ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] -> Maybe X509.CertificateStore ->
	TlsM h g (TlsHandle h g)
open h cssv crts mcs = liftM TlsHandleS . execHandshakeM h $
	((>>) <$> setSettingsS <*> handshake) (cssv',
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

setCipherSuites :: (ValidateHandle h, CPRG g) => TlsHandle h g ->
	[CipherSuite] -> TlsM h g ()
setCipherSuites (TlsHandleS t) cssv = rerunHandshakeM t $ do
	(_, rcrt, ecrt, mcs) <- getSettingsS
	setSettingsS (cssv, rcrt, ecrt, mcs)

setKeyCerts :: (ValidateHandle h, CPRG g) => TlsHandle h g ->
	[(CertSecretKey, X509.CertificateChain)] -> TlsM h g ()
setKeyCerts (TlsHandleS t) crts = rerunHandshakeM t $ do
	(cssv, _, _, mcs) <- getSettingsS
	setSettingsS (cssv,
		first rsaKey <$> find (isRsaKey . fst) crts,
		first ecdsaKey <$> find (isEcdsaKey . fst) crts, mcs)

setCertificateStore :: (ValidateHandle h, CPRG g) => TlsHandle h g ->
	Maybe X509.CertificateStore -> TlsM h g ()
setCertificateStore (TlsHandleS t) mcs = rerunHandshakeM t $ do
	(cssv, rcrt, ecrt, _) <- getSettingsS
	setSettingsS (cssv, rcrt, ecrt, mcs)

renegotiate :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
renegotiate (TlsHandleS t) = rerunHandshakeM t $ do
	writeHandshake HHelloReq
	debug "low" ("before flushAppData" :: String)
	ne <- flushAppData
	debug "low" ("after flushAppData" :: String)
	when ne (handshake =<< getSettingsS)

rehandshake :: (ValidateHandle h, CPRG g) => TlsHandleBase h g -> TlsM h g ()
rehandshake t = rerunHandshakeM t $ handshake =<< getSettingsS

handshake :: (ValidateHandle h, CPRG g) => SettingsS -> HandshakeM h g ()
handshake (cssv, rcrt, ecrt, mcs) = do
	(ke, be, cr, cv) <- clientHello cssv
	sr <- serverHello (snd <$> rcrt) (snd <$> ecrt)
	ha <- case be of
		AES_128_CBC_SHA -> return Sha1
		AES_128_CBC_SHA256 -> return Sha256
		_ -> throwError ALFatal ADInternalError $
			pre ++ "not implemented bulk encryption type"
	mpk <- ($ mcs) . ($ (cr, sr)) $ case (ke, fst <$> rcrt, fst <$> ecrt) of
		(RSA, Just rsk, _) -> rsaKeyExchange rsk cv
		(DHE_RSA, Just rsk, _) -> dhKeyExchange ha dh3072Modp rsk
		(ECDHE_RSA, Just rsk, _) -> dhKeyExchange ha secp256r1 rsk
		(ECDHE_ECDSA, _, Just esk) -> dhKeyExchange ha secp256r1 esk
		_ -> \_ _ -> throwError ALFatal ADInternalError $
			pre ++ "no implemented key exchange type or " ++
				"no applicable certificate files"
	flip (maybe $ return ()) mpk $ \pk -> case pk of
		X509.PubKeyRSA rpk -> certVerify rpk
		X509.PubKeyECDSA c xy -> certVerify $ makeEcdsaPubKey c xy
		_ -> throwError ALFatal ADUnsupportedCertificate $
			pre ++ "not implement: " ++ show pk
	getChangeCipherSpec >> flushCipherSuite Read
	(==) `liftM` finishedHash Client `ap` readHandshake >>= \ok -> unless ok .
		throwError ALFatal ADDecryptError $ pre ++ "wrong finished hash"
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Server
	where pre = moduleName ++ ".handshake: "

secp256r1 :: ECC.Curve
secp256r1 = ECC.getCurveByName ECC.SEC_p256r1

dh3072Modp :: DH.Params
dh3072Modp = DH.Params p 2
	where [(p, "")] = readHex $
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1" ++
		"29024e088a67cc74020bbea63b139b22514a08798e3404dd" ++
		"ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245" ++
		"e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" ++
		"ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d" ++
		"c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" ++
		"83655d23dca3ad961c62f356208552bb9ed529077096966d" ++
		"670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" ++
		"e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9" ++
		"de2bcbf6955817183995497cea956ae515d2261898fa0510" ++
		"15728e5a8aaac42dad33170d04507a33a85521abdf1cba64" ++
		"ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" ++
		"abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b" ++
		"f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" ++
		"bbe117577a615d6c770988c0bad946e208e24fa074e5ab31" ++
		"43db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"

clientHello :: (HandleLike h, CPRG g) => [CipherSuite] ->
	HandshakeM h g (KeyEx, BulkEnc, BS.ByteString, Version)
clientHello cssv = do
	ClientHello cv cr _sid cscl cms me <- readHandshake
	checkRenegoInfo cscl me
	unless (cv >= version) . throwError ALFatal ADProtocolVersion $
		pre ++ "only implement TLS 1.2"
	unless (CompMethodNull `elem` cms) . throwError ALFatal ADDecodeError $
		pre ++ "compression method NULL must be supported"
	(ke, be) <- case find (`elem` cscl) cssv of
		Just cs@(CipherSuite k b) -> setCipherSuite cs >> return (k, b)
		_ -> throwError ALFatal ADHsFailure $
			pre ++ "no acceptable set of security parameters: \n\t" ++
			"cscl: " ++ show cscl ++ "\n\t" ++
			"cssv: " ++ show cssv ++ "\n"
	return (ke, be, cr, cv)
	where pre = moduleName ++ ".clientHello: "

checkRenegoInfo ::
	HandleLike h => [CipherSuite] -> Maybe [Extension] -> HandshakeM h g ()
checkRenegoInfo cscl me = (\n -> maybe n checkClRenego mcf) . throwError
	ALFatal ADInsufficientSecurity $
	moduleName ++ ".checkRenego: require secure renegotiation"
	where mcf = case (EMPTY_RENEGOTIATION_INFO `elem` cscl, me) of
		(True, _) -> Just emptyRenegoInfo
		(_, Just e) -> find isRenegoInfo e
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
		. Just . (: []) =<< makeSvRenego
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
		pms <- either (E.throwError . strMsg . show) return =<<
			withRandom (\g -> RSA.decryptSafer g sk epms)
		unless (BS.length pms == 48) $ throwError ALFatal ADHsFailure ""
		let [pvj, pvn] = BS.unpack $ BS.take 2 pms
		unless (pvj == vj && pvn == vn) $ throwError ALFatal ADHsFailure ""
		return pms

dhKeyExchange :: (ValidateHandle h, CPRG g, SvSignSecretKey sk,
		DhParam dp, B.Bytable dp, B.Bytable (Public dp)) =>
	HashAlg -> dp -> sk -> (BS.ByteString, BS.ByteString) ->
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
dhKeyExchange ha dp sk rs@(cr, sr) mcs = do
	sv <- withRandom $ generateSecret dp
	bl <- withRandom $ generateBlinder sk
	let pv = B.encode $ calculatePublic dp sv
	writeHandshake
		. ServerKeyEx (B.encode dp) pv ha (signatureAlgorithm sk)
		. sign ha bl sk $ BS.concat [cr, sr, B.encode dp, pv]
	const `liftM` reqAndCert mcs `ap` do
		ClientKeyEx cke <- readHandshake
		generateKeys Server rs . calculateShared dp sv =<<
			either (throwError ALFatal ADInternalError .
					(moduleName ++) . (".dhKeyExchange: " ++))
				return (B.decode cke)

reqAndCert :: (ValidateHandle h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
reqAndCert mcs = do
	flip (maybe $ return ()) mcs $ writeHandshake . certReq
		[CTRsaSign, CTEcdsaSign] [(Sha256, Rsa), (Sha256, Ecdsa)]
	writeHandshake SHDone
	flip (maybe $ return Nothing) mcs $ liftM Just . \cs -> do
		cc@(X509.CertificateChain (c : _)) <- readHandshake
		vr <- handshakeValidate cs cc
		unless (null vr) . throwError ALFatal (validateAlert vr) $
			moduleName ++ ".reqAndCert: " ++ show vr
		return . X509.certPubKey $ X509.getCertificate c

certVerify :: (HandleLike h, CPRG g, ClSignPublicKey pk) => pk -> HandshakeM h g ()
certVerify pk = do
	debugCipherSuite . show $ cspAlgorithm pk
	hs0 <- handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(Sha256, sa) | sa == cspAlgorithm pk -> return ()
		_ -> throwError ALFatal ADDecodeError $
			moduleName ++ ".certVerify: not implement: " ++ show a
	unless (csVerify pk s hs0) . throwError ALFatal ADDecryptError $
		moduleName ++ ".certVerify: client auth failed "
