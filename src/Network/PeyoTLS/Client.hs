{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.Client (
	PeyotlsM, PeyotlsHandleC, TlsM, TlsHandleC,
	run, open, renegotiate, names,
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	ValidateHandle(..), CertSecretKey(..) ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (when, unless, liftM)
import Data.Maybe (fromMaybe, listToMaybe, mapMaybe)
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
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import qualified Network.PeyoTLS.Base as HB (names)
import Network.PeyoTLS.Base (
	PeyotlsM, TlsM, run, HandshakeM, execHandshakeM, rerunHandshakeM,
		AlertLevel(..), AlertDesc(..), throwError,
		withRandom, randomByteString,
	ValidateHandle(..), handshakeValidate, validateAlert,
	TlsHandle,
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
		getSettingsC, setSettingsC,
	CertSecretKey(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		setCipherSuite, flushCipherSuite,
		checkServerRenego, makeClientRenego,
	ServerKeyExEcdhe(..), ServerKeyExDhe(..),
	CertificateRequest(..), ClientCertificateType(..),
	ServerHelloDone(..),
	ClientKeyExchange(..), Epms(..),
		generateKeys, encryptRsa,
	DigitallySigned(..), handshakeHash,
	Side(..), RW(..), finishedHash,
	DhParam(..), decodePoint,

	eRenegoInfo, flushAppData,
	hlGetRn, hlGetLineRn, hlGetContentRn,
	SvSignPublicKey(..), ClSignSecretKey(..),
	)

type PeyotlsHandleC = TlsHandleC Handle SystemRNG

newtype TlsHandleC h g = TlsHandleC { tlsHandleC :: TlsHandle h g } deriving Show

instance (ValidateHandle h, CPRG g) => HandleLike (TlsHandleC h g) where
	type HandleMonad (TlsHandleC h g) = TlsM h g
	type DebugLevel (TlsHandleC h g) = DebugLevel h
	hlPut (TlsHandleC t) = hlPut t
	hlGet = hlGetRn rehandshake . tlsHandleC
	hlGetLine = hlGetLineRn rehandshake . tlsHandleC
	hlGetContent = hlGetContentRn rehandshake . tlsHandleC
	hlDebug (TlsHandleC t) = hlDebug t
	hlClose (TlsHandleC t) = hlClose t

moduleName :: String
moduleName = "Network.PeyoTLS.Client"

names :: TlsHandleC h g -> [String]
names = HB.names . tlsHandleC

open :: (ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	TlsM h g (TlsHandleC h g)
open h cscl crts ca = (TlsHandleC `liftM`) . execHandshakeM h $ do
	setSettingsC (cscl, crts, ca)
	handshake crts ca =<< clientHello cscl

renegotiate :: (ValidateHandle h, CPRG g) => TlsHandleC h g -> TlsM h g ()
renegotiate (TlsHandleC t) = rerunHandshakeM t $ do
	(cscl, crts, ca) <- getSettingsC
	cr <- clientHello cscl
	flushAppData >>= flip when (handshake crts ca cr)

rehandshake :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
rehandshake t = rerunHandshakeM t $ do
	(cscl, crts, ca) <- getSettingsC
	handshake crts ca =<< clientHello cscl

clientHello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g BS.ByteString
clientHello cscl = do
	cr <- randomByteString 32
	writeHandshake
		. ClientHello (3, 3) cr (SessionId "") cscl [CompMethodNull]
		. Just . (: []) =<< makeClientRenego
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
		_ -> \_ _ _ -> throwError ALFatal ADHsFailure $
			moduleName ++ ".handshake: not implemented"

serverHello :: (HandleLike h, CPRG g) => HandshakeM h g (BS.ByteString, KeyEx)
serverHello = do
	ServerHello v sr _sid cs@(CipherSuite ke _) cm e <- readHandshake
	case v of
		(3, 3) -> return ()
		_ -> throwError ALFatal ADProtocolVersion $
			moduleName ++ ".serverHello: only TLS 1.2"
	case cm of
		CompMethodNull -> return ()
		_ -> throwError ALFatal ADHsFailure $
			moduleName ++ ".serverHello: only compression method null"
	case listToMaybe . mapMaybe eRenegoInfo $ fromMaybe [] e of
		Just ri -> checkServerRenego ri
		_ -> throwError ALFatal ADInsufficientSecurity $
			moduleName ++ ".serverHello: require secure renegotiation"
	setCipherSuite cs
	return (sr, ke)

rsaHandshake :: (ValidateHandle h, CPRG g) => (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
rsaHandshake rs crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	vr <- handshakeValidate ca cc
	unless (null vr) . throwError ALFatal (validateAlert vr) $
		moduleName ++ ".rsaHandshake: validate failure"
	pk <- case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA k -> return k
		_ -> throwError ALFatal ADIllegalParameter $
			moduleName ++ ".rsaHandshake: require RSA public key"
	crt <- clientCertificate crts
	pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
	generateKeys Client rs pms
	writeHandshake . Epms =<< encryptRsa pk pms
	finishHandshake crt

dheHandshake :: (ValidateHandle h, CPRG g,
		KeyExchangeClass ke, Show (Secret ke), Show (Public ke)) =>
	ke -> (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
dheHandshake t rs crts ca = do
	cc@(X509.CertificateChain cs) <- readHandshake
	vr <- handshakeValidate ca cc
	unless (null vr) . throwError ALFatal (validateAlert vr) $
		moduleName ++ ".succeed: validate failure"
	case X509.certPubKey . X509.signedObject . X509.getSigned $ last cs of
		X509.PubKeyRSA pk -> succeed t pk rs crts
		X509.PubKeyECDSA cv pt -> succeed t (ek cv pt) rs crts
		_ -> throwError ALFatal ADHsFailure $
			moduleName ++ ".dheHandshake: not implemented"
	where ek cv pt = ECDSA.PublicKey (ECC.getCurveByName cv) (decodePoint pt)

succeed :: (ValidateHandle h, CPRG g, SvSignPublicKey pk,
		KeyExchangeClass ke, Show (Secret ke), Show (Public ke)) =>
	ke -> pk -> (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> HandshakeM h g ()
succeed t pk rs@(cr, sr) crts = do
	(ps, pv, ha, _sa, sn) <- serverKeyExchange
	let _ = ps `asTypeOf` t
	unless (verify ha pk sn $ BS.concat [cr, sr, B.encode ps, B.encode pv]) .
		throwError ALFatal ADDecryptError $
			moduleName ++ ".succeed: verify failure"
	crt <- clientCertificate crts
	sv <- withRandom $ generateSecret ps
	generateKeys Client rs $ calculateShared ps sv pv
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
				_ -> throwError ALFatal ADUnknownCa $
					moduleName ++ ".clientCertificate: " ++
						"no certificate"
		Right ServerHelloDone -> return Nothing

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
	case fst <$> crt of
		Just (RsaKey sk) -> writeHandshake $ digitallySigned sk hs
		Just (EcdsaKey sk) -> writeHandshake $ digitallySigned sk hs
		_ -> return ()
	putChangeCipherSpec >> flushCipherSuite Write
	fc <- finishedHash Client
	writeHandshake fc
	getChangeCipherSpec >> flushCipherSuite Read
	fs <- finishedHash Server
	(fs ==) `liftM` readHandshake >>= flip unless
		(throwError ALFatal ADDecryptError $
			moduleName ++ ".finishHandshake: finished hash failure")
	where
	digitallySigned sk hs = DigitallySigned (clsAlgorithm sk) $ clsSign sk hs
