{-|

Module		: Network.PeyoTLS.Server
Copyright	: (c) Yoshikuni Jujo, 2014
License		: BSD3
Maintainer	: PAF01143@nifty.ne.jp
Stability	: Experimental

-}

{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.Client.Body (
	-- * Basic
	TlsState(..), State1(..), Keys(..), toCheckName,
	PeyotlsM, PeyotlsHandle, TlsM, TlsHandle, Alert(..),
	run, run', open, open', getNames, getCertificate, checkName,
	-- * Renegotiation
	renegotiate, setCipherSuites, setKeyCerts, setCertificateStore,
	-- * Cipher Suite
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	-- * Others
	ValidateHandle(..), CertSecretKey(..) ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (when, unless, liftM, ap)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Maybe (fromMaybe, fromJust)
import Data.List (find, intersect)
import Data.Function (on)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG, cprgGenerate)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified "monads-tf" Control.Monad.Error as E

import qualified Network.PeyoTLS.Base as BASE (getNames, getCertificate)
import Network.PeyoTLS.Base ( debug, wFlush,
	TlsState(..), State1(..), Keys(..),
	PeyotlsM, TlsM, run, run',
		getSettingsC, setSettingsC,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		withRandom, flushAd,
		Alert(..), AlertLevel(..), AlertDesc(..), throw,
	ValidateHandle(..), handshakeValidate, validateAlert,
	HandleBase, CertSecretKey(..),
		readHandshake, writeHandshake, CCSpec(..),
	ClHello(..), SvHello(..), PrtVrsn(..), SssnId(..), isRnInfo,
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CmpMtd(..), HashAlg(..), SignAlg(..),
		setCipherSuite,
		checkSvRenego, makeClRenego,
	SvKeyExEcdhe(..), SvKeyExDhe(..), SvSignPublicKey(..),
	CertReq(..), ClCertType(..),
	SHDone(..),
	ClKeyEx(..), Epms(..), makeKeys,
	DigitSigned(..), ClSignSecretKey(..), handshakeHash,
	Side(..), RW(..), finishedHash, flushCipherSuite,
	DhParam(..), ecdsaPubKey )

type PeyotlsHandle = TlsHandle Handle SystemRNG

newtype TlsHandle h g = TlsHandleC { tlsHandleC :: HandleBase h g } deriving Show

instance (ValidateHandle h, CPRG g) => HandleLike (TlsHandle h g) where
	type HandleMonad (TlsHandle h g) = TlsM h g
	type DebugLevel (TlsHandle h g) = DebugLevel h
	hlPut = adPut . tlsHandleC
	hlGet = adGet rehandshake . tlsHandleC
	hlGetLine = adGetLine rehandshake . tlsHandleC
	hlGetContent = adGetContent rehandshake . tlsHandleC
	hlDebug = adDebug . tlsHandleC
	hlClose = adClose . tlsHandleC
	hlFlush = wFlush . tlsHandleC

modNm :: String
modNm = "Network.PeyoTLS.Client"

getNames :: HandleLike h => TlsHandle h g -> TlsM h g [String]
getNames = BASE.getNames . tlsHandleC

getCertificate :: HandleLike h => TlsHandle h g -> TlsM h g X509.SignedCertificate
getCertificate = (fromJust `liftM`) . BASE.getCertificate . tlsHandleC

checkName :: HandleLike h => TlsHandle h g -> String -> TlsM h g Bool
checkName t n = flip toCheckName n `liftM` getNames t

toCheckName :: [String] -> String -> Bool
toCheckName s0s s = any (`toCheckName1` s) s0s

toCheckName1 :: String -> String -> Bool
toCheckName1 = on checkSepNames $ sepBy '.'

sepBy :: Eq a => a ->[a] -> [[a]]
sepBy x0 xs
	| (t, _ : d) <- span (/= x0) xs = t : sepBy x0 d
	| otherwise = [xs]

checkSepNames :: [String] -> [String] -> Bool
checkSepNames [] [] = True
checkSepNames _ [] = False
checkSepNames [] _ = False
checkSepNames ("*" : ns0) (_ : ns) = checkSepNames ns0 ns
checkSepNames (n0 : ns0) (n : ns) = n0 == n && checkSepNames ns0 ns

-- | Don't forget check server name by checkName.

open :: (ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	TlsM h g (TlsHandle h g)
open h cscl crts ca = (TlsHandleC `liftM`) . execHandshakeM h $ do
	setSettingsC (cscl, crts, ca)
	handshake crts ca =<< clientHello cscl

-- | This function open and check server name.
--   Use this so as not to forget to check server name.

open' :: (ValidateHandle h, CPRG g) => h -> String -> [CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	TlsM h g (TlsHandle h g)
open' h n cscl crts ca = do
	t <- open h cscl crts ca
	c <- checkName t n
	unless c . E.throwError $ strMsg "certificate name mismatch"
	return t

renegotiate :: (ValidateHandle h, CPRG g) => TlsHandle h g -> TlsM h g ()
renegotiate (TlsHandleC t) = rerunHandshakeM t $ do
	(cscl, crts, ca) <- getSettingsC
	clientHello cscl >>= \cr -> flushAd >>= flip when (handshake crts ca cr)

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

rehandshake :: (ValidateHandle h, CPRG g) => HandleBase h g -> TlsM h g ()
rehandshake t = rerunHandshakeM t $ do
	(cscl, crts, ca) <- getSettingsC
	handshake crts ca =<< clientHello cscl

clientHello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g BS.ByteString
clientHello cscl = do
	cr <- withRandom $ cprgGenerate 32
	((>>) <$> writeHandshake <*> debug "low")
		. ClHello (PrtVrsn 3 3) cr (SssnId "") cscl [CmpMtdNull]
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
		_ -> \_ _ _ -> throw ALFtl ADHsFailure $
			modNm ++ ".handshake: not implemented"

serverHello :: (HandleLike h, CPRG g) => HandshakeM h g (BS.ByteString, KeyEx)
serverHello = do
	SvHello v sr _sid cs@(CipherSuite ke _) cm e <- readHandshake
	case v of
		PrtVrsn 3 3 -> return ()
		_ -> throw ALFtl ADProtoVer $
			modNm ++ ".serverHello: only TLS 1.2"
	case cm of
		CmpMtdNull -> return ()
		_ -> throw ALFtl ADHsFailure $
			modNm ++ ".serverHello: only compression method null"
	case find isRnInfo $ fromMaybe [] e of
		Just ri -> checkSvRenego ri
		_ -> throw ALFtl ADInsSec $ modNm ++ ".serverHello: no sec renego"
	setCipherSuite cs
	return (sr, ke)

rsaHandshake :: (ValidateHandle h, CPRG g) => (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
rsaHandshake rs crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	vr <- handshakeValidate ca cc
	unless (null vr) . throw ALFtl (validateAlert vr) $
		modNm ++ ".rsaHandshake: validate failure"
	pk <- case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA k -> return k
		_ -> throw ALFtl ADIllParam $ modNm ++ ".rsaHandshake: RSA pk"
	crt <- clientCertificate crts
	pms <- ("\x03\x03" `BS.append`) `liftM` withRandom (cprgGenerate 46)
	makeKeys Client rs pms
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
	unless (null vr) . throw ALFtl (validateAlert vr) $
		modNm ++ ".succeed: validate failure"
	case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA pk -> succeed t pk rs crts
		X509.PubKeyECDSA cv pt -> succeed t (ecdsaPubKey cv pt) rs crts
		_ -> throw ALFtl ADHsFailure $
			modNm ++ ".dheHandshake: not implemented"

succeed :: (ValidateHandle h, CPRG g, SvSignPublicKey pk,
		KeyExchangeClass ke, Show (Secret ke), Show (Public ke)) =>
	ke -> pk -> (BS.ByteString, BS.ByteString) ->
	[(CertSecretKey, X509.CertificateChain)] -> HandshakeM h g ()
succeed t pk rs@(cr, sr) crts = do
	(ps, pv, ha, sa, sn) <- serverKeyExchange
	let _ = ps `asTypeOf` t
	unless (sa == sspAlgorithm pk) . throw ALFtl ADHsFailure $
		pre ++ "sign algorithm unmatch"
	unless (ssVerify ha pk sn $ BS.concat [cr, sr, B.encode ps, B.encode pv]) .
		throw ALFtl ADDecryptErr $ pre ++ "verify failure"
	crt <- clientCertificate crts
	sv <- withRandom $ generateSecret ps
	makeKeys Client rs $ calculateShared ps sv pv
	writeHandshake . ClKeyEx . B.encode $ calculatePublic ps sv
	finishHandshake crt
	where pre = modNm ++ ".succeed: "

class (DhParam bs, B.Bytable bs, B.Bytable (Public bs)) => KeyExchangeClass bs where
	serverKeyExchange :: (HandleLike h, CPRG g) => HandshakeM h g
		(bs, Public bs, HashAlg, SignAlg, BS.ByteString)

instance KeyExchangeClass ECC.Curve where
	serverKeyExchange = do
		SvKeyExEcdhe cv pnt ha sa sn <- readHandshake
		return (cv, pnt, ha, sa, sn)

instance KeyExchangeClass DH.Params where
	serverKeyExchange = do
		SvKeyExDhe ps pv ha sa sn <- readHandshake
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
			_ -> throw ALFtl ADUnkCa $ modNm ++
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
	ccrt _ = error $ modNm ++ ".isMatchedCert: empty certificate chain"
	cpk X509.PubKeyRSA{} = rsa; cpk X509.PubKeyECDSA{} = ecdsa; cpk _ = False

finishHandshake :: (HandleLike h, CPRG g) =>
	Maybe (CertSecretKey, X509.CertificateChain) -> HandshakeM h g ()
finishHandshake crt = do
	hs <- handshakeHash
	case fst <$> crt of
		Just (RsaKey sk) -> writeHandshake .
			DigitSigned (cssAlgorithm sk) $ csSign sk hs
		Just (EcdsaKey sk) -> writeHandshake .
			DigitSigned (cssAlgorithm sk) $ csSign sk hs
		_ -> return ()
	writeHandshake CCSpec
	flushCipherSuite Write
	writeHandshake =<< finishedHash Client
	CCSpec <- readHandshake
	flushCipherSuite Read
	(==) `liftM` finishedHash Server `ap` readHandshake >>= flip unless
		(throw ALFtl ADDecryptErr $
			modNm ++ ".finishHandshake: finished hash failure")
