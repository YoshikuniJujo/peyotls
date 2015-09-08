{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Network.PeyoTLS.Run.State ( State1(..),
	TlsState(..), initState, PartnerId, newPartner,
		getGen, setGen, getNames, setNames, getCertificate, setCertificate,
		getRSn, getWSn, rstRSn, rstWSn, sccRSn, sccWSn,
		getClFinished, setClFinished, getSvFinished, setSvFinished,
	ContType(..), getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf,
	ProtocolVersion,
	CipherSuite(..), BulkEnc(..), RW(..),
		getCipherSuite, setCipherSuite, flushCipherSuite,
	Keys(..), getKeys, setKeys,
	SettingsC, getSettingsC, setSettingsC,
	SettingsS, getSettingsS, setSettingsS,
	CertSecretKey(..), isRsaKey, isEcdsaKey ) where

import Control.Applicative ((<$>))
import Control.Arrow (first)
import Data.Maybe (maybeToList)
import Data.List (find)
import Data.Word (Word64)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import Network.PeyoTLS.CertSecretKey (CertSecretKey(..), isRsaKey, isEcdsaKey)
import Network.PeyoTLS.Codec (CipherSuite(..), KeyEx(KE_NULL), BulkEnc(..))
import Network.PeyoTLS.Codec.ContentTypes (ContType(..), ProtocolVersion)

modNm :: String
modNm = "Network.PeyoTLS.State"

type Modify s = s -> s

data TlsState h g =
	TlsState { gen :: g, nextPid :: Int, states :: [(PartnerId, State1 g)] }

initState :: g -> TlsState h g
initState g = TlsState{ gen = g, nextPid = 0, states = [] }

getState :: PartnerId -> TlsState h g -> State1 g
getState i s = case lookup i $ states s of
	Just s1 -> s1
	_ -> error $ modNm ++ ".getState"

modState :: Modify (State1 g) -> PartnerId -> Modify (TlsState h g)
modState f i s = s { states = (i, f $ getState i s) : states s }

setState :: (a -> Modify (State1 g)) -> PartnerId -> a -> Modify (TlsState h g)
setState f i x = modState (f x) i

data State1 g = State1 {
	settings :: Settings,
	rnClFinished :: BS.ByteString, rnSvFinished :: BS.ByteString,
	sKeys :: Keys, readSN :: Word64, writeSN :: Word64,
	rBuffer :: (ContType, BS.ByteString), wBuffer :: (ContType, BS.ByteString),
	adBuffer :: BS.ByteString,
	sNames :: [String],
	sCert :: Maybe X509.SignedCertificate }

type Settings = (
	[CipherSuite], [(CertSecretKey, X509.CertificateChain)],
	Maybe X509.CertificateStore )

data PartnerId = PartnerId Int deriving (Show, Eq)

newPartner :: TlsState h g -> (PartnerId, TlsState h g)
newPartner s@TlsState { nextPid = np, states = ss } = (
	PartnerId np ,
	s { nextPid = succ np, states = (PartnerId np, s1) : ss } )
	where
	s1 = State1 {
		settings = ([], [], Nothing),
		rnClFinished = "", rnSvFinished = "",
		sKeys = nullKeys, readSN = 0, writeSN = 0,
		rBuffer = (CTNull, ""), wBuffer = (CTNull, ""), adBuffer = "",
		sNames = [], sCert = Nothing }

getGen :: TlsState h g -> g
getGen = gen

setGen :: g -> TlsState h g -> TlsState h g
setGen g st = st { gen = g }

getNames :: PartnerId -> TlsState h g -> [String]
getNames = (sNames .) . getState

setNames :: PartnerId -> [String] -> Modify (TlsState h g)
setNames = setState $ \n st -> st { sNames = n }

getCertificate :: PartnerId -> TlsState h g -> Maybe X509.SignedCertificate
getCertificate = (sCert .) . getState

setCertificate :: PartnerId -> X509.SignedCertificate -> Modify (TlsState h g)
setCertificate = setState $ \c st -> st { sCert = Just c }

getRSn, getWSn :: PartnerId -> TlsState h g -> Word64
getRSn = (readSN .) . getState; getWSn = (writeSN .) . getState

rstRSn, rstWSn :: PartnerId -> Modify (TlsState h g)
rstRSn = modState $ \s -> s { readSN = 0 }
rstWSn = modState $ \s -> s { writeSN = 0 }

sccRSn, sccWSn :: PartnerId -> Modify (TlsState h g)
sccRSn = modState $ \s -> s { readSN = succ $ readSN s }
sccWSn = modState $ \s -> s { writeSN = succ $ writeSN s }

getClFinished, getSvFinished :: PartnerId -> TlsState h g -> BS.ByteString
getClFinished = (rnClFinished .) . getState
getSvFinished = (rnSvFinished .) . getState

setClFinished, setSvFinished :: PartnerId -> BS.ByteString -> Modify (TlsState h g)
setClFinished = setState $ \cf st -> st { rnClFinished = cf }
setSvFinished = setState $ \sf st -> st { rnSvFinished = sf }

getRBuf, getWBuf :: PartnerId -> TlsState h g -> (ContType, BS.ByteString)
getRBuf = (rBuffer .) . getState; getWBuf = (wBuffer .) . getState

getAdBuf :: PartnerId -> TlsState h g -> BS.ByteString
getAdBuf = (adBuffer .) . getState

setRBuf, setWBuf :: PartnerId -> (ContType, BS.ByteString) -> Modify (TlsState h g)
setRBuf = setState $ \bs st -> st { rBuffer = bs }
setWBuf = setState $ \bs st -> st { wBuffer = bs }

setAdBuf :: PartnerId -> BS.ByteString -> Modify (TlsState h g)
setAdBuf = setState $ \bs st -> st { adBuffer = bs }

data RW = Read | Write deriving Show

getCipherSuite :: PartnerId -> TlsState h g -> CipherSuite
getCipherSuite = ((kCchCSuite . sKeys) .) . getState

setCipherSuite :: PartnerId -> CipherSuite -> Modify (TlsState h g)
setCipherSuite = setState $ \cs st -> st { sKeys = (sKeys st) { kCchCSuite = cs } }

flushCipherSuite :: RW -> PartnerId -> Modify (TlsState h g)
flushCipherSuite Read = flushCipherSuiteRead
flushCipherSuite Write = flushCipherSuiteWrite

flushCipherSuiteRead :: PartnerId -> Modify (TlsState h g)
flushCipherSuiteRead = modState $ \st -> st { sKeys = (sKeys st) {
	kRCSuite = kCchCSuite (sKeys st), kRMKey = kCchRMKey (sKeys st),
	kRKey = kCchRKey (sKeys st) } }

flushCipherSuiteWrite :: PartnerId -> Modify (TlsState h g)
flushCipherSuiteWrite = modState $ \st -> st { sKeys = (sKeys st) {
	kWCSuite = kCchCSuite (sKeys st), kWMKey = kCchWMKey (sKeys st),
	kWKey = kCchWKey (sKeys st) } }

data Keys = Keys {
	kMSec :: BS.ByteString,
	kRCSuite :: CipherSuite, kWCSuite :: CipherSuite,
	kRMKey :: BS.ByteString, kWMKey :: BS.ByteString,
	kRKey :: BS.ByteString, kWKey :: BS.ByteString,
	kCchCSuite :: CipherSuite,
	kCchRMKey :: BS.ByteString, kCchWMKey :: BS.ByteString,
	kCchRKey :: BS.ByteString, kCchWKey :: BS.ByteString }
	deriving (Show, Eq)

nullKeys :: Keys
nullKeys = Keys {
	kMSec = "",
	kRCSuite = CipherSuite KE_NULL BE_NULL,
	kWCSuite = CipherSuite KE_NULL BE_NULL,
	kRMKey = "", kWMKey = "", kRKey = "", kWKey = "",
	kCchCSuite = CipherSuite KE_NULL BE_NULL,
	kCchRMKey = "", kCchWMKey = "",
	kCchRKey = "", kCchWKey = "" }

getKeys :: PartnerId -> TlsState h g -> Keys
getKeys = (sKeys .) . getState

setKeys :: PartnerId -> Keys -> Modify (TlsState h g)
setKeys = setState $ \k st -> st { sKeys = k }

type SettingsC = (
	[CipherSuite], [(CertSecretKey, X509.CertificateChain)],
	X509.CertificateStore )

getSettingsC :: PartnerId -> TlsState h g -> Maybe SettingsC
getSettingsC i s = case settings $ getState i s of
	(css, crts, Just cs) -> Just (css, crts, cs)
	_ -> Nothing

setSettingsC :: PartnerId -> SettingsC -> Modify (TlsState h g)
setSettingsC =
	setState $ \(css, crts, cs) st -> st { settings = (css, crts, Just cs) }

type SettingsS = (
	[CipherSuite],
	Maybe (RSA.PrivateKey, X509.CertificateChain),
	Maybe (ECDSA.PrivateKey, X509.CertificateChain),
	Maybe X509.CertificateStore )

getSettingsS :: PartnerId -> TlsState h g -> SettingsS
getSettingsS = ((toS . settings) .) . getState
	where toS (cs, crts, mcs) = (cs,
		first rsaKey <$> find (isRsaKey . fst) crts,
		first ecdsaKey <$> find (isEcdsaKey . fst) crts, mcs)

setSettingsS :: PartnerId -> SettingsS -> Modify (TlsState h g)
setSettingsS = setState $ \is st -> st { settings = fromS is }
	where fromS (cs, rcrt, ecrt, mcs) = (cs,
		maybeToList (first RsaKey <$> rcrt) ++
		maybeToList (first EcdsaKey <$> ecrt), mcs)
