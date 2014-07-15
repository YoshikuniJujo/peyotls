{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

module Network.PeyoTLS.State (
	TlsState, initState, PartnerId, newPartner,
		getGen, setGen, getNames, setNames,
		getRSn, getWSn, rstRSn, rstWSn, sccRSn, sccWSn,
		getClFinished, setClFinished, getSvFinished, setSvFinished,
	ContType(..), getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf,
	CipherSuite(..), BulkEnc(..), RW(..),
		getCipherSuite, setCipherSuite, flushCipherSuite,
	Keys(..), getKeys, setKeys,
	SettingsC, getSettingsC, setSettingsC,
	SettingsS, getSettingsS, setSettingsS,
	CertSecretKey(..), isRsaKey, isEcdsaKey ) where

import Control.Applicative ((<$>))
import Control.Arrow (first)
import Data.Maybe (fromJust, maybeToList)
import Data.List (find)
import Data.Word (Word8, Word64)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

import Network.PeyoTLS.CertSecretKey (CertSecretKey(..), isRsaKey, isEcdsaKey)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import Network.PeyoTLS.CipherSuite (
	CipherSuite(..), KeyEx(..), BulkEnc(..))

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

data TlsState h g = TlsState {
	getGen :: g, nextPartnerId :: Int,
	states :: [(PartnerId, StateOne g)] }

initState :: g -> TlsState h g
initState g = TlsState{ getGen = g, nextPartnerId = 0, states = [] }

data PartnerId = PartnerId Int deriving (Show, Eq)

newPartner :: TlsState h g -> (PartnerId, TlsState h g)
newPartner s = (PartnerId i ,) s{
	nextPartnerId = succ i,
	states = (PartnerId i, so) : sos }
	where
	i = nextPartnerId s
	so = StateOne {
		sKeys = nullKeys,
		rBuffer = (CTNull, ""), wBuffer = (CTNull, ""),
		radBuffer = "",
		readSN = 0, writeSN = 0,
		rnClientFinished = "", rnServerFinished = "",
		initialSettings = ([], [], Nothing),
		sNames = []
		}
	sos = states s

type SettingsS = (
	[CipherSuite],
	Maybe (RSA.PrivateKey, X509.CertificateChain),
	Maybe (ECDSA.PrivateKey, X509.CertificateChain),
	Maybe X509.CertificateStore )

type Settings = (
	[CipherSuite],
	[(CertSecretKey, X509.CertificateChain)],
	Maybe X509.CertificateStore )

convertSettings :: Settings -> SettingsS
convertSettings (cs, crts, mcs) = (cs,
	first rsaKey <$> find (isRsaKey . fst) crts,
	first ecdsaKey <$> find (isEcdsaKey . fst) crts, mcs)

revertSettings :: SettingsS -> Settings
revertSettings (cs, rcrt, ecrt, mcs) = (cs,
	maybeToList (first RsaKey <$> rcrt) ++
	maybeToList (first EcdsaKey <$> ecrt), mcs)

data StateOne g = StateOne {
	sKeys :: Keys,
	rBuffer :: (ContType, BS.ByteString),
	wBuffer :: (ContType, BS.ByteString),
	radBuffer :: BS.ByteString,
	readSN :: Word64,
	writeSN :: Word64,
	rnClientFinished :: BS.ByteString,
	rnServerFinished :: BS.ByteString,
	initialSettings :: Settings,
	sNames :: [String]
	}

getState :: PartnerId -> TlsState h g -> StateOne g
getState i = fromJust' "getState" . lookup i . states

setState :: PartnerId -> StateOne g -> Modify (TlsState h g)
setState i so s = s { states = (i, so) : states s }

modifyState :: PartnerId -> Modify (StateOne g) -> Modify (TlsState h g)
modifyState i f s = setState i (f $ getState i s) s

data Keys = Keys {
	kCachedCS :: CipherSuite,
	kReadCS :: CipherSuite, kWriteCS :: CipherSuite,
	kMasterSecret :: BS.ByteString,
	kCachedReadMacKey :: BS.ByteString,
	kCachedWriteMacKey :: BS.ByteString,
	kCachedReadKey :: BS.ByteString,
	kCachedWriteKey :: BS.ByteString,
	kReadMacKey :: BS.ByteString, kWriteMacKey :: BS.ByteString,
	kReadKey :: BS.ByteString, kWriteKey :: BS.ByteString }
	deriving (Show, Eq)

nullKeys :: Keys
nullKeys = Keys {
	kCachedCS = CipherSuite KE_NULL BE_NULL,
	kReadCS = CipherSuite KE_NULL BE_NULL,
	kWriteCS = CipherSuite KE_NULL BE_NULL,
	kMasterSecret = "",
	kCachedReadMacKey = "", kCachedWriteMacKey = "",
	kCachedReadKey = "", kCachedWriteKey = "",
	kReadMacKey = "", kWriteMacKey = "", kReadKey = "", kWriteKey = "" }

data ContType
	= CTCCSpec | CTAlert | CTHandshake | CTAppData | CTNull | CTRaw Word8
	deriving (Show, Eq)

instance B.Bytable ContType where
	encode CTNull = BS.pack [0]
	encode CTCCSpec = BS.pack [20]
	encode CTAlert = BS.pack [21]
	encode CTHandshake = BS.pack [22]
	encode CTAppData = BS.pack [23]
	encode (CTRaw ct) = BS.pack [ct]
	decode "\0" = Right CTNull
	decode "\20" = Right CTCCSpec
	decode "\21" = Right CTAlert
	decode "\22" = Right CTHandshake
	decode "\23" = Right CTAppData
	decode bs | [ct] <- BS.unpack bs = Right $ CTRaw ct
	decode _ = Left "State.decodeCT"

setGen :: g -> TlsState h g -> TlsState h g
setGen rg st = st { getGen = rg }

getRBuf :: PartnerId -> TlsState h g -> (ContType, BS.ByteString)
getRBuf i = rBuffer . fromJust' "getRBuf" . lookup i . states

setRBuf :: PartnerId -> (ContType, BS.ByteString) -> Modify (TlsState h g)
setRBuf i = modifyState i . \bs st -> st { rBuffer = bs }

getAdBuf :: PartnerId -> TlsState h g -> BS.ByteString
getAdBuf i = radBuffer . fromJust' "getAdBuf" . lookup i . states

setAdBuf :: PartnerId -> BS.ByteString -> Modify (TlsState h g)
setAdBuf i = modifyState i . \bs st -> st { radBuffer = bs }

getCipherSuite :: PartnerId -> TlsState h g -> CipherSuite
getCipherSuite i =
	kCachedCS . sKeys . fromJust' "getCipherSuite" . lookup i . states

setCipherSuite :: PartnerId -> CipherSuite -> Modify (TlsState h g)
setCipherSuite i = modifyState i . \cs st ->
	st { sKeys = (sKeys st) { kCachedCS = cs } }

getNames :: PartnerId -> TlsState h g -> [String]
getNames i = sNames . fromJust' "getNames" . lookup i . states

setNames :: PartnerId -> [String] -> Modify (TlsState h g)
setNames i = modifyState i . \n st -> st { sNames = n }

getKeys :: PartnerId -> TlsState h g -> Keys
getKeys i = sKeys . fromJust' "getKeys" . lookup i . states

setKeys :: PartnerId -> Keys -> Modify (TlsState h g)
setKeys i = modifyState i . \k st -> st { sKeys = k }

getSettings :: PartnerId -> TlsState h g -> Settings
getSettings i = initialSettings . fromJust' "getSettings" . lookup i . states

type SettingsC = (
	[CipherSuite],
	[(CertSecretKey, X509.CertificateChain)],
	X509.CertificateStore )

getSettingsC :: PartnerId -> TlsState h g -> Maybe SettingsC
getSettingsC i s = case getSettings i s of
	(css, crts, Just cs) -> Just (css, crts, cs)
	_ -> Nothing

getSettingsS :: PartnerId -> TlsState h g -> SettingsS
getSettingsS i = convertSettings .
	initialSettings . fromJust' "getSettingsS" . lookup i . states

setSettings :: PartnerId -> Settings -> Modify (TlsState h g)
setSettings i = modifyState i . \is st -> st { initialSettings = is }

setSettingsC :: PartnerId -> SettingsC -> Modify (TlsState h g)
setSettingsC i (css, crts, cs) = setSettings i (css, crts, Just cs)

setSettingsS :: PartnerId -> SettingsS -> Modify (TlsState h g)
setSettingsS i = modifyState i . \is st -> st
	{ initialSettings = revertSettings is }

getClFinished, getSvFinished ::
	PartnerId -> TlsState h g -> BS.ByteString
getClFinished i =
	rnClientFinished . fromJust' "getClFinished" . lookup i . states
getSvFinished i =
	rnServerFinished . fromJust' "getClFinished" . lookup i . states

setClFinished, setSvFinished ::
	PartnerId -> BS.ByteString -> Modify (TlsState h g)
setClFinished i = modifyState i . \cf st -> st { rnClientFinished = cf }
setSvFinished i = modifyState i . \sf st -> st { rnServerFinished = sf }

flushCipherSuite :: RW -> PartnerId -> Modify (TlsState h g)
flushCipherSuite Read = flushCipherSuiteRead
flushCipherSuite Write = flushCipherSuiteWrite

flushCipherSuiteRead :: PartnerId -> Modify (TlsState h g)
flushCipherSuiteRead i = modifyState i $ \st ->
	st { sKeys = (sKeys st) {
		kReadCS = kCachedCS (sKeys st),
		kReadMacKey = kCachedReadMacKey (sKeys st),
		kReadKey = kCachedReadKey (sKeys st)
		} }

flushCipherSuiteWrite :: PartnerId -> Modify (TlsState h g)
flushCipherSuiteWrite i = modifyState i $ \st ->
	st { sKeys = (sKeys st) {
		kWriteCS = kCachedCS (sKeys st),
		kWriteMacKey = kCachedWriteMacKey (sKeys st),
		kWriteKey = kCachedWriteKey (sKeys st)
		} }

getWBuf :: PartnerId -> TlsState h g -> (ContType, BS.ByteString)
getWBuf i = wBuffer . fromJust' "getWriteBuffer" . lookup i . states

setWBuf :: PartnerId -> (ContType, BS.ByteString) -> Modify (TlsState h g)
setWBuf i = modifyState i . \bs st -> st{ wBuffer = bs }

getRSn, getWSn :: PartnerId -> TlsState h g -> Word64
getRSn i = readSN . fromJust . lookup i . states
getWSn i = writeSN . fromJust . lookup i . states

sccRSn, sccWSn :: PartnerId -> Modify (TlsState h g)
sccRSn i = modifyState i $ \s -> s{ readSN = succ $ readSN s }
sccWSn i = modifyState i $ \s -> s{ writeSN = succ $ writeSN s }

rstRSn, rstWSn :: PartnerId -> Modify (TlsState h g)
rstRSn i = modifyState i $ \s -> s{ readSN = 0 }
rstWSn i = modifyState i $ \s -> s{ writeSN = 0 }

type Modify s = s -> s

fromJust' :: String -> Maybe a -> a
fromJust' _ (Just x) = x
fromJust' msg _ = error msg

data RW = Read | Write deriving Show
