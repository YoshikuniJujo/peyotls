{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

module Network.PeyoTLS.State (
	HandshakeState, initState, PartnerId, newPartnerId, Keys(..), nullKeys,
	ContentType(..), Alert(..), AlertLevel(..), AlertDesc(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	randomGen, setRandomGen,
	getBuf, setBuf, getWBuf, setWBuf,
	getReadSN, getWriteSN, succReadSN, succWriteSN, resetReadSN, resetWriteSN,
	getCipherSuite, setCipherSuite, flushCipherSuiteRead, flushCipherSuiteWrite,
	getKeys, setKeys,
	getInitSet, setInitSet,
	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,

	InitialSettings,
) where

import "monads-tf" Control.Monad.Error.Class (Error(strMsg))
import Data.Maybe (fromJust)
import Data.Word (Word8, Word64)
import Data.String (IsString(..))

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

import Network.PeyoTLS.CertSecretKey
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import Network.PeyoTLS.CipherSuite (
	CipherSuite(..), KeyExchange(..), BulkEncryption(..))

data HandshakeState h g = HandshakeState {
	randomGen :: g, nextPartnerId :: Int,
	states :: [(PartnerId, StateOne g)] }

initState :: g -> HandshakeState h g
initState g = HandshakeState{ randomGen = g, nextPartnerId = 0, states = [] }

data PartnerId = PartnerId Int deriving (Show, Eq)

newPartnerId :: HandshakeState h g -> (PartnerId, HandshakeState h g)
newPartnerId s = (PartnerId i ,) s{
	nextPartnerId = succ i,
	states = (PartnerId i, so) : sos }
	where
	i = nextPartnerId s
	so = StateOne {
		sKeys = nullKeys,
		rBuffer = (CTNull, ""), wBuffer = (CTNull, ""),
		readSN = 0, writeSN = 0,
		rnClientFinished = "", rnServerFinished = "",
		initialSettings = ([], [], Nothing)
		}
	sos = states s

type InitialSettings = (
	[CipherSuite], [(CertSecretKey, X509.CertificateChain)],
	Maybe X509.CertificateStore)

data StateOne g = StateOne {
	sKeys :: Keys,
	rBuffer :: (ContentType, BS.ByteString),
	wBuffer :: (ContentType, BS.ByteString),
	readSN :: Word64,
	writeSN :: Word64,
	rnClientFinished :: BS.ByteString,
	rnServerFinished :: BS.ByteString,
	initialSettings :: (
		[CipherSuite], [(CertSecretKey, X509.CertificateChain)],
		Maybe X509.CertificateStore)
	}

getState :: PartnerId -> HandshakeState h g -> StateOne g
getState i = fromJust' "getState" . lookup i . states

setState :: PartnerId -> StateOne g -> Modify (HandshakeState h g)
setState i so s = s { states = (i, so) : states s }

modifyState :: PartnerId -> Modify (StateOne g) -> Modify (HandshakeState h g)
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

data ContentType
	= CTCCSpec | CTAlert | CTHandshake | CTAppData | CTNull | CTRaw Word8
	deriving (Show, Eq)

instance B.Bytable ContentType where
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

data Alert = Alert AlertLevel AlertDesc String | NotDetected String
	deriving Show

data AlertLevel = ALWarning | ALFatal | ALRaw Word8 deriving Show

data AlertDesc
	= ADCloseNotify            | ADUnexpectedMessage  | ADBadRecordMac
	| ADUnsupportedCertificate | ADCertificateExpired | ADCertificateUnknown
	| ADIllegalParameter       | ADUnknownCa          | ADDecodeError
	| ADDecryptError           | ADProtocolVersion    | ADRaw Word8
	deriving Show

instance Error Alert where
	strMsg = NotDetected

instance IsString Alert where
	fromString = NotDetected

setRandomGen :: g -> HandshakeState h g -> HandshakeState h g
setRandomGen rg st = st { randomGen = rg }

getBuf :: PartnerId -> HandshakeState h g -> (ContentType, BS.ByteString)
getBuf i = rBuffer . fromJust' "getBuf" . lookup i . states

setBuf :: PartnerId -> (ContentType, BS.ByteString) -> Modify (HandshakeState h g)
setBuf i = modifyState i . \bs st -> st { rBuffer = bs }

getCipherSuite :: PartnerId -> HandshakeState h g -> CipherSuite
getCipherSuite i =
	kCachedCS . sKeys . fromJust' "getCipherSuite" . lookup i . states

setCipherSuite :: PartnerId -> CipherSuite -> Modify (HandshakeState h g)
setCipherSuite i = modifyState i . \cs st ->
	st { sKeys = (sKeys st) { kCachedCS = cs } }

getKeys :: PartnerId -> HandshakeState h g -> Keys
getKeys i = sKeys . fromJust' "getKeys" . lookup i . states

setKeys :: PartnerId -> Keys -> Modify (HandshakeState h g)
setKeys i = modifyState i . \k st -> st { sKeys = k }

getInitSet :: PartnerId -> HandshakeState h g -> InitialSettings
getInitSet i = initialSettings . fromJust' "getInitSet" . lookup i . states

setInitSet :: PartnerId -> InitialSettings -> Modify (HandshakeState h g)
setInitSet i = modifyState i . \is st -> st { initialSettings = is }

getClientFinished, getServerFinished ::
	PartnerId -> HandshakeState h g -> BS.ByteString
getClientFinished i =
	rnClientFinished . fromJust' "getClientFinished" . lookup i . states
getServerFinished i =
	rnServerFinished . fromJust' "getClientFinished" . lookup i . states

setClientFinished, setServerFinished ::
	PartnerId -> BS.ByteString -> Modify (HandshakeState h g)
setClientFinished i = modifyState i . \cf st -> st { rnClientFinished = cf }
setServerFinished i = modifyState i . \sf st -> st { rnServerFinished = sf }

flushCipherSuiteRead :: PartnerId -> Modify (HandshakeState h g)
flushCipherSuiteRead i = modifyState i $ \st ->
	st { sKeys = (sKeys st) {
		kReadCS = kCachedCS (sKeys st),
		kReadMacKey = kCachedReadMacKey (sKeys st),
		kReadKey = kCachedReadKey (sKeys st)
		} }

flushCipherSuiteWrite :: PartnerId -> Modify (HandshakeState h g)
flushCipherSuiteWrite i = modifyState i $ \st ->
	st { sKeys = (sKeys st) {
		kWriteCS = kCachedCS (sKeys st),
		kWriteMacKey = kCachedWriteMacKey (sKeys st),
		kWriteKey = kCachedWriteKey (sKeys st)
		} }

getWBuf :: PartnerId -> HandshakeState h g -> (ContentType, BS.ByteString)
getWBuf i = wBuffer . fromJust' "getWriteBuffer" . lookup i . states

setWBuf :: PartnerId -> (ContentType, BS.ByteString) -> Modify (HandshakeState h g)
setWBuf i = modifyState i . \bs st -> st{ wBuffer = bs }

getReadSN, getWriteSN :: PartnerId -> HandshakeState h g -> Word64
getReadSN i = readSN . fromJust . lookup i . states
getWriteSN i = writeSN . fromJust . lookup i . states

succReadSN, succWriteSN :: PartnerId -> Modify (HandshakeState h g)
succReadSN i = modifyState i $ \s -> s{ readSN = succ $ readSN s }
succWriteSN i = modifyState i $ \s -> s{ writeSN = succ $ writeSN s }

resetReadSN, resetWriteSN :: PartnerId -> Modify (HandshakeState h g)
resetReadSN i = modifyState i $ \s -> s{ readSN = 0 }
resetWriteSN i = modifyState i $ \s -> s{ writeSN = 0 }

type Modify s = s -> s

fromJust' :: String -> Maybe a -> a
fromJust' _ (Just x) = x
fromJust' msg _ = error msg
