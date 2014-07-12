{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Network.PeyoTLS.Monad (
	TlsM, evalTlsM, S.initState,
		tGet, tPut, tClose, tDebug, thlError,
		withRandom,
		getRBuf, setRBuf, getWBuf, setWBuf,
		getAdBuf, setAdBuf,
		getRSn, getWSn, sccRSn, sccWSn, rstRSn, rstWSn,
		getCipherSuite, setCipherSuite,
		flushCipherSuiteRead, flushCipherSuiteWrite, setKeys, getKeys,
		getSettings, setSettings, SettingsC,
		getInitSet, setInitSet, S.SettingsS, S.Settings,
	S.Alert(..), S.AlertLevel(..), S.AlertDesc(..),
	S.ContentType(..),
	S.CipherSuite(..), S.KeyEx(..), S.BulkEnc(..),
	S.PartnerId, S.newPartnerId, S.Keys(..), S.nullKeys,

	getClFinished, setClFinished,
	getSvFinished, setSvFinished,
	S.CertSecretKey(..), S.isRsaKey, S.isEcdsaKey,

	getSettingsC, setSettingsC,
	) where

import Control.Arrow ((***))
import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT, throwError)
import Data.Word (Word64)
import Data.HandleLike (HandleLike(..))

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import qualified Network.PeyoTLS.State as S (
	HandshakeState, initState, PartnerId, newPartnerId, Keys(..), nullKeys,
	ContentType(..), Alert(..), AlertLevel(..), AlertDesc(..),
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	randomGen, setRandomGen,
	setBuf, getBuf, setWBuf, getWBuf,
	setAdBuf, getAdBuf,
	getReadSN, getWriteSN, succReadSN, succWriteSN, resetReadSN, resetWriteSN,
	getCipherSuite, setCipherSuite,
	flushCipherSuiteRead, flushCipherSuiteWrite, setKeys, getKeys,
	getSettings, setSettings,
	getInitSet, setInitSet,
	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,

	SettingsS, Settings,
	CertSecretKey(..), isRsaKey, isEcdsaKey,
	)

type TlsM h g = ErrorT S.Alert (StateT (S.HandshakeState h g) (HandleMonad h))

evalTlsM :: HandleLike h => 
	TlsM h g a -> S.HandshakeState h g -> HandleMonad h (Either S.Alert a)
evalTlsM = evalStateT . runErrorT

getRBuf, getWBuf ::  HandleLike h =>
	S.PartnerId -> TlsM h g (S.ContentType, BS.ByteString)
getRBuf = gets . S.getBuf; getWBuf = gets . S.getWBuf

getAdBuf :: HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getAdBuf = gets . S.getAdBuf

setAdBuf :: HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setAdBuf = (modify .) . S.setAdBuf

setRBuf, setWBuf :: HandleLike h =>
	S.PartnerId -> (S.ContentType, BS.ByteString) -> TlsM h g ()
setRBuf = (modify .) . S.setBuf; setWBuf = (modify .) . S.setWBuf

getWSn, getRSn :: HandleLike h => S.PartnerId -> TlsM h g Word64
getWSn = gets . S.getWriteSN; getRSn = gets . S.getReadSN

sccWSn, sccRSn :: HandleLike h => S.PartnerId -> TlsM h g ()
sccWSn = modify . S.succWriteSN; sccRSn = modify . S.succReadSN

rstWSn, rstRSn :: HandleLike h => S.PartnerId -> TlsM h g ()
rstWSn = modify . S.resetWriteSN; rstRSn = modify . S.resetReadSN

getCipherSuite :: HandleLike h => S.PartnerId -> TlsM h g S.CipherSuite
getCipherSuite = gets . S.getCipherSuite

setCipherSuite :: HandleLike h => S.PartnerId -> S.CipherSuite -> TlsM h g ()
setCipherSuite = (modify .) . S.setCipherSuite

setKeys :: HandleLike h => S.PartnerId -> S.Keys -> TlsM h g ()
setKeys = (modify .) . S.setKeys

getKeys :: HandleLike h => S.PartnerId -> TlsM h g S.Keys
getKeys = gets . S.getKeys

getInitSet :: HandleLike h => S.PartnerId -> TlsM h g S.SettingsS
getInitSet = gets . S.getInitSet

getSettings :: HandleLike h => S.PartnerId -> TlsM h g S.Settings
getSettings = gets . S.getSettings

setInitSet :: HandleLike h => S.PartnerId -> S.SettingsS -> TlsM h g ()
setInitSet = (modify .) . S.setInitSet

setSettings :: HandleLike h => S.PartnerId -> S.Settings -> TlsM h g ()
setSettings = (modify .) . S.setSettings

getClFinished, getSvFinished ::
	HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getClFinished = gets . S.getClientFinished
getSvFinished = gets . S.getServerFinished

setClFinished, setSvFinished ::
	HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setClFinished = (modify .) . S.setClientFinished
setSvFinished = (modify .) . S.setServerFinished

flushCipherSuiteRead, flushCipherSuiteWrite ::
	HandleLike h => S.PartnerId -> TlsM h g ()
flushCipherSuiteRead = modify . S.flushCipherSuiteRead
flushCipherSuiteWrite = modify . S.flushCipherSuiteWrite

withRandom :: HandleLike h => (gen -> (a, gen)) -> TlsM h gen a
withRandom p = p `liftM` gets S.randomGen >>=
	uncurry (flip (>>)) . (return *** modify . S.setRandomGen)

tGet :: HandleLike h => h -> Int -> TlsM h g BS.ByteString
tGet = ((lift . lift) .) . hlGet

tPut :: HandleLike h => h -> BS.ByteString -> TlsM h g ()
tPut = ((lift . lift) .) . hlPut

tClose :: HandleLike h => h -> TlsM h g ()
tClose = lift . lift . hlClose

tDebug :: HandleLike h =>
	h -> DebugLevel h -> BS.ByteString -> TlsM h gen ()
tDebug = (((lift . lift) .) .) . hlDebug

thlError :: HandleLike h => h -> BS.ByteString -> TlsM h g a
thlError = ((lift . lift) .) . hlError

getSettingsC :: HandleLike h => S.PartnerId -> TlsM h g SettingsC
getSettingsC i = do
	(css, crts, mcs) <- getSettings i
	case mcs of
		Just cs -> return (css, crts, cs)
		_ -> throwError "Network.PeyoTLS.Base.getSettingsC"

setSettingsC :: HandleLike h => S.PartnerId -> SettingsC -> TlsM h g ()
setSettingsC i (css, crts, cs) = setSettings i (css, crts, Just cs)

type SettingsC = (
	[S.CipherSuite],
	[(S.CertSecretKey, X509.CertificateChain)],
	X509.CertificateStore )
