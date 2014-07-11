{-# LANGUAGE PackageImports #-}

module Network.PeyoTLS.Monad (
	TlsM, evalTlsM, S.initState,
		thlGet, thlPut, thlClose, thlDebug, thlError,
		withRandom,
		getRBuf, setRBuf, getWBuf, setWBuf,
		getAdBuf, setAdBuf,
		getRSn, getWSn, sccRSn, sccWSn, rstRSn, rstWSn,
		getCipherSuiteSt, setCipherSuiteSt,
		flushCipherSuiteRead, flushCipherSuiteWrite, setKeys, getKeys,
		getSettings, setSettings,
		getInitSet, setInitSet, S.SettingsS, S.Settings,
	S.Alert(..), S.AlertLevel(..), S.AlertDesc(..),
	S.ContentType(..),
	S.CipherSuite(..), S.KeyEx(..), S.BulkEnc(..),
	S.PartnerId, S.newPartnerId, S.Keys(..), S.nullKeys,

	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,
	S.CertSecretKey(..), S.isRsaKey, S.isEcdsaKey,
	) where

import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT)
import Data.Word (Word64)
import Data.HandleLike (HandleLike(..))

import qualified Data.ByteString as BS

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

getCipherSuiteSt :: HandleLike h => S.PartnerId -> TlsM h g S.CipherSuite
getCipherSuiteSt = gets . S.getCipherSuite

setCipherSuiteSt :: HandleLike h => S.PartnerId -> S.CipherSuite -> TlsM h g ()
setCipherSuiteSt = (modify .) . S.setCipherSuite

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

getClientFinished, getServerFinished ::
	HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getClientFinished = gets . S.getClientFinished
getServerFinished = gets . S.getServerFinished

setClientFinished, setServerFinished ::
	HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setClientFinished = (modify .) . S.setClientFinished
setServerFinished = (modify .) . S.setServerFinished

flushCipherSuiteRead, flushCipherSuiteWrite ::
	HandleLike h => S.PartnerId -> TlsM h g ()
flushCipherSuiteRead = modify . S.flushCipherSuiteRead
flushCipherSuiteWrite = modify . S.flushCipherSuiteWrite

withRandom :: HandleLike h => (gen -> (a, gen)) -> TlsM h gen a
withRandom p = do
	(x, g') <- p `liftM` gets S.randomGen
	modify $ S.setRandomGen g'
	return x

thlGet :: HandleLike h => h -> Int -> TlsM h g BS.ByteString
thlGet = ((lift . lift) .) . hlGet

thlPut :: HandleLike h => h -> BS.ByteString -> TlsM h g ()
thlPut = ((lift . lift) .) . hlPut

thlClose :: HandleLike h => h -> TlsM h g ()
thlClose = lift . lift . hlClose

thlDebug :: HandleLike h =>
	h -> DebugLevel h -> BS.ByteString -> TlsM h gen ()
thlDebug = (((lift . lift) .) .) . hlDebug

thlError :: HandleLike h => h -> BS.ByteString -> TlsM h g a
thlError = ((lift . lift) .) . hlError
