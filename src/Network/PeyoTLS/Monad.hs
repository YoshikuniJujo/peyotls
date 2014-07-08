{-# LANGUAGE PackageImports #-}

module Network.PeyoTLS.Monad (
	TlsM, evalTlsM, S.initState,
		thlGet, thlPut, thlClose, thlDebug, thlError,
		withRandom, randomByteString,
		getBuf, setBuf, getWBuf, setWBuf,
		getAdBuf, setAdBuf,
		getReadSn, getWriteSn, succReadSn, succWriteSn,
		resetReadSn, resetWriteSn,
		getCipherSuiteSt, setCipherSuiteSt,
		flushCipherSuiteRead, flushCipherSuiteWrite, setKeys, getKeys,
		getSettings, setSettings,
		getInitSet, setInitSet, S.InitialSettings, S.Settings,
	S.Alert(..), S.AlertLevel(..), S.AlertDesc(..),
	S.ContentType(..),
	S.CipherSuite(..), S.KeyEx(..), S.BulkEnc(..),
	S.PartnerId, S.newPartnerId, S.Keys(..), S.nullKeys,

	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,
	S.CertSecretKey(..),
	) where

import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT)
import Data.Word (Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG, cprgGenerate)

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

	InitialSettings, Settings,
	CertSecretKey(..),
	)

type TlsM h g = ErrorT S.Alert (StateT (S.HandshakeState h g) (HandleMonad h))

evalTlsM :: HandleLike h => 
	TlsM h g a -> S.HandshakeState h g -> HandleMonad h (Either S.Alert a)
evalTlsM = evalStateT . runErrorT

getBuf, getWBuf ::  HandleLike h =>
	S.PartnerId -> TlsM h g (S.ContentType, BS.ByteString)
getBuf = gets . S.getBuf; getWBuf = gets . S.getWBuf

getAdBuf :: HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getAdBuf = gets . S.getAdBuf

setAdBuf :: HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setAdBuf = (modify .) . S.setAdBuf

setBuf, setWBuf :: HandleLike h =>
	S.PartnerId -> (S.ContentType, BS.ByteString) -> TlsM h g ()
setBuf = (modify .) . S.setBuf; setWBuf = (modify .) . S.setWBuf

getWriteSn, getReadSn :: HandleLike h => S.PartnerId -> TlsM h g Word64
getWriteSn = gets . S.getWriteSN; getReadSn = gets . S.getReadSN

succWriteSn, succReadSn :: HandleLike h => S.PartnerId -> TlsM h g ()
succWriteSn = modify . S.succWriteSN; succReadSn = modify . S.succReadSN

resetWriteSn, resetReadSn :: HandleLike h => S.PartnerId -> TlsM h g ()
resetWriteSn = modify . S.resetWriteSN; resetReadSn = modify . S.resetReadSN

getCipherSuiteSt :: HandleLike h => S.PartnerId -> TlsM h g S.CipherSuite
getCipherSuiteSt = gets . S.getCipherSuite

setCipherSuiteSt :: HandleLike h => S.PartnerId -> S.CipherSuite -> TlsM h g ()
setCipherSuiteSt = (modify .) . S.setCipherSuite

setKeys :: HandleLike h => S.PartnerId -> S.Keys -> TlsM h g ()
setKeys = (modify .) . S.setKeys

getKeys :: HandleLike h => S.PartnerId -> TlsM h g S.Keys
getKeys = gets . S.getKeys

getInitSet :: HandleLike h => S.PartnerId -> TlsM h g S.InitialSettings
getInitSet = gets . S.getInitSet

getSettings :: HandleLike h => S.PartnerId -> TlsM h g S.Settings
getSettings = gets . S.getSettings

setInitSet :: HandleLike h => S.PartnerId -> S.InitialSettings -> TlsM h g ()
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

randomByteString :: (HandleLike h, CPRG g) => Int -> TlsM h g BS.ByteString
randomByteString = withRandom . cprgGenerate

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
