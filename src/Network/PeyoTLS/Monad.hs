{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Network.PeyoTLS.Monad (
	TlsM, run, evalTlsM, S.initState,
		tGet, tPut, tClose, tDebug, thlError,
		withRandom,
		getRBuf, setRBuf, getWBuf, setWBuf,
		getAdBuf, setAdBuf,
		getRSn, getWSn, sccRSn, sccWSn, rstRSn, rstWSn,
		getCipherSuite, setCipherSuite,
		getNames, setNames,
		setKeys, getKeys,
		S.SettingsS, getSettingsS, setSettingsS,
	S.Alert(..), S.AlertLevel(..), S.AlertDesc(..),
	S.ContType(..),
	S.CipherSuite(..), S.KeyEx(..), S.BulkEnc(..),
	S.PartnerId, S.newPartner, S.Keys(..), S.nullKeys,

	getClFinished, setClFinished,
	getSvFinished, setSvFinished,
	S.CertSecretKey(..), S.isRsaKey, S.isEcdsaKey,

	SettingsC, getSettingsC, setSettingsC,
	RW(..),
	flushCipherSuite,
	) where

import Control.Arrow ((***))
import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT, throwError, catchError)
import Data.Word (Word64)
import Data.HandleLike (HandleLike(..))

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import qualified Network.PeyoTLS.State as S (
	HandshakeState, initState, PartnerId, newPartner, Keys(..), nullKeys,
	ContType(..), Alert(..), AlertLevel(..), AlertDesc(..),
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	randomGen, setRandomGen,
	setBuf, getBuf, setWBuf, getWBuf,
	setAdBuf, getAdBuf,
	getReadSN, getWriteSN, succReadSN, succWriteSN, resetReadSN, resetWriteSN,
	getCipherSuite, setCipherSuite,
	setNames, getNames,
	setKeys, getKeys,
	getSettings, setSettings,
	getInitSet, setInitSet,
	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,

	flushCipherSuiteRead, flushCipherSuiteWrite,

	SettingsS, Settings,
	CertSecretKey(..), isRsaKey, isEcdsaKey,
	)

run :: HandleLike h => TlsM h g a -> g -> HandleMonad h a
run m g = do
	ret <- (`evalTlsM` S.initState g) $ m `catchError` \a -> throwError a
	case ret of
		Right r -> return r
		Left a -> error $ show a

type TlsM h g = ErrorT S.Alert (StateT (S.HandshakeState h g) (HandleMonad h))

evalTlsM :: HandleLike h => 
	TlsM h g a -> S.HandshakeState h g -> HandleMonad h (Either S.Alert a)
evalTlsM = evalStateT . runErrorT

getRBuf, getWBuf ::  HandleLike h =>
	S.PartnerId -> TlsM h g (S.ContType, BS.ByteString)
getRBuf = gets . S.getBuf; getWBuf = gets . S.getWBuf

getAdBuf :: HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getAdBuf = gets . S.getAdBuf

setAdBuf :: HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setAdBuf = (modify .) . S.setAdBuf

setRBuf, setWBuf :: HandleLike h =>
	S.PartnerId -> (S.ContType, BS.ByteString) -> TlsM h g ()
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

getNames :: HandleLike h => S.PartnerId -> TlsM h g [String]
getNames = gets . S.getNames

setNames :: HandleLike h => S.PartnerId -> [String] -> TlsM h g ()
setNames = (modify .) . S.setNames

setKeys :: HandleLike h => S.PartnerId -> S.Keys -> TlsM h g ()
setKeys = (modify .) . S.setKeys

getKeys :: HandleLike h => S.PartnerId -> TlsM h g S.Keys
getKeys = gets . S.getKeys

getSettingsS :: HandleLike h => S.PartnerId -> TlsM h g S.SettingsS
getSettingsS = gets . S.getInitSet

getSettings :: HandleLike h => S.PartnerId -> TlsM h g S.Settings
getSettings = gets . S.getSettings

setSettingsS :: HandleLike h => S.PartnerId -> S.SettingsS -> TlsM h g ()
setSettingsS = (modify .) . S.setInitSet

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

flushCipherSuite :: HandleLike h => RW -> S.PartnerId -> TlsM h g ()
flushCipherSuite rw = case rw of
	Read -> flushCipherSuiteRead
	Write -> flushCipherSuiteWrite

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

data RW = Read | Write deriving Show
