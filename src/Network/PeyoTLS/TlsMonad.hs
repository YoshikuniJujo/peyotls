{-# LANGUAGE PackageImports #-}

module Network.PeyoTLS.TlsMonad (
	TlsM, evalTlsM, S.initState,
		thlGet, thlPut, thlClose, thlDebug, thlError,
		withRandom, randomByteString, getBuf, setBuf, getWBuf, setWBuf,
		getReadSn, getWriteSn, succReadSn, succWriteSn,
	S.Alert(..), S.AlertLevel(..), S.AlertDesc(..),
	S.ContentType(..),
	S.CipherSuite(..), S.KeyExchange(..), S.BulkEncryption(..),
	S.PartnerId, S.newPartnerId, S.Keys(..), S.nullKeys ) where

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
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	randomGen, setRandomGen,
	setBuf, getBuf, setWBuf, getWBuf,
	getReadSN, getWriteSN, succReadSN, succWriteSN )

type TlsM h g = ErrorT S.Alert (StateT (S.HandshakeState h g) (HandleMonad h))

evalTlsM :: HandleLike h => 
	TlsM h g a -> S.HandshakeState h g -> HandleMonad h (Either S.Alert a)
evalTlsM = evalStateT . runErrorT

getBuf, getWBuf ::  HandleLike h =>
	S.PartnerId -> TlsM h g (S.ContentType, BS.ByteString)
getBuf = gets . S.getBuf; getWBuf = gets . S.getWBuf

setBuf, setWBuf :: HandleLike h =>
	S.PartnerId -> (S.ContentType, BS.ByteString) -> TlsM h g ()
setBuf = (modify .) . S.setBuf; setWBuf = (modify .) . S.setWBuf

getWriteSn, getReadSn :: HandleLike h => S.PartnerId -> TlsM h g Word64
getWriteSn = gets . S.getWriteSN; getReadSn = gets . S.getReadSN

succWriteSn, succReadSn :: HandleLike h => S.PartnerId -> TlsM h g ()
succWriteSn = modify . S.succWriteSN; succReadSn = modify . S.succReadSN

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
