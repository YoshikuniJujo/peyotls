{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Network.PeyoTLS.Monad (
	TlsM, run, throw, withRandom,
		S.Alert(..), S.AlertLevel(..), S.AlertDesc(..),
		tGet, decrypt, tPut, encrypt, tClose, tDebug,
	S.PartnerId, S.newPartner, S.ContType(..),
		getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf, rstSn,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		getNames, setNames,
	S.CipherSuite(..), S.CertSecretKey(..), S.isRsaKey, S.isEcdsaKey,
		SettingsC, getSettingsC, setSettingsC,
		S.SettingsS, getSettingsS, setSettingsS,
		RW(..), getCipherSuite, setCipherSuite, flushCipherSuite,
	S.Keys(..), makeKeys, getKeys, setKeys,
	C.Side(..), finishedHash ) where

import Control.Arrow ((***))
import Control.Monad (unless, liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT, throwError, catchError)
import Data.Word (Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B

import qualified Network.PeyoTLS.State as S (
	HandshakeState, initState, PartnerId, newPartner, Keys(..),
	ContType(..), Alert(..), AlertLevel(..), AlertDesc(..),
	CipherSuite(..), BulkEnc(..),
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
import qualified Network.PeyoTLS.Crypto as C (
	makeKeys, encrypt, decrypt, sha1, sha256, Side(..), finishedHash )

modNm :: String
modNm = "Network.PeyoTLS.Monad"

vrsn :: BS.ByteString
vrsn = "\3\3"

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
tGet h n = do
	b <- lift . lift $ hlGet h n
	unless (BS.length b == n) . throw S.ALFtl S.ADUnk $
		modNm ++ ".tGet: read err " ++ show (BS.length b) ++ " " ++ show n
	return b

tPut :: HandleLike h => h -> BS.ByteString -> TlsM h g ()
tPut = ((lift . lift) .) . hlPut

tClose :: HandleLike h => h -> TlsM h g ()
tClose = lift . lift . hlClose

tDebug :: HandleLike h => h -> DebugLevel h -> BS.ByteString -> TlsM h gen ()
tDebug = (((lift . lift) .) .) . hlDebug

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

rstSn :: HandleLike h => S.PartnerId -> RW -> TlsM h g ()
rstSn i rw = case rw of Read -> rstRSn i; Write -> rstWSn i

getSn :: HandleLike h => S.PartnerId -> RW -> TlsM h g Word64
getSn i rw = case rw of Read -> getRSn i; Write -> getWSn i

sccSn :: HandleLike h => S.PartnerId -> RW -> TlsM h g ()
sccSn i rw = case rw of Read -> sccRSn i; Write -> sccWSn i

throw :: HandleLike h => S.AlertLevel -> S.AlertDesc -> String -> TlsM h g a
throw = ((throwError .) .) . S.Alert

udSn :: HandleLike h => S.PartnerId -> RW -> TlsM h g Word64
udSn i rw = do
	ks <- getKeys i
	sn <- getSn i rw
	let cs = ($ ks) $ case rw of Read -> S.kReadCS; Write -> S.kWriteCS
	case cs of
		S.CipherSuite _ S.BE_NULL -> return ()
		_ -> sccSn i rw
	return sn

encrypt :: (HandleLike h, CPRG g) =>
	S.PartnerId -> S.ContType -> BS.ByteString -> TlsM h g BS.ByteString
encrypt i ct p = do
	ks <- getKeys i
	let	S.CipherSuite _ be = S.kWriteCS ks
		wk = S.kWriteKey ks
		mk = S.kWriteMacKey ks
	sn <- udSn i Write
	case be of
		S.AES_128_CBC_SHA -> withRandom $
			C.encrypt C.sha1 wk mk sn (B.encode ct `BS.append` vrsn) p
		S.AES_128_CBC_SHA256 -> withRandom $
			C.encrypt C.sha256 wk mk sn (B.encode ct `BS.append` vrsn) p
		S.BE_NULL -> return p

decrypt :: HandleLike h =>
	S.PartnerId -> S.ContType -> BS.ByteString -> TlsM h g BS.ByteString
decrypt i ct e = do
	ks <- getKeys i
	let	S.CipherSuite _ be = S.kReadCS ks
		wk = S.kReadKey ks
		mk = S.kReadMacKey ks
	sn <- udSn i Read
	case be of
		S.AES_128_CBC_SHA -> either (throw S.ALFtl S.ADUnk) return $
			C.decrypt C.sha1 wk mk sn (B.encode ct `BS.append` vrsn) e
		S.AES_128_CBC_SHA256 -> either (throw S.ALFtl S.ADUnk) return $
			C.decrypt C.sha256 wk mk sn (B.encode ct `BS.append` vrsn) e
		S.BE_NULL -> return e

makeKeys :: HandleLike h => S.PartnerId -> C.Side ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> S.CipherSuite ->
	TlsM h g S.Keys
makeKeys t p cr sr pms cs@(S.CipherSuite _ be) = do
	kl <- case be of
		S.AES_128_CBC_SHA -> return $ snd C.sha1
		S.AES_128_CBC_SHA256 -> return $ snd C.sha256
		_ -> throw S.ALFtl S.ADUnk $ modNm ++ ".makeKeys: no bulk enc"
	let (ms, cwmk, swmk, cwk, swk) = C.makeKeys kl cr sr pms
	k <- getKeys t
	return $ case p of
		C.Client -> k {
			S.kCachedCS = cs, S.kMasterSecret = ms,
			S.kCachedReadMacKey = swmk, S.kCachedWriteMacKey = cwmk,
			S.kCachedReadKey = swk, S.kCachedWriteKey = cwk }
		C.Server -> k {
			S.kCachedCS = cs, S.kMasterSecret = ms,
			S.kCachedReadMacKey = cwmk, S.kCachedWriteMacKey = swmk,
			S.kCachedReadKey = cwk, S.kCachedWriteKey = swk }
makeKeys _ _ _ _ _ _ = throw S.ALFtl S.ADUnk $ modNm ++ ".makeKeys"

finishedHash :: HandleLike h =>
	C.Side -> S.PartnerId -> BS.ByteString -> TlsM h g BS.ByteString
finishedHash s t hs =
	flip (C.finishedHash s) hs `liftM` S.kMasterSecret `liftM` getKeys t
