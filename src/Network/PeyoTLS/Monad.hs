{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Network.PeyoTLS.Monad (
	TlsM, run, throw, withRandom,
		Alert(..), AlertLevel(..), AlertDesc(..),
		tGet, decrypt, tPut, encrypt, tClose, tDebug,
	S.PartnerId, S.newPartner, S.ContType(..),
		getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf, rstSn,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		getNames, setNames,
	S.CipherSuite(..), S.CertSecretKey(..), S.isRsaKey, S.isEcdsaKey,
		S.SettingsC, getSettingsC, setSettingsC,
		S.SettingsS, getSettingsS, setSettingsS,
		S.RW(..), getCipherSuite, setCipherSuite, flushCipherSuite,
	S.Keys(..), makeKeys, getKeys, setKeys,
	C.Side(..), finishedHash ) where

import Control.Arrow ((***))
import Control.Monad (unless, liftM)
import "monads-tf" Control.Monad.State (lift, StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT, throwError, catchError)
import "monads-tf" Control.Monad.Error.Class (Error(..))
import Data.Word (Word8, Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

import qualified Network.PeyoTLS.State as S (
	HandshakeState, initState, PartnerId, newPartner,
		getGen, setGen, getNames, setNames,
		getRSn, getWSn, rstRSn, rstWSn, sccRSn, sccWSn,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
	ContType(..), getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf,
	CipherSuite(..), BulkEnc(..), RW(..),
		getCipherSuite, setCipherSuite, flushCipherSuite,
	Keys(..), getKeys, setKeys,
	SettingsC, getSettingsC, setSettingsC,
	SettingsS, getSettingsS, setSettingsS,
	CertSecretKey(..), isRsaKey, isEcdsaKey )
import qualified Network.PeyoTLS.Crypto as C (
	makeKeys, encrypt, decrypt, sha1, sha256, Side(..), finishedHash )

modNm :: String
modNm = "Network.PeyoTLS.Monad"

vrsn :: BS.ByteString
vrsn = "\3\3"

type TlsM h g = ErrorT Alert (StateT (S.HandshakeState h g) (HandleMonad h))

run :: HandleLike h => TlsM h g a -> g -> HandleMonad h a
run m g = do
	ret <- (`evalTlsM` S.initState g) $ m `catchError` \a -> throwError a
	case ret of
		Right r -> return r
		Left a -> error $ show a

evalTlsM :: HandleLike h => 
	TlsM h g a -> S.HandshakeState h g -> HandleMonad h (Either Alert a)
evalTlsM = evalStateT . runErrorT

getRBuf, getWBuf ::  HandleLike h =>
	S.PartnerId -> TlsM h g (S.ContType, BS.ByteString)
getRBuf = gets . S.getRBuf; getWBuf = gets . S.getWBuf

getAdBuf :: HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getAdBuf = gets . S.getAdBuf

setAdBuf :: HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setAdBuf = (modify .) . S.setAdBuf

setRBuf, setWBuf :: HandleLike h =>
	S.PartnerId -> (S.ContType, BS.ByteString) -> TlsM h g ()
setRBuf = (modify .) . S.setRBuf; setWBuf = (modify .) . S.setWBuf

getWSn, getRSn :: HandleLike h => S.PartnerId -> TlsM h g Word64
getWSn = gets . S.getWSn; getRSn = gets . S.getRSn

sccWSn, sccRSn :: HandleLike h => S.PartnerId -> TlsM h g ()
sccWSn = modify . S.sccWSn; sccRSn = modify . S.sccRSn

rstWSn, rstRSn :: HandleLike h => S.PartnerId -> TlsM h g ()
rstWSn = modify . S.rstWSn; rstRSn = modify . S.rstRSn

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
getSettingsS = gets . S.getSettingsS

getSettingsC :: HandleLike h => S.PartnerId -> TlsM h g S.SettingsC
getSettingsC i = gets (S.getSettingsC i ) >>= maybe (throw ALFtl ADUnk "...") return

setSettingsS :: HandleLike h => S.PartnerId -> S.SettingsS -> TlsM h g ()
setSettingsS = (modify .) . S.setSettingsS

setSettingsC :: HandleLike h => S.PartnerId -> S.SettingsC -> TlsM h g ()
setSettingsC = (modify .) . S.setSettingsC
-- setSettingsC i (css, crts, cs) = modify $ S.setSettings i (css, crts, Just cs)

getClFinished, getSvFinished ::
	HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getClFinished = gets . S.getClFinished
getSvFinished = gets . S.getSvFinished

setClFinished, setSvFinished ::
	HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setClFinished = (modify .) . S.setClFinished
setSvFinished = (modify .) . S.setSvFinished

flushCipherSuite :: HandleLike h => S.RW -> S.PartnerId -> TlsM h g ()
flushCipherSuite = (modify .) . S.flushCipherSuite

withRandom :: HandleLike h => (gen -> (a, gen)) -> TlsM h gen a
withRandom p = p `liftM` gets S.getGen >>=
	uncurry (flip (>>)) . (return *** modify . S.setGen)

tGet :: HandleLike h => h -> Int -> TlsM h g BS.ByteString
tGet h n = do
	b <- lift . lift $ hlGet h n
	unless (BS.length b == n) . throw ALFtl ADUnk $
		modNm ++ ".tGet: read err " ++ show (BS.length b) ++ " " ++ show n
	return b

tPut :: HandleLike h => h -> BS.ByteString -> TlsM h g ()
tPut = ((lift . lift) .) . hlPut

tClose :: HandleLike h => h -> TlsM h g ()
tClose = lift . lift . hlClose

tDebug :: HandleLike h => h -> DebugLevel h -> BS.ByteString -> TlsM h gen ()
tDebug = (((lift . lift) .) .) . hlDebug

rstSn :: HandleLike h => S.PartnerId -> S.RW -> TlsM h g ()
rstSn i rw = case rw of S.Read -> rstRSn i; S.Write -> rstWSn i

getSn :: HandleLike h => S.PartnerId -> S.RW -> TlsM h g Word64
getSn i rw = case rw of S.Read -> getRSn i; S.Write -> getWSn i

sccSn :: HandleLike h => S.PartnerId -> S.RW -> TlsM h g ()
sccSn i rw = case rw of S.Read -> sccRSn i; S.Write -> sccWSn i

throw :: HandleLike h => AlertLevel -> AlertDesc -> String -> TlsM h g a
throw = ((throwError .) .) . Alert

udSn :: HandleLike h => S.PartnerId -> S.RW -> TlsM h g Word64
udSn i rw = do
	ks <- getKeys i
	sn <- getSn i rw
	let cs = ($ ks) $ case rw of S.Read -> S.kReadCS; S.Write -> S.kWriteCS
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
	sn <- udSn i S.Write
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
	sn <- udSn i S.Read
	case be of
		S.AES_128_CBC_SHA -> either (throw ALFtl ADUnk) return $
			C.decrypt C.sha1 wk mk sn (B.encode ct `BS.append` vrsn) e
		S.AES_128_CBC_SHA256 -> either (throw ALFtl ADUnk) return $
			C.decrypt C.sha256 wk mk sn (B.encode ct `BS.append` vrsn) e
		S.BE_NULL -> return e

makeKeys :: HandleLike h => S.PartnerId -> C.Side ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> S.CipherSuite ->
	TlsM h g S.Keys
makeKeys t p cr sr pms cs@(S.CipherSuite _ be) = do
	kl <- case be of
		S.AES_128_CBC_SHA -> return $ snd C.sha1
		S.AES_128_CBC_SHA256 -> return $ snd C.sha256
		_ -> throw ALFtl ADUnk $ modNm ++ ".makeKeys: no bulk enc"
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
makeKeys _ _ _ _ _ _ = throw ALFtl ADUnk $ modNm ++ ".makeKeys"

finishedHash :: HandleLike h =>
	C.Side -> S.PartnerId -> BS.ByteString -> TlsM h g BS.ByteString
finishedHash s t hs =
	flip (C.finishedHash s) hs `liftM` S.kMasterSecret `liftM` getKeys t

data Alert = Alert AlertLevel AlertDesc String | NotDetected String
	deriving Show

data AlertLevel = ALWarning | ALFtl | ALRaw Word8 deriving Show

data AlertDesc
	= ADCloseNotify            | ADUnexMsg              | ADBadRecordMac
	| ADRecordOverflow         | ADDecompressionFailure | ADHsFailure
	| ADUnsupportedCertificate | ADCertificateExpired   | ADCertificateUnknown
	| ADIllegalParameter       | ADUnknownCa            | ADDecodeError
	| ADDecryptError           | ADProtocolVersion      | ADInsufficientSecurity
	| ADInternalError          | ADUnk
	| ADRaw Word8
	deriving Show

instance Error Alert where strMsg = NotDetected
