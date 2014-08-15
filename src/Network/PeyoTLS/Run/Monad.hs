{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Network.PeyoTLS.Run.Monad (
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
import Control.Monad (unless, liftM, ap)
import "monads-tf" Control.Monad.State (lift, StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT, throwError)
import "monads-tf" Control.Monad.Error.Class (Error(..))
import Data.Word (Word8, Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

import qualified Network.PeyoTLS.Run.State as S (
	TlsState, initState, PartnerId, newPartner,
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
import qualified Network.PeyoTLS.Run.Crypto as C (
	makeKeys, encrypt, decrypt, sha1, sha256, Side(..), finishedHash )

modNm :: String
modNm = "Network.PeyoTLS.Monad"

vrsn :: BS.ByteString
vrsn = "\3\3"

type TlsM h g = ErrorT Alert (StateT (S.TlsState h g) (HandleMonad h))

run :: HandleLike h => TlsM h g a -> g -> HandleMonad h a
run m g = evalStateT (runErrorT m) (S.initState g) >>= \er -> case er of
		Right r -> return r
		Left a -> error $ show a

throw :: HandleLike h => AlertLevel -> AlertDesc -> String -> TlsM h g a
throw = ((throwError .) .) . Alert

data Alert
	= Alert AlertLevel AlertDesc String
	| ExternalAlert String
	| NotDetected String deriving Show

data AlertLevel = ALWarning | ALFtl | ALRaw Word8 deriving Show

data AlertDesc
	= ADCloseNotify | ADUnexMsg   | ADBadRecMac  | ADRecOverflow | ADDecFail
	| ADHsFailure   | ADUnsCert   | ADCertEx     | ADCertUnk     | ADIllParam
	| ADUnkCa       | ADDecodeErr | ADDecryptErr | ADProtoVer    | ADInsSec
	| ADInternalErr | ADUnk       | ADRaw Word8
	deriving Show

instance Error Alert where strMsg = NotDetected

withRandom :: HandleLike h => (gen -> (a, gen)) -> TlsM h gen a
withRandom p = p `liftM` gets S.getGen >>=
	uncurry (flip (>>)) . (return *** modify . S.setGen)

tGet :: HandleLike h => h -> Int -> TlsM h g BS.ByteString
tGet h n = lift (lift $ hlGet h n) >>= \b -> do
	unless (BS.length b == n) . throw ALFtl ADUnk $
		modNm ++ ".tGet: read err " ++ show (BS.length b) ++ " " ++ show n
	return b

decrypt :: HandleLike h =>
	S.PartnerId -> S.ContType -> BS.ByteString -> TlsM h g BS.ByteString
decrypt i ct e = do
	ks <- getKeys i
	let	S.CipherSuite _ be = S.kRCSuite ks;
		wk = S.kRKey ks; mk = S.kRMKey ks
	sn <- udSn S.Read i
	case be of
		S.AES_128_CBC_SHA -> either (throw ALFtl ADUnk) return $
			C.decrypt C.sha1 wk mk sn (B.encode ct `BS.append` vrsn) e
		S.AES_128_CBC_SHA256 -> either (throw ALFtl ADUnk) return $
			C.decrypt C.sha256 wk mk sn (B.encode ct `BS.append` vrsn) e
		S.BE_NULL -> return e

tPut :: HandleLike h => h -> BS.ByteString -> TlsM h g ()
tPut = ((lift . lift) .) . hlPut

encrypt :: (HandleLike h, CPRG g) =>
	S.PartnerId -> S.ContType -> BS.ByteString -> TlsM h g BS.ByteString
encrypt i ct p = do
	ks <- getKeys i
	let	S.CipherSuite _ be = S.kWCSuite ks
		wk = S.kWKey ks; mk = S.kWMKey ks
	sn <- udSn S.Write i
	case be of
		S.AES_128_CBC_SHA -> withRandom $
			C.encrypt C.sha1 wk mk sn (B.encode ct `BS.append` vrsn) p
		S.AES_128_CBC_SHA256 -> withRandom $
			C.encrypt C.sha256 wk mk sn (B.encode ct `BS.append` vrsn) p
		S.BE_NULL -> return p

tClose :: HandleLike h => h -> TlsM h g ()
tClose = lift . lift . hlClose

tDebug :: HandleLike h => h -> DebugLevel h -> BS.ByteString -> TlsM h gen ()
tDebug = (((lift . lift) .) .) . hlDebug

getRBuf, getWBuf ::  HandleLike h =>
	S.PartnerId -> TlsM h g (S.ContType, BS.ByteString)
getRBuf = gets . S.getRBuf; getWBuf = gets . S.getWBuf

getAdBuf :: HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getAdBuf = gets . S.getAdBuf

setRBuf, setWBuf :: HandleLike h =>
	S.PartnerId -> (S.ContType, BS.ByteString) -> TlsM h g ()
setRBuf = (modify .) . S.setRBuf; setWBuf = (modify .) . S.setWBuf

setAdBuf :: HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setAdBuf = (modify .) . S.setAdBuf

udSn :: HandleLike h => S.RW -> S.PartnerId -> TlsM h g Word64
udSn rw i = case rw of
	S.Read -> const `liftM` gets (S.getRSn i) `ap` modify (S.sccRSn i)
	S.Write -> const `liftM` gets (S.getWSn i) `ap` modify (S.sccWSn i)

rstSn :: HandleLike h => S.RW -> S.PartnerId -> TlsM h g ()
rstSn rw = case rw of S.Read -> modify . S.rstRSn; S.Write -> modify . S.rstWSn

getClFinished, getSvFinished ::
	HandleLike h => S.PartnerId -> TlsM h g BS.ByteString
getClFinished = gets . S.getClFinished
getSvFinished = gets . S.getSvFinished

setClFinished, setSvFinished ::
	HandleLike h => S.PartnerId -> BS.ByteString -> TlsM h g ()
setClFinished = (modify .) . S.setClFinished
setSvFinished = (modify .) . S.setSvFinished

getNames :: HandleLike h => S.PartnerId -> TlsM h g [String]
getNames = gets . S.getNames

setNames :: HandleLike h => S.PartnerId -> [String] -> TlsM h g ()
setNames = (modify .) . S.setNames

getSettingsC :: HandleLike h => S.PartnerId -> TlsM h g S.SettingsC
getSettingsC i = gets (S.getSettingsC i ) >>= maybe (throw ALFtl ADUnk "...") return

getSettingsS :: HandleLike h => S.PartnerId -> TlsM h g S.SettingsS
getSettingsS = gets . S.getSettingsS

setSettingsC :: HandleLike h => S.PartnerId -> S.SettingsC -> TlsM h g ()
setSettingsC = (modify .) . S.setSettingsC

setSettingsS :: HandleLike h => S.PartnerId -> S.SettingsS -> TlsM h g ()
setSettingsS = (modify .) . S.setSettingsS

getCipherSuite :: HandleLike h => S.PartnerId -> TlsM h g S.CipherSuite
getCipherSuite = gets . S.getCipherSuite

setCipherSuite :: HandleLike h => S.PartnerId -> S.CipherSuite -> TlsM h g ()
setCipherSuite = (modify .) . S.setCipherSuite

flushCipherSuite :: HandleLike h => S.RW -> S.PartnerId -> TlsM h g ()
flushCipherSuite = (modify .) . S.flushCipherSuite

makeKeys :: HandleLike h => C.Side -> S.PartnerId ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> S.CipherSuite ->
	TlsM h g S.Keys
makeKeys s t cr sr pms cs@(S.CipherSuite _ be) = do
	kl <- case be of
		S.AES_128_CBC_SHA -> return $ snd C.sha1
		S.AES_128_CBC_SHA256 -> return $ snd C.sha256
		_ -> throw ALFtl ADUnk $ modNm ++ ".makeKeys: bad bulk enc"
	let (ms, cwmk, swmk, cwk, swk) = C.makeKeys kl cr sr pms
	getKeys t >>= \k -> return $ case s of
		C.Client -> k {
			S.kCchCSuite = cs, S.kMSec = ms,
			S.kCchRMKey = swmk, S.kCchWMKey = cwmk,
			S.kCchRKey = swk, S.kCchWKey = cwk }
		C.Server -> k {
			S.kCchCSuite = cs, S.kMSec = ms,
			S.kCchRMKey = cwmk, S.kCchWMKey = swmk,
			S.kCchRKey = cwk, S.kCchWKey = swk }
makeKeys _ _ _ _ _ _ = throw ALFtl ADUnk $ modNm ++ ".makeKeys"

getKeys :: HandleLike h => S.PartnerId -> TlsM h g S.Keys
getKeys = gets . S.getKeys

setKeys :: HandleLike h => S.PartnerId -> S.Keys -> TlsM h g ()
setKeys = (modify .) . S.setKeys

finishedHash :: HandleLike h =>
	C.Side -> S.PartnerId -> BS.ByteString -> TlsM h g BS.ByteString
finishedHash s t hs = C.finishedHash s hs `liftM` S.kMSec `liftM` getKeys t
