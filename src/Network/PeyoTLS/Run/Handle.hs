{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

module Network.PeyoTLS.Run.Handle ( debug,
	M.TlsState(..), M.State1(..), wFlush, M.Keys(..),
	M.TlsM, M.run, M.run', M.withRandom,
	HandleBase, M.CipherSuite,
		newHandle, chGet, ccsPut, hsPut,
		adGet, adGetLine, splitLine, adGetContent, adPut, adDebug, adClose,
		flushAd, getBuf, setBuf,
		getCipherSuite, setCipherSuite,
		M.SettingsC, getSettingsC, setSettingsC,
		M.SettingsS, getSettingsS, setSettingsS,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		getNames, setNames, getCertificate, setCertificate,
		makeKeys, setKeys,
		M.Side(..), finishedHash,
		M.RW(..), flushCipherSuite,
	ValidateHandle(..), tValidate,
	M.CertSecretKey(..), M.isRsaKey, M.isEcdsaKey,
	M.Alert(..), M.AlertLevel(..), M.AlertDesc(..), debugCipherSuite ) where

import Control.Arrow (first, second)
import Control.Monad (when, unless, liftM, ap)
import "monads-tf" Control.Monad.State (lift, get, put)
import Data.Word (Word8, Word16)
import Data.HandleLike (HandleLike(..), DebugHandle(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B

import qualified Network.PeyoTLS.Run.Monad as M (
	TlsState(..), State1(..),
	TlsM, run, run', throw, withRandom,
		Alert(..), AlertLevel(..), AlertDesc(..),
		tGet, decrypt, tPut, encrypt, tClose, tDebug,
	PartnerId, newPartner, ContType(..),
		getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf, rstSn,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		getNames, setNames, getCertificate, setCertificate,
	CipherSuite(..), CertSecretKey(..), isRsaKey, isEcdsaKey,
		SettingsC, getSettingsC, setSettingsC,
		SettingsS, getSettingsS, setSettingsS,
		RW(..), getCipherSuite, setCipherSuite, flushCipherSuite,
	Keys(..), makeKeys, getKeys, setKeys,
	Side(..), finishedHash )

modNm :: String
modNm = "Network.PeyoTLS.Handle"

vrsn :: BS.ByteString
vrsn = "\x03\x03"

data HandleBase h g = Handle { pid :: M.PartnerId, handle :: h } deriving Show

newHandle :: HandleLike h => h -> M.TlsM h g (HandleBase h g)
newHandle h = M.newPartner `liftM` get >>= \(i, s) ->
	put s >> return Handle { pid = i, handle = h }

chGet :: (HandleLike h, CPRG g) =>
	HandleBase h g -> Int -> M.TlsM h g (Either Word8 BS.ByteString)
chGet _ 0 = return $ Right ""
chGet h n = getType h >>= \ct -> case ct of
	M.CTCCSpec -> (Left . head . BS.unpack) `liftM`
		(const `liftM` tRead h 1 `ap` M.rstSn M.Read (pid h))
	M.CTHandshake -> Right `liftM` tRead h n
	M.CTAlert -> M.throw M.ALFtl M.ADUnk
		. ((modNm ++ ".chGet: ") ++) . show =<< tRead h 2
	_ -> M.throw M.ALFtl M.ADUnk $ modNm ++ ".chGet: not handshake"

tRead :: (HandleLike h, CPRG g) => HandleBase h g -> Int -> M.TlsM h g BS.ByteString
tRead h n = do
	(ct, b) <- M.getRBuf $ pid h; let n' = n - BS.length b
	if n' <= 0
	then cut h n ct b
	else do	(ct', b') <- getCont h
		unless (ct' == ct) . M.throw M.ALFtl M.ADUnk $
			modNm ++ ".tRead: content type confliction\n"
		when (BS.null b') . M.throw M.ALFtl M.ADUnk  $
			modNm ++ ".tRead: no data available\n"
		M.setRBuf (pid h) (ct', b')
		(b `BS.append`) `liftM` tRead h n'

cut :: HandleLike h => HandleBase h g ->
	Int -> M.ContType -> BS.ByteString -> M.TlsM h g BS.ByteString
cut h n ct b = (const r `liftM`) . M.setRBuf (pid h) $
	(if BS.null b' then M.CTNull else ct, b')
	where (r, b') = BS.splitAt n b

ccsPut :: (HandleLike h, CPRG g) => HandleBase h g -> Word8 -> M.TlsM h g ()
ccsPut t w =
	const `liftM` tWrite t M.CTCCSpec (BS.pack [w]) `ap` M.rstSn M.Write (pid t)

hsPut :: (HandleLike h, CPRG g) => HandleBase h g -> BS.ByteString -> M.TlsM h g ()
hsPut = flip tWrite M.CTHandshake

adGet :: (HandleLike h, CPRG g) => (HandleBase h g -> M.TlsM h g ()) ->
	HandleBase h g -> Int -> M.TlsM h g BS.ByteString
adGet rp h n = getType h >>= \ct -> case ct of
	M.CTAppData -> tRead h n
	M.CTHandshake -> rp h >> adGet rp h n
	M.CTAlert -> tRead h 2 >>= \al -> case al of
		"\SOH\NUL" -> tWrite h M.CTAlert "\SOH\NUL" >>
			M.throw M.ALFtl M.ADUnk "EOF"
		_ -> M.throw M.ALFtl M.ADUnk $ "Alert: " ++ show al
	_ -> M.throw M.ALFtl M.ADUnk $ modNm ++ ".adGet"

adGetLine :: (HandleLike h, CPRG g) => (HandleBase h g -> M.TlsM h g ()) ->
	HandleBase h g -> M.TlsM h g BS.ByteString
adGetLine rp h = getType h >>= \ct -> case ct of
	M.CTAppData -> M.getRBuf (pid h) >>= \(bct, bbs) -> case splitLine bbs of
		Just (l, ls) -> do
			M.setRBuf (pid h) (if BS.null ls then M.CTNull else bct, ls)
			return l
		_ -> do	getCont h >>= M.setRBuf (pid h)
			(bbs `BS.append`) `liftM` adGetLine rp h
	M.CTHandshake -> rp h >> adGetLine rp h
	M.CTAlert -> tRead h 2 >>= \al -> case al of
		"\SOH\NUL" -> tWrite h M.CTAlert "\SOH\NUL" >>
			M.throw M.ALFtl M.ADUnk "EOF"
		_ -> M.throw M.ALFtl M.ADUnk $ "Alert: " ++ show al
	_ -> M.throw M.ALFtl M.ADUnk $ modNm ++ ".adGetLine"

splitLine :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
splitLine bs = case ('\r' `BSC.elem` bs, '\n' `BSC.elem` bs) of
	(True, _) -> case BSC.uncons rls of
		Just ('\n', rnls) -> Just (rl, rnls)
		_ -> Just (rl, rls)
	(_, True) -> Just (nl, nls)
	_ -> Nothing
	where
	(rl, Just ('\r', rls)) = second BSC.uncons $ BSC.span (/= '\r') bs
	(nl, Just ('\n', nls)) = second BSC.uncons $ BSC.span (/= '\n') bs

adGetContent :: (HandleLike h, CPRG g) => (HandleBase h g -> M.TlsM h g ()) ->
	HandleBase h g -> M.TlsM h g BS.ByteString
adGetContent rp h = getType h >>= \ct -> case ct of
	M.CTAppData -> bCont h
	M.CTHandshake -> rp h >> adGetContent rp h
	M.CTAlert -> tRead h 2 >>= \al -> case al of
		"\SOH\NUL" -> do
			tWrite h M.CTAlert "\SOH\NUL"
			M.throw M.ALFtl M.ADUnk $ modNm ++ ".adGetContent"
		_ -> M.throw M.ALFtl M.ADUnk $ modNm ++ ".adGetcontent"
	_ -> M.throw M.ALFtl M.ADUnk $ modNm ++ ".adGetContent"

bCont :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g BS.ByteString
bCont h = snd `liftM` M.getRBuf (pid h) >>= \bp -> if BS.null bp
	then snd `liftM` getCont h
	else M.setRBuf (pid h) (M.CTNull, BS.empty) >> return bp

adPut :: (HandleLike h, CPRG g) =>
	HandleBase h g -> BS.ByteString -> M.TlsM h g ()
adPut = flip tWrite M.CTAppData

adDebug :: HandleLike h =>
	HandleBase h g -> DebugLevel h -> BS.ByteString -> M.TlsM h g ()
adDebug = M.tDebug . handle

adClose :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g ()
adClose t = tWrite t M.CTAlert "\SOH\NUL" >> wFlush t >> M.tClose (handle t)

flushAd :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.TlsM h g (BS.ByteString, Bool)
flushAd t = getType t >>= \ct -> case ct of
	M.CTAppData -> bCont t >>= \ad -> first (ad `BS.append`) `liftM` flushAd t
	M.CTAlert -> tRead t 2 >>= \a -> case a of
		"\1\0" -> return ("", False)
		_ -> M.throw M.ALFtl M.ADUnk $ modNm ++ ".flushAd: " ++ show a
	_ -> return ("", True)

getBuf :: HandleLike h => HandleBase h g -> M.TlsM h g BS.ByteString
getBuf = M.getAdBuf . pid

setBuf :: HandleLike h => HandleBase h g -> BS.ByteString -> M.TlsM h g ()
setBuf = M.setAdBuf . pid

getType :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g M.ContType
getType h = M.getRBuf (pid h) >>= \(t, b) ->
	(\p -> case (t, b) of (M.CTNull, _) -> p; (_, "") -> p; _ -> return t) $ do
		c@(t', _) <- getCont h
		M.setRBuf (pid h) c >> return t'

getCont :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.TlsM h g (M.ContType, BS.ByteString)
getCont h = do
	wFlush h
	ct <- (either (M.throw M.ALFtl M.ADUnk) return . B.decode) =<< rd 1
	_v <- rd 2
	e <- rd =<< either (M.throw M.ALFtl M.ADUnk) return . B.decode =<< rd 2
	(ct ,) `liftM` M.decrypt (pid h) ct e
	where rd = M.tGet $ handle h

tWrite :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.ContType -> BS.ByteString -> M.TlsM h g ()
tWrite h ct p = do
	(bct, bp) <- M.getWBuf $ pid h
	case ct of
		M.CTCCSpec -> wFlush h >> M.setWBuf (pid h) (ct, p) >> wFlush h
		_	| bct /= M.CTNull && ct /= bct ->
				wFlush h >> M.setWBuf (pid h) (ct, p)
			| otherwise -> M.setWBuf (pid h) (ct, bp `BS.append` p)

wFlush :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g ()
wFlush h = M.getWBuf (pid h) >>= \(bct, bp) -> do
	M.setWBuf (pid h) (M.CTNull, "")
	unless (bct == M.CTNull)
		. mapM_ (encryptPut h bct) $ divide (2 ^ (14 :: Int)) bp
	{-
	unless (bct == M.CTNull) $ M.encrypt (pid h) bct bp >>= \e ->
		M.tPut (handle h) $ BS.concat
			[B.encode bct, vrsn, B.addLen (undefined :: Word16) e]
			-}

encryptPut :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.ContType -> BS.ByteString -> M.TlsM h g ()
encryptPut h bct bp = M.encrypt (pid h) bct bp >>= \e -> M.tPut (handle h) $
	BS.concat [B.encode bct, vrsn, B.addLen (undefined :: Word16) e]

divide :: Int -> BS.ByteString -> [BS.ByteString]
divide _ "" = []
divide n s = BS.take n s : divide n (BS.drop n s)

getCipherSuite :: HandleLike h => HandleBase h g -> M.TlsM h g M.CipherSuite
getCipherSuite = M.getCipherSuite . pid

setCipherSuite :: HandleLike h => HandleBase h g -> M.CipherSuite -> M.TlsM h g ()
setCipherSuite = M.setCipherSuite . pid

getSettingsC :: HandleLike h => HandleBase h g -> M.TlsM h g M.SettingsC
getSettingsC = M.getSettingsC . pid

setSettingsC :: HandleLike h => HandleBase h g -> M.SettingsC -> M.TlsM h g ()
setSettingsC = M.setSettingsC . pid

getSettingsS :: HandleLike h => HandleBase h g -> M.TlsM h g M.SettingsS
getSettingsS = M.getSettingsS . pid

setSettingsS :: HandleLike h => HandleBase h g -> M.SettingsS -> M.TlsM h g ()
setSettingsS = M.setSettingsS . pid

getClFinished, getSvFinished ::
	HandleLike h => HandleBase h g -> M.TlsM h g BS.ByteString
getClFinished = M.getClFinished . pid
getSvFinished = M.getSvFinished . pid

setClFinished, setSvFinished ::
	HandleLike h => HandleBase h g -> BS.ByteString -> M.TlsM h g ()
setClFinished = M.setClFinished . pid
setSvFinished = M.setSvFinished . pid

getNames :: HandleLike h => HandleBase h g -> M.TlsM h g [String]
getNames = M.getNames . pid

setNames :: HandleLike h => HandleBase h g -> [String] -> M.TlsM h g ()
setNames = M.setNames . pid

getCertificate :: HandleLike h =>
	HandleBase h g -> M.TlsM h g (Maybe X509.SignedCertificate)
getCertificate = M.getCertificate . pid

setCertificate :: HandleLike h =>
	HandleBase h g -> X509.SignedCertificate -> M.TlsM h g ()
setCertificate = M.setCertificate . pid

makeKeys :: HandleLike h => HandleBase h g -> M.Side ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> M.CipherSuite ->
	M.TlsM h g M.Keys
makeKeys = flip M.makeKeys . pid

setKeys :: HandleLike h => HandleBase h g -> M.Keys -> M.TlsM h g ()
setKeys = M.setKeys . pid

flushCipherSuite :: HandleLike h => M.RW -> HandleBase h g -> M.TlsM h g ()
flushCipherSuite rw = M.flushCipherSuite rw . pid

finishedHash :: HandleLike h =>
	M.Side -> HandleBase h g -> BS.ByteString -> M.TlsM h g BS.ByteString
finishedHash s = M.finishedHash s . pid

debug :: (HandleLike h, Show a) =>
	HandleBase h g -> DebugLevel h -> a -> M.TlsM h g ()
debug t l x = lift . lift . hlDebug (handle t) l . BSC.pack . (++ "\n") $ show x

class HandleLike h => ValidateHandle h where
	validate :: h -> X509.CertificateStore -> X509.CertificateChain ->
		HandleMonad h [X509.FailedReason]

tValidate :: ValidateHandle h => HandleBase h g -> X509.CertificateStore ->
	X509.CertificateChain -> M.TlsM h g [X509.FailedReason]
tValidate = (((lift . lift) .) .) . validate . handle

instance ValidateHandle Handle where
	validate _ cs =
		X509.validate X509.HashSHA256 X509.defaultHooks ch cs ca ("", "")
		where
		ch = X509.defaultChecks { X509.checkFQHN = False }
		ca = X509.ValidationCache
			(\_ _ _ -> return X509.ValidationCacheUnknown)
			(\_ _ _ -> return ())

instance ValidateHandle h => ValidateHandle (DebugHandle h) where
	validate (DebugHandle h _) = validate h

debugCipherSuite :: HandleLike h => HandleBase h g -> String -> M.TlsM h g ()
debugCipherSuite h a = do
	k <- M.getKeys $ pid h
	M.tDebug (handle h) "high" . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show $ M.kCchCSuite k
	where lenSpace n str = str ++ replicate (n - length str) ' '
