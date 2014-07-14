{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

module Network.PeyoTLS.Handle ( debug,
	M.TlsM, M.run, M.withRandom,
	HandleBase, M.CipherSuite,
		newHandle, chGet, ccsPut, hsPut,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
		flushAd, getBuf, setBuf,
		getCipherSuite, setCipherSuite,
		M.SettingsC, getSettingsC, setSettingsC,
		M.SettingsS, getSettingsS, setSettingsS,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		makeKeys, setKeys,
		getNames, setNames,
		C.Side(..), finishedHash,
		M.RW(..), flushCipherSuite,
	ValidateHandle(..), tValidate,
	M.CertSecretKey(..), M.isRsaKey, M.isEcdsaKey,
	M.Alert(..), M.AlertLevel(..), M.AlertDesc(..), debugCipherSuite,
	splitLine ) where

import Control.Arrow (second)
import Control.Monad (when, unless, liftM, ap)
import "monads-tf" Control.Monad.State (lift, get, put)
import "monads-tf" Control.Monad.Error (throwError)
import Data.Word (Word8, Word16, Word64)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B

import qualified Network.PeyoTLS.Monad as M (
	TlsM, run, withRandom,
		Alert(..), AlertLevel(..), AlertDesc(..),
		tGet, tPut, tClose, tDebug,
	PartnerId, newPartner, ContType(..),
		getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf,
		getSn, sccSn, rstSn,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		getNames, setNames,
	CipherSuite(..), BulkEnc(..), CertSecretKey(..), isRsaKey, isEcdsaKey,
		SettingsC, getSettingsC, setSettingsC,
		SettingsS, getSettingsS, setSettingsS,
		RW(..), getCipherSuite, setCipherSuite, flushCipherSuite,
	Keys(..), getKeys, setKeys )
import qualified Network.PeyoTLS.Crypto as C (
	makeKeys, encrypt, decrypt, hashSha1, hashSha256, Side(..), finishedHash )

modNm :: String
modNm = "Network.PeyoTLS.Handle"

data HandleBase h g = Handle { pid :: M.PartnerId, handle :: h } deriving Show

newHandle :: HandleLike h => h -> M.TlsM h g (HandleBase h g)
newHandle h = M.newPartner `liftM` get >>= \(i, s) ->
	put s >> return Handle { pid = i, handle = h }

chGet :: (HandleLike h, CPRG g) =>
	HandleBase h g -> Int -> M.TlsM h g (Either Word8 BS.ByteString)
chGet _ 0 = return $ Right ""
chGet h n = getCType h >>= \ct -> case ct of
	M.CTCCSpec -> (Left . head . BS.unpack) `liftM`
		(const `liftM` tRead h 1 `ap` M.rstSn (pid h) M.Read)
	M.CTHandshake -> Right `liftM` tRead h n
	M.CTAlert -> throw M.ALFatal M.ADUnclasified
		. ((modNm ++ ".chGet: ") ++) . show =<< tRead h 2
	_ -> throw M.ALFatal M.ADUnclasified $ modNm ++ ".chGet: not handshake"

tRead :: (HandleLike h, CPRG g) => HandleBase h g -> Int -> M.TlsM h g BS.ByteString
tRead h n = do
	(ct, b) <- M.getRBuf $ pid h; let n' = n - BS.length b
	if n' <= 0
	then cut h n ct b
	else do	(ct', b') <- getContent h
		unless (ct' == ct) . throw M.ALFatal M.ADUnclasified $
			modNm ++ ".tRead: content type confliction\n"
		when (BS.null b') $ throw M.ALFatal M.ADUnclasified  $
			modNm ++ ".tRead: no data available"
		M.setRBuf (pid h) (ct', b')
		(b `BS.append`) `liftM` tRead h n'

cut :: HandleLike h => HandleBase h g ->
	Int -> M.ContType -> BS.ByteString -> M.TlsM h g BS.ByteString
cut h n ct b = (const r `liftM`) . M.setRBuf (pid h) $
	(if BS.null b' then M.CTNull else ct, b')
	where (r, b') = BS.splitAt n b

ccsPut :: (HandleLike h, CPRG g) => HandleBase h g -> Word8 -> M.TlsM h g ()
ccsPut t w =
	const `liftM` tWrite t M.CTCCSpec (BS.pack [w]) `ap` M.rstSn (pid t) M.Write

hsPut :: (HandleLike h, CPRG g) => HandleBase h g -> BS.ByteString -> M.TlsM h g ()
hsPut = flip tWrite M.CTHandshake

adGet :: (HandleLike h, CPRG g) => (HandleBase h g -> M.TlsM h g ()) ->
	HandleBase h g -> Int -> M.TlsM h g BS.ByteString
adGet rp h n = getCType h >>= \ct -> case ct of
	M.CTAppData -> tRead h n
	M.CTHandshake -> rp h >> adGet rp h n
	M.CTAlert -> tRead h 2 >>= \al -> case al of
		"\SOH\NUL" -> tWrite h M.CTAlert "\SOH\NUL" >>
			throw M.ALFatal M.ADUnclasified "EOF"
		_ -> throw M.ALFatal M.ADUnclasified $ "Alert: " ++ show al
	_ -> throw M.ALFatal M.ADUnclasified $ modNm ++ ".adGet"

adGetLine :: (HandleLike h, CPRG g) => (HandleBase h g -> M.TlsM h g ()) ->
	HandleBase h g -> M.TlsM h g BS.ByteString
adGetLine rp h = getCType h >>= \ct -> case ct of
	M.CTAppData -> M.getRBuf (pid h) >>= \(bct, bbs) -> case splitLine bbs of
		Just (l, ls) -> do
			M.setRBuf (pid h) (if BS.null ls then M.CTNull else bct, ls)
			return l
		_ -> do	getContent h >>= M.setRBuf (pid h)
			(bbs `BS.append`) `liftM` adGetLine rp h
	M.CTHandshake -> rp h >> adGetLine rp h
	M.CTAlert -> tRead h 2 >>= \al -> case al of
		"\SOH\NUL" -> tWrite h M.CTAlert "\SOH\NUL" >>
			throw M.ALFatal M.ADUnclasified "EOF"
		_ -> throw M.ALFatal M.ADUnclasified $ "Alert: " ++ show al
	_ -> throw M.ALFatal M.ADUnclasified $ modNm ++ ".adGetLine"

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
adGetContent rp h = getCType h >>= \ct -> case ct of
	M.CTAppData -> tGetContent h
	M.CTHandshake -> rp h >> adGetContent rp h
	M.CTAlert -> tRead h 2 >>= \al -> case al of
		"\SOH\NULL" -> do
			tWrite h M.CTAlert "\SOH\NUL"
			throw M.ALFatal M.ADUnclasified $ modNm ++ ".adGetContent"
		_ -> throw M.ALFatal M.ADUnclasified $ modNm ++ ".adGetcontent"
	_ -> throw M.ALFatal M.ADUnclasified $ modNm ++ ".adGetContent"

tGetContent :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g BS.ByteString
tGetContent h = snd `liftM` M.getRBuf (pid h) >>= \bp -> if BS.null bp
	then snd `liftM` getContent h
	else M.setRBuf (pid h) (M.CTNull, BS.empty) >> return bp

adPut :: (HandleLike h, CPRG g) => HandleBase h g -> BS.ByteString -> M.TlsM h g ()
adPut = flip tWrite M.CTAppData

adDebug :: HandleLike h =>
	HandleBase h g -> DebugLevel h -> BS.ByteString -> M.TlsM h g ()
adDebug = M.tDebug . handle

adClose :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g ()
adClose t = tWrite t M.CTAlert "\SOH\NUL" >> flush t >> M.tClose (handle t)

flushAd :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.TlsM h g (BS.ByteString, Bool)
flushAd t = do
	lift . lift $ hlDebug (handle t) "low" "begin flushAd\n"
	ct <- getCType t
	lift . lift $ hlDebug (handle t) "low" "after getCType\n"
	case ct of
		M.CTAppData -> do
			lift . lift $ hlDebug (handle t) "low" "CTAppData\n"
			ad <- tGetContent t
			(bs, b) <- flushAd t
			lift . lift . hlDebug (handle t) "low" .
				BSC.pack $ show bs
			return (ad `BS.append` bs, b)
		M.CTAlert -> do
			a <- tRead t 2
			lift . lift $ hlDebug (handle t) "low" .
				BSC.pack $ show a
			case a of
				"\1\0" -> return ("", False)
				_ -> throwError "flushAd"
		_ -> do	lift . lift $ hlDebug (handle t) "low" .
				BSC.pack $ show ct
			return ("", True)

getCType :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g M.ContType
getCType t = do
	(ct, bs) <- M.getRBuf (pid t)
	(\gt -> case (ct, bs) of (M.CTNull, _) -> gt; (_, "") -> gt; _ -> return ct) $
--	(\gt -> case (ct, bs) of (M.CTNull, "") -> gt; _ -> return ct) $ do
		do	(ct', bf) <- getContent t
			M.setRBuf (pid t) (ct', bf)
			return ct'

getContent :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.TlsM h g (M.ContType, BS.ByteString)
getContent t = do
	flush t
	ct <- (either (throw M.ALFatal M.ADUnclasified) return . B.decode) =<< rd 1
	[_vmj, _vmn] <- BS.unpack `liftM` rd 2
	e <- rd =<< either (throw M.ALFatal M.ADUnclasified) return . B.decode =<< rd 2
	when (BS.null e) $ throwError "HandleBase.getContent: e is null"
	p <- decrypt t ct e
	M.tDebug (handle t) "medium" . BSC.pack . (++ ": ") $ show ct
	M.tDebug (handle t) "medium" . BSC.pack . (++  "\n") . show $ BS.head p
	M.tDebug (handle t) "low" . BSC.pack . (++ "\n") $ show p
	return (ct, p)
	where rd n = do
		r <- M.tGet (handle t) n
		unless (BS.length r == n) . throw M.ALFatal M.ADUnclasified $
			"HandleBase.rd: can't read " ++ show (BS.length r) ++ " " ++ show n
		return r

decrypt :: HandleLike h =>
	HandleBase h g -> M.ContType -> BS.ByteString -> M.TlsM h g BS.ByteString
decrypt t ct e = do
	ks <- M.getKeys $ pid t
	decrypt_ t ks ct e

decrypt_ :: HandleLike h => HandleBase h g ->
	M.Keys -> M.ContType -> BS.ByteString -> M.TlsM h g BS.ByteString
decrypt_ _ M.Keys{ M.kReadCS = M.CipherSuite _ M.BE_NULL } _ e = return e
decrypt_ t ks ct e = do
	let	M.CipherSuite _ be = M.kReadCS ks
		wk = M.kReadKey ks
		mk = M.kReadMacKey ks
	sn <- updateSequenceNumber t M.Read
	hs <- case be of
		M.AES_128_CBC_SHA -> return C.hashSha1
		M.AES_128_CBC_SHA256 -> return C.hashSha256
		_ -> throwError "HandleBase.decrypt: not implement bulk encryption"
	either (throw M.ALFatal M.ADUnclasified) return $
		C.decrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") e

tWrite :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.ContType -> BS.ByteString -> M.TlsM h g ()
tWrite t ct p = do
	(bct, bp) <- M.getWBuf $ pid t
	case ct of
		M.CTCCSpec -> flush t >> M.setWBuf (pid t) (ct, p) >> flush t
		_	| bct /= M.CTNull && ct /= bct ->
				flush t >> M.setWBuf (pid t) (ct, p)
			| otherwise -> M.setWBuf (pid t) (ct, bp `BS.append` p)

flush :: (HandleLike h, CPRG g) => HandleBase h g -> M.TlsM h g ()
flush t = do
	(bct, bp) <- M.getWBuf $ pid t
	M.setWBuf (pid t) (M.CTNull, "")
	unless (bct == M.CTNull) $ do
		e <- encrypt t bct bp
		M.tPut (handle t) $ BS.concat [
			B.encode bct, "\x03\x03", B.addLen (undefined :: Word16) e ]

encrypt :: (HandleLike h, CPRG g) =>
	HandleBase h g -> M.ContType -> BS.ByteString -> M.TlsM h g BS.ByteString
encrypt t ct p = do
	ks <- M.getKeys $ pid t
	encrypt_ t ks ct p

encrypt_ :: (HandleLike h, CPRG g) => HandleBase h g ->
	M.Keys -> M.ContType -> BS.ByteString -> M.TlsM h g BS.ByteString
encrypt_ _ M.Keys{ M.kWriteCS = M.CipherSuite _ M.BE_NULL } _ p = return p
encrypt_ t ks ct p = do
	let	M.CipherSuite _ be = M.kWriteCS ks
		wk = M.kWriteKey ks
		mk = M.kWriteMacKey ks
	sn <- updateSequenceNumber t M.Write
	hs <- case be of
		M.AES_128_CBC_SHA -> return C.hashSha1
		M.AES_128_CBC_SHA256 -> return C.hashSha256
		_ -> throwError "HandleBase.encrypt: not implemented bulk encryption"
	M.withRandom $ C.encrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") p

updateSequenceNumber :: HandleLike h => HandleBase h g -> M.RW -> M.TlsM h g Word64
updateSequenceNumber t rw = do
	ks <- M.getKeys $ pid t
	sn <- M.getSn (pid t) rw
	let cs = ($ ks) $ case rw of M.Read -> M.kReadCS; M.Write -> M.kWriteCS
	case cs of
		M.CipherSuite _ M.BE_NULL -> return ()
		_ -> M.sccSn (pid t) rw
	return sn

makeKeys :: HandleLike h =>
	HandleBase h g -> C.Side -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> M.CipherSuite -> M.TlsM h g M.Keys
makeKeys t p cr sr pms cs = do
	let M.CipherSuite _ be = cs
	kl <- case be of
		M.AES_128_CBC_SHA -> return 20
		M.AES_128_CBC_SHA256 -> return 32
		_ -> throwError
			"TlsServer.makeKeys: not implemented bulk encryption"
	let	(ms, cwmk, swmk, cwk, swk) = C.makeKeys kl cr sr pms
	k <- M.getKeys $ pid t
	return $ case p of
		C.Client -> k {
			M.kCachedCS = cs,
			M.kMasterSecret = ms,
			M.kCachedReadMacKey = swmk, M.kCachedWriteMacKey = cwmk,
			M.kCachedReadKey = swk, M.kCachedWriteKey = cwk }
		C.Server -> k {
			M.kCachedCS = cs,
			M.kMasterSecret = ms,
			M.kCachedReadMacKey = cwmk, M.kCachedWriteMacKey = swmk,
			M.kCachedReadKey = cwk, M.kCachedWriteKey = swk }

flushCipherSuite :: HandleLike h => M.RW -> HandleBase h g -> M.TlsM h g ()
flushCipherSuite rw = M.flushCipherSuite rw . pid

debugCipherSuite :: HandleLike h => HandleBase h g -> String -> M.TlsM h g ()
debugCipherSuite t a = do
	k <- M.getKeys $ pid t
	M.tDebug (handle t) "high" . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show $ M.kCachedCS k
	where lenSpace n str = str ++ replicate (n - length str) ' '

finishedHash :: HandleLike h =>
	C.Side -> HandleBase h g -> BS.ByteString -> M.TlsM h g BS.ByteString
finishedHash s t hs = do
	ms <- M.kMasterSecret `liftM` M.getKeys (pid t)
	return $ C.finishedHash s ms hs

getClFinished, getSvFinished ::
	HandleLike h => HandleBase h g -> M.TlsM h g BS.ByteString
getClFinished = M.getClFinished . pid
getSvFinished = M.getSvFinished . pid

setClFinished, setSvFinished ::
	HandleLike h => HandleBase h g -> BS.ByteString -> M.TlsM h g ()
setClFinished = M.setClFinished . pid
setSvFinished = M.setSvFinished . pid

getSettingsS :: HandleLike h => HandleBase h g -> M.TlsM h g M.SettingsS
getSettingsS = M.getSettingsS . pid

setSettingsS :: HandleLike h => HandleBase h g -> M.SettingsS -> M.TlsM h g ()
setSettingsS = M.setSettingsS . pid

getBuf :: HandleLike h => HandleBase h g -> M.TlsM h g BS.ByteString
getBuf = M.getAdBuf . pid

setBuf :: HandleLike h => HandleBase h g -> BS.ByteString -> M.TlsM h g ()
setBuf = M.setAdBuf . pid

getSettingsC :: HandleLike h => HandleBase h g -> M.TlsM h g M.SettingsC
getSettingsC = M.getSettingsC . pid

setSettingsC :: HandleLike h => HandleBase h g ->
	M.SettingsC -> M.TlsM h g ()
setSettingsC = M.setSettingsC . pid

getCipherSuite :: HandleLike h => HandleBase h g -> M.TlsM h g M.CipherSuite
getCipherSuite = M.getCipherSuite . pid

setCipherSuite :: HandleLike h => HandleBase h g -> M.CipherSuite -> M.TlsM h g ()
setCipherSuite = M.setCipherSuite . pid

getNames :: HandleLike h => HandleBase h g -> M.TlsM h g [String]
getNames = M.getNames . pid

setNames :: HandleLike h => HandleBase h g -> [String] -> M.TlsM h g ()
setNames = M.setNames . pid

setKeys :: HandleLike h => HandleBase h g -> M.Keys -> M.TlsM h g ()
setKeys = M.setKeys . pid

throw :: HandleLike h => M.AlertLevel -> M.AlertDesc -> String -> M.TlsM h g a
throw = ((throwError .) .) . M.Alert

debug :: (HandleLike h, Show a) =>
	HandleBase h g -> DebugLevel h -> a -> M.TlsM h g ()
debug t l x = lift . lift . hlDebug (handle t) l .
	BSC.pack . (++ "\n") $ show x

class HandleLike h => ValidateHandle h where
	validate :: h -> X509.CertificateStore -> X509.CertificateChain ->
		HandleMonad h [X509.FailedReason]

tValidate :: ValidateHandle h =>
	HandleBase h g -> X509.CertificateStore -> X509.CertificateChain ->
	M.TlsM h g [X509.FailedReason]
tValidate t cs cc = lift . lift $ validate (handle t) cs cc

instance ValidateHandle Handle where
	validate _ cs cc =
		X509.validate X509.HashSHA256 X509.defaultHooks ch cs ca ("", "") cc
		where
		ch = X509.defaultChecks { X509.checkFQHN = False }
		ca = X509.ValidationCache
			(\_ _ _ -> return X509.ValidationCacheUnknown)
			(\_ _ _ -> return ())
