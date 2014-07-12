{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

module Network.PeyoTLS.Handle (
	M.TlsM, run, M.withRandom,
	TlsHandleBase(..), M.CipherSuite,
		newHandle, chGet, ccsPut, hsPut,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
		flushAd, getBuf, setBuf,
		getCipherSuite, setCipherSuite,
		M.SettingsC, getSettingsC, setSettingsC,
		M.SettingsS, getSettingsS, setSettingsS,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		makeKeys, setKeys,
		C.Side(..), finishedHash,
		M.RW(..), flushCipherSuite,
	M.CertSecretKey(..), M.isRsaKey, M.isEcdsaKey,
	M.Alert(..), M.AlertLevel(..), M.AlertDesc(..), debugCipherSuite ) where

import Control.Arrow (second)
import Control.Monad (when, unless, liftM)
import "monads-tf" Control.Monad.State (lift, get, put)
import "monads-tf" Control.Monad.Error (catchError, throwError)
import Data.Word (Word8, Word16, Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B

import qualified Network.PeyoTLS.Monad as M (
	TlsM, evalTlsM, initState, withRandom,
		Alert(..), AlertLevel(..), AlertDesc(..),
		tGet, tPut, tClose, tDebug,
	PartnerId, newPartnerId, ContentType(..),
		getRBuf, getWBuf, getAdBuf, setRBuf, setWBuf, setAdBuf,
		getRSn, getWSn, sccRSn, sccWSn, rstRSn, rstWSn,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
	CipherSuite(..), BulkEnc(..), CertSecretKey(..), isRsaKey, isEcdsaKey,
		SettingsC, getSettingsC, setSettingsC,
		SettingsS, getSettingsS, setSettingsS,
		RW(..), getCipherSuite, setCipherSuite, flushCipherSuite,
	Keys(..), getKeys, setKeys )
import qualified Network.PeyoTLS.Crypto as C (
	makeKeys, encrypt, decrypt, hashSha1, hashSha256,
	Side(..), finishedHash )

data TlsHandleBase h g =
	TlsHandleBase { clientId :: M.PartnerId, tlsHandle :: h, names :: [String] }
	deriving Show

run :: HandleLike h => M.TlsM h g a -> g -> HandleMonad h a
run m g = do
	ret <- (`M.evalTlsM` M.initState g) $ m `catchError` \a -> throwError a
	case ret of
		Right r -> return r
		Left a -> error $ show a

newHandle :: HandleLike h => h -> M.TlsM h g (TlsHandleBase h g)
newHandle h = do
	s <- get
	let (i, s') = M.newPartnerId s
	put s'
	return TlsHandleBase {
		clientId = i, tlsHandle = h, names = [] }

getContentType :: (HandleLike h, CPRG g) => TlsHandleBase h g -> M.TlsM h g M.ContentType
getContentType t = do
	(ct, bs) <- M.getRBuf (clientId t)
	(\gt -> case (ct, bs) of (M.CTNull, _) -> gt; (_, "") -> gt; _ -> return ct) $
		do	(ct', bf) <- getWholeWithCt t
			M.setRBuf (clientId t) (ct', bf)
			return ct'

flushAd :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> M.TlsM h g (BS.ByteString, Bool)
flushAd t = do
	lift . lift $ hlDebug (tlsHandle t) "low" "begin flushAd\n"
	ct <- getContentType t
	lift . lift $ hlDebug (tlsHandle t) "low" "after getContentType\n"
	case ct of
		M.CTAppData -> do
			lift . lift $ hlDebug (tlsHandle t) "low" "CTAppData\n"
			(ct', ad) <- tGetContent t
			lift . lift $ hlDebug (tlsHandle t) "low" .
				BSC.pack $ show (ct', ad) ++ "\n"
			(bs, b) <- flushAd t
			lift . lift . hlDebug (tlsHandle t) "low" .
				BSC.pack $ show bs
			return (ad `BS.append` bs, b)
		M.CTAlert -> do
			(_, a) <- buffered t 2
			lift . lift $ hlDebug (tlsHandle t) "low" .
				BSC.pack $ show a
			case a of
				"\1\0" -> return ("", False)
				_ -> throwError "flushAd"
		_ -> do	lift . lift $ hlDebug (tlsHandle t) "low" .
				BSC.pack $ show ct
			return ("", True)

chGet :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> Int -> M.TlsM h g (Either Word8 BS.ByteString)
chGet _ 0 = return $ Right ""
chGet t n = do
	lift . lift . hlDebug (tlsHandle t) "critical" .
		BSC.pack . (++ "\n") $ show n
	ct <- getContentType t
	lift . lift . hlDebug (tlsHandle t) "critical" .
		BSC.pack . (++ "\n") $ show ct
	case ct of
		M.CTCCSpec -> do
			(M.CTCCSpec, bs) <- buffered t 1
			resetSequenceNumber t M.Read
			return . Left . (\[w] -> w) $ BS.unpack bs
		M.CTHandshake -> do
			(M.CTHandshake, bs) <- buffered t n
			return $ Right bs
		M.CTAlert -> do
			(M.CTAlert, al) <- buffered t 2
			throw M.ALFatal M.ADUnclasified $ show al
		_ -> throwError "not handshake"

buffered :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> Int -> M.TlsM h g (M.ContentType, BS.ByteString)
buffered t n = do
	(ct, b) <- M.getRBuf $ clientId t; let rl = n - BS.length b
	if rl <= 0
	then splitRetBuf t n ct b
	else do	(ct', b') <- getWholeWithCt t
		unless (ct' == ct) . throw M.ALFatal M.ADUnclasified $
			"Content Type confliction\n" ++
				"\tExpected: " ++ show ct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show b'
		when (BS.null b') $ throwError "buffered: No data available"
		M.setRBuf (clientId t) (ct', b')
		second (b `BS.append`) `liftM` buffered t rl

adGet :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> M.TlsM h g ()) ->
	TlsHandleBase h g -> Int -> M.TlsM h g BS.ByteString
adGet rn t n = buffered_ rn t n

buffered_ :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> M.TlsM h g ()) ->
	TlsHandleBase h g -> Int -> M.TlsM h g BS.ByteString
buffered_ rn t n = do
	ct0 <- getContentType t
	case ct0 of
		M.CTHandshake -> rn t >> buffered_ rn t n
		M.CTAlert -> do
			(M.CTAlert, b) <- M.getRBuf $ clientId t
			let rl = 2 - BS.length b
			al <- if rl <= 0
				then snd `liftM` splitRetBuf t 2 M.CTAlert b
				else do (ct', b') <- getWholeWithCt t
					unless (ct' == M.CTAlert) $ throw
						M.ALFatal M.ADUnclasified
						"Content Type confliction\n"
					when (BS.null b') $ throwError "buffered: No data"
					M.setRBuf (clientId t) (ct', b')
					(b `BS.append`) `liftM` buffered_ rn t rl
			case al of
				"\SOH\NULL" -> do
					tlsPut t M.CTAlert "\SOH\NULL"
					throw M.ALFatal M.ADUnclasified "EOF"
				_ -> throw M.ALFatal M.ADUnclasified $
					"Alert: " ++ show al
		_ -> do	(ct, b) <- M.getRBuf $ clientId t; let rl = n - BS.length b
			if rl <= 0
			then snd `liftM` splitRetBuf t n ct b
			else do
				(ct', b') <- getWholeWithCt t
				unless (ct' == ct) $ throw M.ALFatal M.ADUnclasified
					"Content Type confliction\n"
				when (BS.null b') $ throwError "buffered: No data"
				M.setRBuf (clientId t) (ct', b')
				(b `BS.append`) `liftM` buffered_ rn t rl

splitRetBuf :: HandleLike h =>
	TlsHandleBase h g -> Int -> M.ContentType -> BS.ByteString ->
	M.TlsM h g (M.ContentType, BS.ByteString)
splitRetBuf t n ct b = do
	let (ret, b') = BS.splitAt n b
	M.setRBuf (clientId t) $ if BS.null b' then (M.CTNull, "") else (ct, b')
	return (ct, ret)

getWholeWithCt :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> M.TlsM h g (M.ContentType, BS.ByteString)
getWholeWithCt t = do
	flush t
	ct <- (either (throw M.ALFatal M.ADUnclasified) return . B.decode) =<< rd 1
	[_vmj, _vmn] <- BS.unpack `liftM` rd 2
	e <- rd =<< either (throw M.ALFatal M.ADUnclasified) return . B.decode =<< rd 2
	when (BS.null e) $ throwError "TlsHandleBase.getWholeWithCt: e is null"
	p <- decrypt t ct e
	M.tDebug (tlsHandle t) "medium" . BSC.pack . (++ ": ") $ show ct
	M.tDebug (tlsHandle t) "medium" . BSC.pack . (++  "\n") . show $ BS.head p
	M.tDebug (tlsHandle t) "low" . BSC.pack . (++ "\n") $ show p
	return (ct, p)
	where rd n = do
		r <- M.tGet (tlsHandle t) n
		unless (BS.length r == n) . throw M.ALFatal M.ADUnclasified $
			"TlsHandleBase.rd: can't read " ++ show (BS.length r) ++ " " ++ show n
		return r

decrypt :: HandleLike h =>
	TlsHandleBase h g -> M.ContentType -> BS.ByteString -> M.TlsM h g BS.ByteString
decrypt t ct e = do
	ks <- M.getKeys $ clientId t
	decrypt_ t ks ct e

decrypt_ :: HandleLike h => TlsHandleBase h g ->
	M.Keys -> M.ContentType -> BS.ByteString -> M.TlsM h g BS.ByteString
decrypt_ _ M.Keys{ M.kReadCS = M.CipherSuite _ M.BE_NULL } _ e = return e
decrypt_ t ks ct e = do
	let	M.CipherSuite _ be = M.kReadCS ks
		wk = M.kReadKey ks
		mk = M.kReadMacKey ks
	sn <- updateSequenceNumber t M.Read
	hs <- case be of
		M.AES_128_CBC_SHA -> return C.hashSha1
		M.AES_128_CBC_SHA256 -> return C.hashSha256
		_ -> throwError "TlsHandleBase.decrypt: not implement bulk encryption"
	either (throw M.ALFatal M.ADUnclasified) return $
		C.decrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") e

tlsPut :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> M.ContentType -> BS.ByteString -> M.TlsM h g ()
tlsPut t ct p = do
	(bct, bp) <- M.getWBuf $ clientId t
	case ct of
		M.CTCCSpec -> flush t >> M.setWBuf (clientId t) (ct, p) >> flush t
		_	| bct /= M.CTNull && ct /= bct ->
				flush t >> M.setWBuf (clientId t) (ct, p)
			| otherwise -> M.setWBuf (clientId t) (ct, bp `BS.append` p)

flush :: (HandleLike h, CPRG g) => TlsHandleBase h g -> M.TlsM h g ()
flush t = do
	(bct, bp) <- M.getWBuf $ clientId t
	M.setWBuf (clientId t) (M.CTNull, "")
	unless (bct == M.CTNull) $ do
		e <- encrypt t bct bp
		M.tPut (tlsHandle t) $ BS.concat [
			B.encode bct, "\x03\x03", B.addLen (undefined :: Word16) e ]

encrypt :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> M.ContentType -> BS.ByteString -> M.TlsM h g BS.ByteString
encrypt t ct p = do
	ks <- M.getKeys $ clientId t
	encrypt_ t ks ct p

encrypt_ :: (HandleLike h, CPRG g) => TlsHandleBase h g ->
	M.Keys -> M.ContentType -> BS.ByteString -> M.TlsM h g BS.ByteString
encrypt_ _ M.Keys{ M.kWriteCS = M.CipherSuite _ M.BE_NULL } _ p = return p
encrypt_ t ks ct p = do
	let	M.CipherSuite _ be = M.kWriteCS ks
		wk = M.kWriteKey ks
		mk = M.kWriteMacKey ks
	sn <- updateSequenceNumber t M.Write
	hs <- case be of
		M.AES_128_CBC_SHA -> return C.hashSha1
		M.AES_128_CBC_SHA256 -> return C.hashSha256
		_ -> throwError "TlsHandleBase.encrypt: not implemented bulk encryption"
	M.withRandom $ C.encrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") p

updateSequenceNumber :: HandleLike h => TlsHandleBase h g -> M.RW -> M.TlsM h g Word64
updateSequenceNumber t rw = do
	ks <- M.getKeys $ clientId t
	(sn, cs) <- case rw of
		M.Read -> (, M.kReadCS ks) `liftM` M.getRSn (clientId t)
		M.Write -> (, M.kWriteCS ks) `liftM` M.getWSn (clientId t)
	case cs of
		M.CipherSuite _ M.BE_NULL -> return ()
		_ -> case rw of
			M.Read -> M.sccRSn $ clientId t
			M.Write -> M.sccWSn $ clientId t
	return sn

resetSequenceNumber :: HandleLike h => TlsHandleBase h g -> M.RW -> M.TlsM h g ()
resetSequenceNumber t rw = case rw of
	M.Read -> M.rstRSn $ clientId t
	M.Write -> M.rstWSn $ clientId t

makeKeys :: HandleLike h =>
	TlsHandleBase h g -> C.Side -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> M.CipherSuite -> M.TlsM h g M.Keys
makeKeys t p cr sr pms cs = do
	let M.CipherSuite _ be = cs
	kl <- case be of
		M.AES_128_CBC_SHA -> return 20
		M.AES_128_CBC_SHA256 -> return 32
		_ -> throwError
			"TlsServer.makeKeys: not implemented bulk encryption"
	let	(ms, cwmk, swmk, cwk, swk) = C.makeKeys kl cr sr pms
	k <- M.getKeys $ clientId t
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

flushCipherSuite :: HandleLike h => M.RW -> TlsHandleBase h g -> M.TlsM h g ()
flushCipherSuite rw = M.flushCipherSuite rw . clientId

debugCipherSuite :: HandleLike h => TlsHandleBase h g -> String -> M.TlsM h g ()
debugCipherSuite t a = do
	k <- M.getKeys $ clientId t
	M.tDebug (tlsHandle t) "high" . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show $ M.kCachedCS k
	where lenSpace n str = str ++ replicate (n - length str) ' '

finishedHash :: HandleLike h =>
	C.Side -> TlsHandleBase h g -> BS.ByteString -> M.TlsM h g BS.ByteString
finishedHash s t hs = do
	ms <- M.kMasterSecret `liftM` M.getKeys (clientId t)
	return $ C.finishedHash s ms hs

adPut, hlPut_ :: (HandleLike h, CPRG g) => TlsHandleBase h g -> BS.ByteString -> M.TlsM h g ()
adPut = hlPut_
hlPut_ = ((>> return ()) .) . flip tlsPut M.CTAppData

adDebug, hlDebug_ :: HandleLike h =>
	TlsHandleBase h g -> DebugLevel h -> BS.ByteString -> M.TlsM h g ()
adDebug = hlDebug_
hlDebug_ = M.tDebug . tlsHandle

adClose, hlClose_ :: (HandleLike h, CPRG g) => TlsHandleBase h g -> M.TlsM h g ()
adClose = hlClose_
hlClose_ t = tlsPut t M.CTAlert "\SOH\NUL" >> flush t >> M.tClose (tlsHandle t)

adGetLine, tGetLine_ :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> M.TlsM h g ()) ->
	TlsHandleBase h g -> M.TlsM h g BS.ByteString
adGetLine = tGetLine_
tGetLine_ rn t = do
	ct <- getContentType t
	case ct of
		M.CTHandshake -> rn t >> tGetLine_ rn t
		M.CTAlert -> do
			(M.CTAlert, b) <- M.getRBuf $ clientId t
			let rl = 2 - BS.length b
			al <- if rl <= 0
				then snd `liftM` splitRetBuf t 2 M.CTAlert b
				else do (ct', b') <- getWholeWithCt t
					unless (ct' == M.CTAlert) . throw M.ALFatal M.ADUnclasified $
						"Content Type confliction\n"
					when (BS.null b') $ throwError "buffered: No data"
					M.setRBuf (clientId t) (ct', b')
					(b `BS.append`) `liftM` buffered_ rn t rl
			case al of
				"\SOH\NULL" -> do
					tlsPut t M.CTAlert "\SOH\NULL"
					throw M.ALFatal M.ADUnclasified "EOF"
				_ -> throw M.ALFatal M.ADUnclasified $
					"Alert: " ++ show al
		_ -> do	(bct, bp) <- M.getRBuf $ clientId t
			case splitLine bp of
				Just (l, ls) -> do
					M.setRBuf (clientId t) (if BS.null ls then M.CTNull else bct, ls)
					return l
				_ -> do	cp <- getWholeWithCt t
					M.setRBuf (clientId t) cp
					(bp `BS.append`) `liftM` tGetLine_ rn t

splitLine :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
splitLine bs = case ('\r' `BSC.elem` bs, '\n' `BSC.elem` bs) of
	(True, _) -> let
		(l, ls) = BSC.span (/= '\r') bs
		Just ('\r', ls') = BSC.uncons ls in
		case BSC.uncons ls' of
			Just ('\n', ls'') -> Just (l, ls'')
			_ -> Just (l, ls')
	(_, True) -> let
		(l, ls) = BSC.span (/= '\n') bs
		Just ('\n', ls') = BSC.uncons ls in Just (l, ls')
	_ -> Nothing

tGetContent :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> M.TlsM h g (M.ContentType, BS.ByteString)
tGetContent t = do
	bcp@(_, bp) <- M.getRBuf $ clientId t
	if BS.null bp then getWholeWithCt t else
		M.setRBuf (clientId t) (M.CTNull, BS.empty) >> return bcp

getClFinished, getSvFinished ::
	HandleLike h => TlsHandleBase h g -> M.TlsM h g BS.ByteString
getClFinished = M.getClFinished . clientId
getSvFinished = M.getSvFinished . clientId

setClFinished, setSvFinished ::
	HandleLike h => TlsHandleBase h g -> BS.ByteString -> M.TlsM h g ()
setClFinished = M.setClFinished . clientId
setSvFinished = M.setSvFinished . clientId

getSettingsS :: HandleLike h => TlsHandleBase h g -> M.TlsM h g M.SettingsS
getSettingsS = M.getSettingsS . clientId

setSettingsS :: HandleLike h => TlsHandleBase h g -> M.SettingsS -> M.TlsM h g ()
setSettingsS = M.setSettingsS . clientId

getBuf :: HandleLike h => TlsHandleBase h g -> M.TlsM h g BS.ByteString
getBuf = M.getAdBuf . clientId

setBuf :: HandleLike h => TlsHandleBase h g -> BS.ByteString -> M.TlsM h g ()
setBuf = M.setAdBuf . clientId

adGetContent, tGetContent_ :: (HandleLike h, CPRG g) =>
	(TlsHandleBase h g -> M.TlsM h g ()) ->
	TlsHandleBase h g -> M.TlsM h g BS.ByteString
adGetContent = tGetContent_
tGetContent_ rn t = do
	ct <- getContentType t
	case ct of
		M.CTHandshake -> rn t >> tGetContent_ rn t
		M.CTAlert -> do
			(M.CTAlert, al) <- buffered t 2
			case al of
				"\SOH\NULL" -> do
					tlsPut t M.CTAlert "\SOH\NUL"
					throw M.ALFatal M.ADUnclasified $
						".checkAppData: EOF"
				_ -> throw M.ALFatal M.ADUnclasified $
					"Alert: " ++ show al
		_ -> snd `liftM` tGetContent t

hsPut :: (HandleLike h, CPRG g) => TlsHandleBase h g -> BS.ByteString -> M.TlsM h g ()
hsPut = flip tlsPut M.CTHandshake

ccsPut :: (HandleLike h, CPRG g) => TlsHandleBase h g -> Word8 -> M.TlsM h g ()
ccsPut t w = do
	ret <- tlsPut t M.CTCCSpec $ BS.pack [w]
	resetSequenceNumber t M.Write
	return ret

getSettingsC :: HandleLike h => TlsHandleBase h g -> M.TlsM h g M.SettingsC
getSettingsC = M.getSettingsC . clientId

setSettingsC :: HandleLike h => TlsHandleBase h g ->
	M.SettingsC -> M.TlsM h g ()
setSettingsC = M.setSettingsC . clientId

getCipherSuite :: HandleLike h => TlsHandleBase h g -> M.TlsM h g M.CipherSuite
getCipherSuite = M.getCipherSuite . clientId

setCipherSuite :: HandleLike h => TlsHandleBase h g -> M.CipherSuite -> M.TlsM h g ()
setCipherSuite = M.setCipherSuite . clientId

setKeys :: HandleLike h => TlsHandleBase h g -> M.Keys -> M.TlsM h g ()
setKeys = M.setKeys . clientId

throw :: HandleLike h => M.AlertLevel -> M.AlertDesc -> String -> M.TlsM h g a
throw = ((throwError .) .) . M.Alert
