{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Handle (
	tGetContent_,
	TlsM, Alert(..), AlertLevel(..), AlertDesc(..),
		run, withRandom,
	TlsHandleBase(..), RW(..), Side(..), ContentType(..), CipherSuite(..),
		newHandle, getContentType, tlsPut, makeKeys,
		chGet, hsPut, ccsPut,
		debugCipherSuite,
		getCipherSuite, setCipherSuite, flushCipherSuite,
		setKeys, finishedHash,
	adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
	hlPut_, hlDebug_, hlClose_, tGetLine, tGetLine_, tGetContent,
	getClFinished, setClFinished,
	getSvFinished, setSvFinished,

	SettingsC,
	getSettingsC, setSettingsC,
	getSettingsS, setSettingsS,
	SettingsS,

	resetSequenceNumber,
	flushAd,

	getBuf, setBuf,
	CertSecretKey(..), isRsaKey, isEcdsaKey,
	) where

import Prelude hiding (read)

import Control.Arrow (second)
import Control.Monad (liftM, when, unless)
import "monads-tf" Control.Monad.State (get, put, lift)
import "monads-tf" Control.Monad.Error (throwError, catchError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Word (Word8, Word16, Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import qualified Network.PeyoTLS.Monad as M
import Network.PeyoTLS.Monad (
	TlsM, evalTlsM, initState, thlGet, thlPut, thlClose, thlDebug,
		withRandom,
		getRBuf, setRBuf, getWBuf, setWBuf,
		getReadSn, getWriteSn, succReadSn, succWriteSn,
		resetReadSn, resetWriteSn,
		getCipherSuiteSt, setCipherSuiteSt,
		flushCipherSuiteRead, flushCipherSuiteWrite, getKeys,
	Alert(..), AlertLevel(..), AlertDesc(..),
	ContentType(..), CipherSuite(..), BulkEnc(..),
	PartnerId, newPartnerId, Keys(..),
	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,
	Settings, getSettings, setSettings,
	SettingsS,
	getInitSet, setInitSet,
	CertSecretKey(..), isRsaKey, isEcdsaKey,
	)
import qualified Network.PeyoTLS.Crypto as CT (
	makeKeys, encrypt, decrypt, hashSha1, hashSha256, finishedHash )

data TlsHandleBase h g = TlsHandleBase {
	clientId :: PartnerId,
	tlsHandle :: h,
	names :: [String] }
	deriving Show

data Side = Server | Client deriving (Show, Eq)

run :: HandleLike h => TlsM h g a -> g -> HandleMonad h a
run m g = do
	ret <- (`evalTlsM` initState g) $ m `catchError` \a -> throwError a
	case ret of
		Right r -> return r
		Left a -> error $ show a

newHandle :: HandleLike h => h -> TlsM h g (TlsHandleBase h g)
newHandle h = do
	s <- get
	let (i, s') = newPartnerId s
	put s'
	return TlsHandleBase {
		clientId = i, tlsHandle = h, names = [] }

getContentType :: (HandleLike h, CPRG g) => TlsHandleBase h g -> TlsM h g ContentType
getContentType t = do
	(ct, bs) <- getRBuf (clientId t)
	(\gt -> case (ct, bs) of (CTNull, _) -> gt; (_, "") -> gt; _ -> return ct) $
		do	(ct', bf) <- getWholeWithCt t
			setRBuf (clientId t) (ct', bf)
			return ct'

flushAd :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> TlsM h g (BS.ByteString, Bool)
flushAd t = do
	lift . lift $ hlDebug (tlsHandle t) "low" "begin flushAd\n"
	ct <- getContentType t
	lift . lift $ hlDebug (tlsHandle t) "low" "after getContentType\n"
	case ct of
		CTAppData -> do
			lift . lift $ hlDebug (tlsHandle t) "low" "CTAppData\n"
			(ct', ad) <- tGetContent t
			lift . lift $ hlDebug (tlsHandle t) "low" .
				BSC.pack $ show (ct', ad) ++ "\n"
			(bs, b) <- flushAd t
			lift . lift . hlDebug (tlsHandle t) "low" .
				BSC.pack $ show bs
			return (ad `BS.append` bs, b)
		CTAlert -> do
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
	TlsHandleBase h g -> Int -> TlsM h g (Either Word8 BS.ByteString)
chGet _ 0 = return $ Right ""
chGet t n = do
	lift . lift . hlDebug (tlsHandle t) "critical" .
		BSC.pack . (++ "\n") $ show n
	ct <- getContentType t
	lift . lift . hlDebug (tlsHandle t) "critical" .
		BSC.pack . (++ "\n") $ show ct
	case ct of
		CTCCSpec -> do
			(CTCCSpec, bs) <- buffered t 1
			resetSequenceNumber t Read
			return . Left . (\[w] -> w) $ BS.unpack bs
		CTHandshake -> do
			(CTHandshake, bs) <- buffered t n
			return $ Right bs
		CTAlert -> do
			(CTAlert, al) <- buffered t 2
			throwError . strMsg $ show al
		_ -> throwError "not handshake"

buffered :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> Int -> TlsM h g (ContentType, BS.ByteString)
buffered t n = do
	(ct, b) <- getRBuf $ clientId t; let rl = n - BS.length b
	if rl <= 0
	then splitRetBuf t n ct b
	else do	(ct', b') <- getWholeWithCt t
		unless (ct' == ct) . throwError . strMsg $
			"Content Type confliction\n" ++
				"\tExpected: " ++ show ct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show b'
		when (BS.null b') $ throwError "buffered: No data available"
		setRBuf (clientId t) (ct', b')
		second (b `BS.append`) `liftM` buffered t rl

adGet :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> TlsM h g ()) ->
	TlsHandleBase h g -> Int -> TlsM h g BS.ByteString
adGet rn t n = buffered_ rn t n

buffered_ :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> TlsM h g ()) ->
	TlsHandleBase h g -> Int -> TlsM h g BS.ByteString
buffered_ rn t n = do
	ct0 <- getContentType t
	case ct0 of
		CTHandshake -> rn t >> buffered_ rn t n
		CTAlert -> do
			(CTAlert, b) <- getRBuf $ clientId t
			let rl = 2 - BS.length b
			al <- if rl <= 0
				then snd `liftM` splitRetBuf t 2 CTAlert b
				else do (ct', b') <- getWholeWithCt t
					unless (ct' == CTAlert) . throwError . strMsg $
						"Content Type confliction\n"
					when (BS.null b') $ throwError "buffered: No data"
					setRBuf (clientId t) (ct', b')
					(b `BS.append`) `liftM` buffered_ rn t rl
			case al of
				"\SOH\NULL" -> do
					tlsPut t CTAlert "\SOH\NULL"
					throwError . strMsg $ "EOF"
				_ -> throwError . strMsg $ "Alert: " ++ show al
		_ -> do	(ct, b) <- getRBuf $ clientId t; let rl = n - BS.length b
			if rl <= 0
			then snd `liftM` splitRetBuf t n ct b
			else do
				(ct', b') <- getWholeWithCt t
				unless (ct' == ct) . throwError . strMsg $
					"Content Type confliction\n"
				when (BS.null b') $ throwError "buffered: No data"
				setRBuf (clientId t) (ct', b')
				(b `BS.append`) `liftM` buffered_ rn t rl

splitRetBuf :: HandleLike h =>
	TlsHandleBase h g -> Int -> ContentType -> BS.ByteString ->
	TlsM h g (ContentType, BS.ByteString)
splitRetBuf t n ct b = do
	let (ret, b') = BS.splitAt n b
	setRBuf (clientId t) $ if BS.null b' then (CTNull, "") else (ct, b')
	return (ct, ret)

getWholeWithCt :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> TlsM h g (ContentType, BS.ByteString)
getWholeWithCt t = do
	flush t
	ct <- (either (throwError . strMsg) return . B.decode) =<< read t 1
	[_vmj, _vmn] <- BS.unpack `liftM` read t 2
	e <- read t =<< either (throwError . strMsg) return . B.decode =<< read t 2
	when (BS.null e) $ throwError "TlsHandleBase.getWholeWithCt: e is null"
	p <- decrypt t ct e
	thlDebug (tlsHandle t) "medium" . BSC.pack . (++ ": ") $ show ct
	thlDebug (tlsHandle t) "medium" . BSC.pack . (++  "\n") . show $ BS.head p
	thlDebug (tlsHandle t) "low" . BSC.pack . (++ "\n") $ show p
	return (ct, p)

read :: (HandleLike h, CPRG g) => TlsHandleBase h g -> Int -> TlsM h g BS.ByteString
read t n = do
	r <- thlGet (tlsHandle t) n
	unless (BS.length r == n) . throwError . strMsg $
		"TlsHandleBase.read: can't read " ++ show (BS.length r) ++ " " ++ show n
	return r

decrypt :: HandleLike h =>
	TlsHandleBase h g -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
decrypt t ct e = do
	ks <- getKeys $ clientId t
	decrypt_ t ks ct e

decrypt_ :: HandleLike h => TlsHandleBase h g ->
	Keys -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
decrypt_ _ Keys{ kReadCS = CipherSuite _ BE_NULL } _ e = return e
decrypt_ t ks ct e = do
	let	CipherSuite _ be = kReadCS ks
		wk = kReadKey ks
		mk = kReadMacKey ks
	sn <- updateSequenceNumber t Read
	hs <- case be of
		AES_128_CBC_SHA -> return CT.hashSha1
		AES_128_CBC_SHA256 -> return CT.hashSha256
		_ -> throwError "TlsHandleBase.decrypt: not implement bulk encryption"
	either (throwError . strMsg) return $
		CT.decrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") e

tlsPut :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> ContentType -> BS.ByteString -> TlsM h g ()
tlsPut t ct p = do
	(bct, bp) <- getWBuf $ clientId t
	case ct of
		CTCCSpec -> flush t >> setWBuf (clientId t) (ct, p) >> flush t
		_	| bct /= CTNull && ct /= bct ->
				flush t >> setWBuf (clientId t) (ct, p)
			| otherwise -> setWBuf (clientId t) (ct, bp `BS.append` p)

flush :: (HandleLike h, CPRG g) => TlsHandleBase h g -> TlsM h g ()
flush t = do
	(bct, bp) <- getWBuf $ clientId t
	setWBuf (clientId t) (CTNull, "")
	unless (bct == CTNull) $ do
		e <- encrypt t bct bp
		thlPut (tlsHandle t) $ BS.concat [
			B.encode bct, "\x03\x03", B.addLen (undefined :: Word16) e ]

encrypt :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
encrypt t ct p = do
	ks <- getKeys $ clientId t
	encrypt_ t ks ct p

encrypt_ :: (HandleLike h, CPRG g) => TlsHandleBase h g ->
	Keys -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
encrypt_ _ Keys{ kWriteCS = CipherSuite _ BE_NULL } _ p = return p
encrypt_ t ks ct p = do
	let	CipherSuite _ be = kWriteCS ks
		wk = kWriteKey ks
		mk = kWriteMacKey ks
	sn <- updateSequenceNumber t Write
	hs <- case be of
		AES_128_CBC_SHA -> return CT.hashSha1
		AES_128_CBC_SHA256 -> return CT.hashSha256
		_ -> throwError "TlsHandleBase.encrypt: not implemented bulk encryption"
	withRandom $ CT.encrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") p

updateSequenceNumber :: HandleLike h => TlsHandleBase h g -> RW -> TlsM h g Word64
updateSequenceNumber t rw = do
	ks <- getKeys $ clientId t
	(sn, cs) <- case rw of
		Read -> (, kReadCS ks) `liftM` getReadSn (clientId t)
		Write -> (, kWriteCS ks) `liftM` getWriteSn (clientId t)
	case cs of
		CipherSuite _ BE_NULL -> return ()
		_ -> case rw of
			Read -> succReadSn $ clientId t
			Write -> succWriteSn $ clientId t
	return sn

resetSequenceNumber :: HandleLike h => TlsHandleBase h g -> RW -> TlsM h g ()
resetSequenceNumber t rw = case rw of
	Read -> resetReadSn $ clientId t
	Write -> resetWriteSn $ clientId t

makeKeys :: HandleLike h =>
	TlsHandleBase h g -> Side -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> CipherSuite -> TlsM h g Keys
makeKeys t p cr sr pms cs = do
	let CipherSuite _ be = cs
	kl <- case be of
		AES_128_CBC_SHA -> return 20
		AES_128_CBC_SHA256 -> return 32
		_ -> throwError
			"TlsServer.makeKeys: not implemented bulk encryption"
	let	(ms, cwmk, swmk, cwk, swk) = CT.makeKeys kl cr sr pms
	k <- getKeys $ clientId t
	return $ case p of
		Client -> k {
			kCachedCS = cs,
			kMasterSecret = ms,
			kCachedReadMacKey = swmk, kCachedWriteMacKey = cwmk,
			kCachedReadKey = swk, kCachedWriteKey = cwk }
		Server -> k {
			kCachedCS = cs,
			kMasterSecret = ms,
			kCachedReadMacKey = cwmk, kCachedWriteMacKey = swmk,
			kCachedReadKey = cwk, kCachedWriteKey = swk }

data RW = Read | Write deriving Show

flushCipherSuite :: HandleLike h => RW -> TlsHandleBase h g -> TlsM h g ()
flushCipherSuite rw = (. clientId) $ case rw of
	Read -> flushCipherSuiteRead
	Write -> flushCipherSuiteWrite

debugCipherSuite :: HandleLike h => TlsHandleBase h g -> String -> TlsM h g ()
debugCipherSuite t a = do
	k <- getKeys $ clientId t
	thlDebug (tlsHandle t) "high" . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show $ kCachedCS k
	where lenSpace n str = str ++ replicate (n - length str) ' '

finishedHash :: HandleLike h =>
	Side -> TlsHandleBase h g -> BS.ByteString -> TlsM h g BS.ByteString
finishedHash s t hs = do
	ms <- kMasterSecret `liftM` getKeys (clientId t)
	return $ CT.finishedHash (s == Client) ms hs

adPut, hlPut_ :: (HandleLike h, CPRG g) => TlsHandleBase h g -> BS.ByteString -> TlsM h g ()
adPut = hlPut_
hlPut_ = ((>> return ()) .) . flip tlsPut CTAppData

adDebug, hlDebug_ :: HandleLike h =>
	TlsHandleBase h g -> DebugLevel h -> BS.ByteString -> TlsM h g ()
adDebug = hlDebug_
hlDebug_ = thlDebug . tlsHandle

adClose, hlClose_ :: (HandleLike h, CPRG g) => TlsHandleBase h g -> TlsM h g ()
adClose = hlClose_
hlClose_ t = tlsPut t CTAlert "\SOH\NUL" >> flush t >> thlClose (tlsHandle t)

tGetLine :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> TlsM h g (ContentType, BS.ByteString)
tGetLine t = do
	(bct, bp) <- getRBuf $ clientId t
	case splitLine bp of
		Just (l, ls) -> setRBuf (clientId t) (bct, ls) >> return (bct, l)
		_ -> do	cp <- getWholeWithCt t
			setRBuf (clientId t) cp
			second (bp `BS.append`) `liftM` tGetLine t

adGetLine, tGetLine_ :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> TlsM h g ()) ->
	TlsHandleBase h g -> TlsM h g BS.ByteString
adGetLine = tGetLine_
tGetLine_ rn t = do
	ct <- getContentType t
	case ct of
		CTHandshake -> rn t >> tGetLine_ rn t
		CTAlert -> do
			(CTAlert, b) <- getRBuf $ clientId t
			let rl = 2 - BS.length b
			al <- if rl <= 0
				then snd `liftM` splitRetBuf t 2 CTAlert b
				else do (ct', b') <- getWholeWithCt t
					unless (ct' == CTAlert) . throwError . strMsg $
						"Content Type confliction\n"
					when (BS.null b') $ throwError "buffered: No data"
					setRBuf (clientId t) (ct', b')
					(b `BS.append`) `liftM` buffered_ rn t rl
			case al of
				"\SOH\NULL" -> do
					tlsPut t CTAlert "\SOH\NULL"
					throwError . strMsg $ "EOF"
				_ -> throwError . strMsg $ "Alert: " ++ show al
		_ -> do	(bct, bp) <- getRBuf $ clientId t
			case splitLine bp of
				Just (l, ls) -> do
					setRBuf (clientId t) (if BS.null ls then CTNull else bct, ls)
					return l
				_ -> do	cp <- getWholeWithCt t
					setRBuf (clientId t) cp
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
	TlsHandleBase h g -> TlsM h g (ContentType, BS.ByteString)
tGetContent t = do
	bcp@(_, bp) <- getRBuf $ clientId t
	if BS.null bp then getWholeWithCt t else
		setRBuf (clientId t) (CTNull, BS.empty) >> return bcp

getClFinished, getSvFinished ::
	HandleLike h => TlsHandleBase h g -> TlsM h g BS.ByteString
getClFinished = getClientFinished . clientId
getSvFinished = getServerFinished . clientId

setClFinished, setSvFinished ::
	HandleLike h => TlsHandleBase h g -> BS.ByteString -> TlsM h g ()
setClFinished = setClientFinished . clientId
setSvFinished = setServerFinished . clientId

getSettingsT :: HandleLike h => TlsHandleBase h g -> TlsM h g Settings
getSettingsT = getSettings . clientId

getSettingsS :: HandleLike h => TlsHandleBase h g -> TlsM h g SettingsS
getSettingsS = getInitSet . clientId

setSettingsT :: HandleLike h => TlsHandleBase h g -> Settings -> TlsM h g ()
setSettingsT = setSettings . clientId

setSettingsS :: HandleLike h => TlsHandleBase h g -> SettingsS -> TlsM h g ()
setSettingsS = setInitSet . clientId

getBuf :: HandleLike h => TlsHandleBase h g -> TlsM h g BS.ByteString
getBuf = M.getAdBuf . clientId

setBuf :: HandleLike h => TlsHandleBase h g -> BS.ByteString -> TlsM h g ()
setBuf = M.setAdBuf . clientId

adGetContent, tGetContent_ :: (HandleLike h, CPRG g) =>
	(TlsHandleBase h g -> TlsM h g ()) ->
	TlsHandleBase h g -> TlsM h g BS.ByteString
adGetContent = tGetContent_
tGetContent_ rn t = do
	ct <- getContentType t
	case ct of
		CTHandshake -> rn t >> tGetContent_ rn t
		CTAlert -> do
			(CTAlert, al) <- buffered t 2
			case al of
				"\SOH\NULL" -> do
					tlsPut t CTAlert "\SOH\NUL"
					throwError . strMsg $ ".checkAppData: EOF"
				_ -> throwError . strMsg $ "Alert: " ++ show al
		_ -> snd `liftM` tGetContent t

hsPut :: (HandleLike h, CPRG g) => TlsHandleBase h g -> BS.ByteString -> TlsM h g ()
hsPut = flip tlsPut CTHandshake

ccsPut :: (HandleLike h, CPRG g) => TlsHandleBase h g -> Word8 -> TlsM h g ()
ccsPut t w = do
	ret <- tlsPut t CTCCSpec $ BS.pack [w]
	resetSequenceNumber t Write
	return ret

type SettingsC = (
	[CipherSuite],
	[(CertSecretKey, X509.CertificateChain)],
	X509.CertificateStore )

getSettingsC :: HandleLike h => TlsHandleBase h g -> TlsM h g SettingsC
getSettingsC t = do
	(css, crts, mcs) <- getSettingsT t
	case mcs of
		Just cs -> return (css, crts, cs)
		_ -> throwError "Network.PeyoTLS.Base.getSettingsC"

setSettingsC :: HandleLike h => TlsHandleBase h g ->
	SettingsC -> TlsM h g ()
setSettingsC t (css, crts, cs) = setSettingsT t (css, crts, Just cs)

getCipherSuite :: HandleLike h => TlsHandleBase h g -> TlsM h g CipherSuite
getCipherSuite = getCipherSuiteSt . clientId

setCipherSuite :: HandleLike h => TlsHandleBase h g -> CipherSuite -> TlsM h g ()
setCipherSuite = setCipherSuiteSt . clientId

setKeys :: HandleLike h => TlsHandleBase h g -> Keys -> TlsM h g ()
setKeys = M.setKeys . clientId
