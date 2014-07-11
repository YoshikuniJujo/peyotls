{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Handle (
	tGetContent_,
	TlsM, Alert(..), AlertLevel(..), AlertDesc(..),
		run, withRandom, randomByteString,
	TlsHandleBase(..), RW(..), Side(..), ContentType(..), CipherSuite(..),
		newHandle, getContentType, tlsGet, tlsPut, generateKeys,
		hsGet,
		debugCipherSuite,
		getCipherSuiteSt, setCipherSuiteSt, flushCipherSuiteSt,
		setKeys,
		handshakeHash, finishedHash,
	hlPut_, hlDebug_, hlClose_, tGetLine, tGetLine_, tGetContent,
	getClientFinishedT, setClientFinishedT,
	getServerFinishedT, setServerFinishedT,

	Settings,
	getSettingsT, setSettingsT,
	getInitSetT, setInitSetT,
	SettingsS,

	resetSequenceNumber,
	tlsGet_,
	flushAppData,

	getAdBufT, setAdBufT,
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
import qualified Crypto.Hash.SHA256 as SHA256

import Network.PeyoTLS.Monad (
	TlsM, evalTlsM, initState, thlGet, thlPut, thlClose, thlDebug,
		withRandom, randomByteString,
		getBuf, setBuf, getWBuf, setWBuf,
		getAdBuf, setAdBuf,
		getReadSn, getWriteSn, succReadSn, succWriteSn,
		resetReadSn, resetWriteSn,
		getCipherSuiteSt, setCipherSuiteSt,
		flushCipherSuiteRead, flushCipherSuiteWrite, getKeys, setKeys,
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

type HandleHash h g = (TlsHandleBase h g, SHA256.Ctx)

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
	(ct, bs) <- getBuf (clientId t)
	(\gt -> case (ct, bs) of (CTNull, _) -> gt; (_, "") -> gt; _ -> return ct) $
		do	(ct', bf) <- getWholeWithCt t
			setBuf (clientId t) (ct', bf)
			return ct'

flushAppData :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> TlsM h g (BS.ByteString, Bool)
flushAppData t = do
	lift . lift $ hlDebug (tlsHandle t) "low" "begin flushAppData\n"
	ct <- getContentType t
	lift . lift $ hlDebug (tlsHandle t) "low" "after getContentType\n"
	case ct of
		CTAppData -> do
			lift . lift $ hlDebug (tlsHandle t) "low" "CTAppData\n"
			(ct', ad) <- tGetContent t
			lift . lift $ hlDebug (tlsHandle t) "low" .
				BSC.pack $ show (ct', ad) ++ "\n"
			(bs, b) <- flushAppData t
			lift . lift . hlDebug (tlsHandle t) "low" .
				BSC.pack $ show bs
			return (ad `BS.append` bs, b)
--			liftM (BS.append . snd) (tGetContent t) `ap` flushAppData t
		CTAlert -> do
			((_, a), _) <- tlsGet (t, undefined) 2
			lift . lift $ hlDebug (tlsHandle t) "low" .
				BSC.pack $ show a
			case a of
				"\1\0" -> return ("", False)
				_ -> throwError "flushAppData"
		_ -> do	lift . lift $ hlDebug (tlsHandle t) "low" .
				BSC.pack $ show ct
			return ("", True)

hsGet :: (HandleLike h, CPRG g) => HandleHash h g -> Int ->
	TlsM h g (Either Word8 BS.ByteString, HandleHash h g)
hsGet hh 0 = return (Right "", hh)
hsGet hh@(t, _) n = do
	lift . lift . hlDebug (tlsHandle t) "critical" .
		BSC.pack . (++ "\n") $ show n
	ct <- getContentType t
	lift . lift . hlDebug (tlsHandle t) "critical" .
		BSC.pack . (++ "\n") $ show ct
	case ct of
		CTCCSpec -> do
			((CTCCSpec, bs), hh') <- tlsGet hh 1
			return (Left . (\[w] -> w) $ BS.unpack bs, hh')
		CTHandshake -> do
			((CTHandshake, bs), hh') <- tlsGet hh n
			return (Right bs, hh')
		CTAlert -> do
			((CTAlert, al), _) <- tlsGet hh 2
			throwError . strMsg $ show al
		_ -> throwError "not handshake"

tlsGet :: (HandleLike h, CPRG g) => HandleHash h g ->
	Int -> TlsM h g ((ContentType, BS.ByteString), HandleHash h g)
tlsGet hh@(t, _) n = do
	r@(ct, bs) <- buffered t n
	(r ,) `liftM` case (ct, bs) of
		_ -> return hh

buffered :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> Int -> TlsM h g (ContentType, BS.ByteString)
buffered t n = do
	(ct, b) <- getBuf $ clientId t; let rl = n - BS.length b
	if rl <= 0
	then splitRetBuf t n ct b
	else do	(ct', b') <- getWholeWithCt t
		unless (ct' == ct) . throwError . strMsg $
			"Content Type confliction\n" ++
				"\tExpected: " ++ show ct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show b'
		when (BS.null b') $ throwError "buffered: No data available"
		setBuf (clientId t) (ct', b')
		second (b `BS.append`) `liftM` buffered t rl

tlsGet_ :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> TlsM h g ()) ->
	HandleHash h g -> Int ->
	TlsM h g (BS.ByteString, HandleHash h g)
tlsGet_ rn hh@(t, _) n = (, hh) `liftM` buffered_ rn t n

buffered_ :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> TlsM h g ()) ->
	TlsHandleBase h g -> Int -> TlsM h g BS.ByteString
buffered_ rn t n = do
	ct0 <- getContentType t
	case ct0 of
		CTHandshake -> rn t >> buffered_ rn t n
		CTAlert -> do
			(CTAlert, b) <- getBuf $ clientId t
			let rl = 2 - BS.length b
			al <- if rl <= 0
				then snd `liftM` splitRetBuf t 2 CTAlert b
				else do (ct', b') <- getWholeWithCt t
					unless (ct' == CTAlert) . throwError . strMsg $
						"Content Type confliction\n"
					when (BS.null b') $ throwError "buffered: No data"
					setBuf (clientId t) (ct', b')
					(b `BS.append`) `liftM` buffered_ rn t rl
			case al of
				"\SOH\NULL" -> do
					_ <- tlsPut (t, undefined) CTAlert "\SOH\NULL"
					throwError . strMsg $ "EOF"
				_ -> throwError . strMsg $ "Alert: " ++ show al
		_ -> do	(ct, b) <- getBuf $ clientId t; let rl = n - BS.length b
			if rl <= 0
			then snd `liftM` splitRetBuf t n ct b
			else do
				(ct', b') <- getWholeWithCt t
				unless (ct' == ct) . throwError . strMsg $
					"Content Type confliction\n"
				when (BS.null b') $ throwError "buffered: No data"
				setBuf (clientId t) (ct', b')
				(b `BS.append`) `liftM` buffered_ rn t rl

splitRetBuf :: HandleLike h =>
	TlsHandleBase h g -> Int -> ContentType -> BS.ByteString ->
	TlsM h g (ContentType, BS.ByteString)
splitRetBuf t n ct b = do
	let (ret, b') = BS.splitAt n b
	setBuf (clientId t) $ if BS.null b' then (CTNull, "") else (ct, b')
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
	HandleHash h g -> ContentType -> BS.ByteString -> TlsM h g (HandleHash h g)
tlsPut hh@(t, _) ct p = do
	(bct, bp) <- getWBuf $ clientId t
	case ct of
		CTCCSpec -> flush t >> setWBuf (clientId t) (ct, p) >> flush t
		_	| bct /= CTNull && ct /= bct ->
				flush t >> setWBuf (clientId t) (ct, p)
			| otherwise -> setWBuf (clientId t) (ct, bp `BS.append` p)
	return hh

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

generateKeys :: HandleLike h => TlsHandleBase h g -> Side -> CipherSuite ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> TlsM h g Keys
generateKeys t p cs cr sr pms = do
	let CipherSuite _ be = cs
	kl <- case be of
		AES_128_CBC_SHA -> return 20
		AES_128_CBC_SHA256 -> return 32
		_ -> throwError
			"TlsServer.generateKeys: not implemented bulk encryption"
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

flushCipherSuiteSt :: HandleLike h => RW -> PartnerId -> TlsM h g ()
flushCipherSuiteSt p = case p of
	Read -> flushCipherSuiteRead
	Write -> flushCipherSuiteWrite

debugCipherSuite :: HandleLike h => TlsHandleBase h g -> String -> TlsM h g ()
debugCipherSuite t a = do
	k <- getKeys $ clientId t
	thlDebug (tlsHandle t) "high" . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show $ kCachedCS k
	where lenSpace n str = str ++ replicate (n - length str) ' '

handshakeHash :: HandleLike h => HandleHash h g -> TlsM h g BS.ByteString
handshakeHash = return . SHA256.finalize . snd

finishedHash :: HandleLike h => HandleHash h g -> Side -> TlsM h g BS.ByteString
finishedHash (t, ctx) partner = do
	ms <- kMasterSecret `liftM` getKeys (clientId t)
	sha256 <- handshakeHash (t, ctx)
	return $ CT.finishedHash (partner == Client) ms sha256

hlPut_ :: (HandleLike h, CPRG g) => TlsHandleBase h g -> BS.ByteString -> TlsM h g ()
hlPut_ = ((>> return ()) .) . flip tlsPut CTAppData . (, undefined)

hlDebug_ :: HandleLike h =>
	TlsHandleBase h g -> DebugLevel h -> BS.ByteString -> TlsM h g ()
hlDebug_ t l = lift . lift . hlDebug (tlsHandle t) l

hlClose_ :: (HandleLike h, CPRG g) => TlsHandleBase h g -> TlsM h g ()
hlClose_ t = tlsPut (t, undefined) CTAlert "\SOH\NUL" >>
	flush t >> thlClose (tlsHandle t)

tGetLine :: (HandleLike h, CPRG g) =>
	TlsHandleBase h g -> TlsM h g (ContentType, BS.ByteString)
tGetLine t = do
	(bct, bp) <- getBuf $ clientId t
	case splitLine bp of
		Just (l, ls) -> setBuf (clientId t) (bct, ls) >> return (bct, l)
		_ -> do	cp <- getWholeWithCt t
			setBuf (clientId t) cp
			second (bp `BS.append`) `liftM` tGetLine t

tGetLine_ :: (HandleLike h, CPRG g) => (TlsHandleBase h g -> TlsM h g ()) ->
	TlsHandleBase h g -> TlsM h g BS.ByteString
tGetLine_ rn t = do
	ct <- getContentType t
	case ct of
		CTHandshake -> rn t >> tGetLine_ rn t
		CTAlert -> do
			(CTAlert, b) <- getBuf $ clientId t
			let rl = 2 - BS.length b
			al <- if rl <= 0
				then snd `liftM` splitRetBuf t 2 CTAlert b
				else do (ct', b') <- getWholeWithCt t
					unless (ct' == CTAlert) . throwError . strMsg $
						"Content Type confliction\n"
					when (BS.null b') $ throwError "buffered: No data"
					setBuf (clientId t) (ct', b')
					(b `BS.append`) `liftM` buffered_ rn t rl
			case al of
				"\SOH\NULL" -> do
					_ <- tlsPut (t, undefined) CTAlert "\SOH\NULL"
					throwError . strMsg $ "EOF"
				_ -> throwError . strMsg $ "Alert: " ++ show al
		_ -> do	(bct, bp) <- getBuf $ clientId t
			case splitLine bp of
				Just (l, ls) -> do
					setBuf (clientId t) (if BS.null ls then CTNull else bct, ls)
					return l
				_ -> do	cp <- getWholeWithCt t
					setBuf (clientId t) cp
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
	bcp@(_, bp) <- getBuf $ clientId t
	if BS.null bp then getWholeWithCt t else
		setBuf (clientId t) (CTNull, BS.empty) >> return bcp

getClientFinishedT, getServerFinishedT ::
	HandleLike h => TlsHandleBase h g -> TlsM h g BS.ByteString
getClientFinishedT = getClientFinished . clientId
getServerFinishedT = getServerFinished . clientId

setClientFinishedT, setServerFinishedT ::
	HandleLike h => TlsHandleBase h g -> BS.ByteString -> TlsM h g ()
setClientFinishedT = setClientFinished . clientId
setServerFinishedT = setServerFinished . clientId

getSettingsT :: HandleLike h => TlsHandleBase h g -> TlsM h g Settings
getSettingsT = getSettings . clientId

getInitSetT :: HandleLike h => TlsHandleBase h g -> TlsM h g SettingsS
getInitSetT = getInitSet . clientId

setSettingsT :: HandleLike h => TlsHandleBase h g -> Settings -> TlsM h g ()
setSettingsT = setSettings . clientId

setInitSetT :: HandleLike h => TlsHandleBase h g -> SettingsS -> TlsM h g ()
setInitSetT = setInitSet . clientId

getAdBufT :: HandleLike h => TlsHandleBase h g -> TlsM h g BS.ByteString
getAdBufT = getAdBuf . clientId

setAdBufT :: HandleLike h => TlsHandleBase h g -> BS.ByteString -> TlsM h g ()
setAdBufT = setAdBuf . clientId

tGetContent_ :: (HandleLike h, CPRG g) =>
	(TlsHandleBase h g -> TlsM h g ()) ->
	TlsHandleBase h g -> TlsM h g BS.ByteString
tGetContent_ rn t = do
	ct <- getContentType t
	case ct of
		CTHandshake -> rn t >> tGetContent_ rn t
		CTAlert -> do
			((CTAlert, al), _) <- tlsGet (t, undefined) 2
			case al of
				"\SOH\NULL" -> do
					_ <- tlsPut (t, undefined) CTAlert "\SOH\NUL"
					throwError . strMsg $ ".checkAppData: EOF"
				_ -> throwError . strMsg $ "Alert: " ++ show al
		_ -> snd `liftM` tGetContent t
