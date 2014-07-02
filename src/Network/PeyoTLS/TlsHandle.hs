{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.TlsHandle (
	TlsM, Alert(..), AlertLevel(..), AlertDesc(..),
		run, withRandom, randomByteString,
	TlsHandle(..), RW(..), Side(..), ContentType(..), CipherSuite(..),
		newHandle, getContentType, tlsGet, tlsPut, generateKeys,
		debugCipherSuite,
		getCipherSuiteSt, setCipherSuiteSt, flushCipherSuiteSt,
		setKeys,
		handshakeHash, finishedHash ) where

import Prelude hiding (read)

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (second)
import Control.Monad (liftM, when, unless)
import "monads-tf" Control.Monad.State (get, put, lift)
import "monads-tf" Control.Monad.Error (throwError, catchError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Word (Word16, Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Hash.SHA256 as SHA256

import Network.PeyoTLS.TlsMonad (
	TlsM, evalTlsM, initState, thlGet, thlPut, thlClose, thlDebug,
		withRandom, randomByteString, getBuf, setBuf, getWBuf, setWBuf,
		getReadSn, getWriteSn, succReadSn, succWriteSn,
		getCipherSuiteSt, setCipherSuiteSt,
		flushCipherSuiteRead, flushCipherSuiteWrite, getKeys, setKeys,
	Alert(..), AlertLevel(..), AlertDesc(..),
	ContentType(..), CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	PartnerId, newPartnerId, Keys(..))
import qualified Network.PeyoTLS.CryptoTools as CT (
	makeKeys, encrypt, decrypt, hashSha1, hashSha256, finishedHash )

data TlsHandle h g = TlsHandle {
	clientId :: PartnerId,
	tlsHandle :: h, names :: [String] }

type HandleHash h g = (TlsHandle h g, SHA256.Ctx)

data Side = Server | Client deriving (Show, Eq)

run :: HandleLike h => TlsM h g a -> g -> HandleMonad h a
run m g = do
	ret <- (`evalTlsM` initState g) $ m `catchError` \a -> throwError a
	case ret of
		Right r -> return r
		Left a -> error $ show a

newHandle :: HandleLike h => h -> TlsM h g (TlsHandle h g)
newHandle h = do
	s <- get
	let (i, s') = newPartnerId s
	put s'
	return TlsHandle {
		clientId = i, tlsHandle = h, names = [] }

getContentType :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ContentType
getContentType t = do
	ct <- fst `liftM` getBuf (clientId t)
	(\gt -> case ct of CTNull -> gt; _ -> return ct) $ do
		(ct', bf) <- getWholeWithCt t
		setBuf (clientId t) (ct', bf)
		return ct'

tlsGet :: (HandleLike h, CPRG g) => HandleHash h g ->
	Int -> TlsM h g ((ContentType, BS.ByteString), HandleHash h g)
tlsGet hh@(t, _) n = do
	r@(ct, bs) <- buffered t n
	(r ,) `liftM` case ct of
		CTHandshake -> updateHash hh bs
		_ -> return hh

buffered :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> Int -> TlsM h g (ContentType, BS.ByteString)
buffered t n = do
	(ct, b) <- getBuf $ clientId t; let rl = n - BS.length b
	if rl <= 0
	then do	let (ret, b') = BS.splitAt n b
		setBuf (clientId t) $ if BS.null b' then (CTNull, "") else (ct, b')
		return (ct, ret)
	else do	(ct', b') <- getWholeWithCt t
		unless (ct' == ct) . throwError . strMsg $
			"Content Type confliction\n" ++
				"\tExpected: " ++ show ct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show b'
		when (BS.null b') $ throwError "buffered: No data available"
		setBuf (clientId t) (ct', b')
		second (b `BS.append`) `liftM` buffered t rl

getWholeWithCt :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
getWholeWithCt t = do
	flush t
	ct <- (either (throwError . strMsg) return . B.decode) =<< read t 1
	[_vmj, _vmn] <- BS.unpack `liftM` read t 2
	e <- read t =<< either (throwError . strMsg) return . B.decode =<< read t 2
	when (BS.null e) $ throwError "TlsHandle.getWholeWithCt: e is null"
	p <- decrypt t ct e
	return (ct, p)

read :: (HandleLike h, CPRG g) => TlsHandle h g -> Int -> TlsM h g BS.ByteString
read t n = do
	r <- thlGet (tlsHandle t) n
	unless (BS.length r == n) . throwError . strMsg $
		"TlsHandle.read: can't read " ++ show (BS.length r) ++ " " ++ show n
	return r

decrypt :: HandleLike h =>
	TlsHandle h g -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
decrypt t ct e = do
	ks <- getKeys $ clientId t
	decrypt_ t ks ct e

decrypt_ :: HandleLike h => TlsHandle h g ->
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
		_ -> throwError "TlsHandle.decrypt: not implement bulk encryption"
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
	case ct of
		CTHandshake -> updateHash hh p
		_ -> return hh

flush :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
flush t = do
	(bct, bp) <- getWBuf $ clientId t
	setWBuf (clientId t) (CTNull, "")
	unless (bct == CTNull) $ do
		e <- encrypt t bct bp
		thlPut (tlsHandle t) $ BS.concat [
			B.encode bct, "\x03\x03", B.addLen (undefined :: Word16) e ]

encrypt :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
encrypt t ct p = do
	ks <- getKeys $ clientId t
	encrypt_ t ks ct p

encrypt_ :: (HandleLike h, CPRG g) => TlsHandle h g ->
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
		_ -> throwError "TlsHandle.encrypt: not implemented bulk encryption"
	withRandom $ CT.encrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") p

updateHash ::
	HandleLike h => HandleHash h g -> BS.ByteString -> TlsM h g (HandleHash h g)
updateHash (th, ctx') bs = return (th, SHA256.update ctx' bs)

updateSequenceNumber :: HandleLike h => TlsHandle h g -> RW -> TlsM h g Word64
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

generateKeys :: HandleLike h => Side -> CipherSuite ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> TlsM h g Keys
generateKeys p cs cr sr pms = do
	let CipherSuite _ be = cs
	kl <- case be of
		AES_128_CBC_SHA -> return 20
		AES_128_CBC_SHA256 -> return 32
		_ -> throwError
			"TlsServer.generateKeys: not implemented bulk encryption"
	let (ms, cwmk, swmk, cwk, swk) = CT.makeKeys kl cr sr pms
	return $ case p of
		Client -> Keys {
			kCachedCS = cs,
			kReadCS = CipherSuite KE_NULL BE_NULL,
			kWriteCS = CipherSuite KE_NULL BE_NULL,
			kMasterSecret = ms,
			kReadMacKey = swmk, kWriteMacKey = cwmk,
			kReadKey = swk, kWriteKey = cwk }
		Server -> Keys {
			kCachedCS = cs,
			kReadCS = CipherSuite KE_NULL BE_NULL,
			kWriteCS = CipherSuite KE_NULL BE_NULL,
			kMasterSecret = ms,
			kReadMacKey = cwmk, kWriteMacKey = swmk,
			kReadKey = cwk, kWriteKey = swk }

data RW = Read | Write deriving Show

flushCipherSuiteSt :: HandleLike h => RW -> PartnerId -> TlsM h g ()
flushCipherSuiteSt p = case p of
	Read -> flushCipherSuiteRead
	Write -> flushCipherSuiteWrite

debugCipherSuite :: HandleLike h => TlsHandle h g -> String -> TlsM h g ()
debugCipherSuite t a = do
	k <- getKeys $ clientId t
	thlDebug (tlsHandle t) "moderate" . BSC.pack
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

instance (HandleLike h, CPRG g) => HandleLike (TlsHandle h g) where
	type HandleMonad (TlsHandle h g) = TlsM h g
	type DebugLevel (TlsHandle h g) = DebugLevel h
	hlPut = ((>> return ()) .) . flip tlsPut CTAppData . (, undefined)
	hlGet = (.) <$> checkAppData <*> ((fst `liftM`) .) . tlsGet . (, undefined)
	hlGetLine = ($) <$> checkAppData <*> tGetLine
	hlGetContent = ($) <$> checkAppData <*> tGetContent
	hlDebug t l = lift . lift . hlDebug (tlsHandle t) l
	hlClose t = tlsPut (t, undefined) CTAlert "\SOH\NUL" >>
		flush t >> thlClose (tlsHandle t)

tGetLine :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
tGetLine t = do
	(bct, bp) <- getBuf $ clientId t
	case splitLine bp of
		Just (l, ls) -> setBuf (clientId t) (bct, ls) >> return (bct, l)
		_ -> do	cp <- getWholeWithCt t
			setBuf (clientId t) cp
			second (bp `BS.append`) `liftM` tGetLine t

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
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
tGetContent t = do
	bcp@(_, bp) <- getBuf $ clientId t
	if BS.null bp then getWholeWithCt t else
		setBuf (clientId t) (CTNull, BS.empty) >> return bcp

checkAppData :: (HandleLike h, CPRG g) => TlsHandle h g ->
	TlsM h g (ContentType, BS.ByteString) -> TlsM h g BS.ByteString
checkAppData t m = m >>= \cp -> case cp of
	(CTAppData, ad) -> return ad
	(CTAlert, "\SOH\NUL") -> do
		_ <- tlsPut (t, undefined) CTAlert "\SOH\NUL"
		throwError "TlsHandle.checkAppData: EOF"
	_ -> do	_ <- tlsPut (t, undefined) CTAlert "\2\10"
		throwError "TlsHandle.checkAppData: not application data"
