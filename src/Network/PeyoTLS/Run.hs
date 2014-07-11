{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports, TypeFamilies #-}

module Network.PeyoTLS.Run (
	updateHash,
	hsGet, hsPut,
	ccsGet, ccsPut,
	adGet, adGetLine, adGetContent,
	TH.isRsaKey, TH.isEcdsaKey,
	checkAppData,
	TH.TlsM, TH.run, HandshakeM, execHandshakeM, rerunHandshakeM,
	withRandom, randomByteString,
	ValidateHandle(..), handshakeValidate,
	TH.TlsHandleBase(..), TH.ContentType(..),
		getCipherSuite, setCipherSuite, flushCipherSuite, debugCipherSuite,
		tlsGetContentType, tlsGet, tlsPut, tlsPutNH,
		generateKeys,
	TH.Alert(..), TH.AlertLevel(..), TH.AlertDesc(..),
	TH.Side(..), TH.RW(..), handshakeHash, finishedHash, throwError,
	TH.hlPut_, TH.hlDebug_, TH.hlClose_,
	TH.tGetLine, TH.tGetContent, tlsGet_, tlsPut_, tlsGet__,
	tGetLine_, tGetContent_,
	getClFinished, getSvFinished, setClFinished, setSvFinished,

	resetSequenceNumber,

	getSettingsS, setSettingsS, TH.SettingsS,
	getSettingsC, setSettingsC, TH.Settings,
	flushAppData,

	getAdBuf, setAdBuf,
	pushAdBuf,

	TH.CertSecretKey(..)
	) where

import Prelude hiding (read)

import Data.Word
import Control.Applicative
import qualified Data.ASN1.Types as ASN1
import Control.Arrow (first, second, (***))
import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (
	StateT, evalStateT, execStateT, get, gets, put, modify)
import qualified "monads-tf" Control.Monad.Error as E (throwError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.Hash.SHA256 as SHA256

import qualified Network.PeyoTLS.Handle as TH (
	updateHash,
	TlsM, Alert(..), AlertLevel(..), AlertDesc(..),
		run, withRandom, randomByteString,
	TlsHandleBase(..), ContentType(..),
		newHandle, getContentType, tlsGet, tlsPut, generateKeys,
		debugCipherSuite,
		getCipherSuiteSt, setCipherSuiteSt, flushCipherSuiteSt, setKeys,
	Side(..), RW(..), finishedHash, handshakeHash, CipherSuite(..),
	hlPut_, hlDebug_, hlClose_, tGetContent, tGetLine, tGetLine_,
	getClientFinishedT, setClientFinishedT,
	getServerFinishedT, setServerFinishedT,

	resetSequenceNumber,

	getSettingsT, setSettingsT, Settings,
	getInitSetT, setInitSetT, SettingsS,
	tlsGet_,
	flushAppData,
	getAdBufT,
	setAdBufT,

	CertSecretKey(..), isRsaKey, isEcdsaKey,
	)

import qualified Codec.Bytable.BigEndian as B

moduleName :: String
moduleName = "Network.PeyoTLS.Run"

instance (HandleLike h, CPRG g) => HandleLike (TH.TlsHandleBase h g) where
	type HandleMonad (TH.TlsHandleBase h g) = TH.TlsM h g
	type DebugLevel (TH.TlsHandleBase h g) = DebugLevel h
	hlPut = TH.hlPut_
	hlGet = (.) <$> checkAppData <*> ((fst `liftM`) .)
		. tlsGet__ . (, undefined)
	hlGetLine = ($) <$> checkAppData <*> TH.tGetLine
	hlGetContent = ($) <$> checkAppData <*> TH.tGetContent
	hlDebug = TH.hlDebug_
	hlClose = TH.hlClose_

checkAppData :: (HandleLike h, CPRG g) => TH.TlsHandleBase h g ->
	TH.TlsM h g (TH.ContentType, BS.ByteString) -> TH.TlsM h g BS.ByteString
checkAppData t m = m >>= \cp -> case cp of
	(TH.CTAppData, ad) -> return ad
	(TH.CTAlert, "\SOH\NUL") -> do
		_ <- tlsPut_ (t, undefined) TH.CTAlert "\SOH\NUL"
		E.throwError . strMsg $
			moduleName ++ ".checkAppData: EOF"
	(TH.CTHandshake, _) -> E.throwError "bad"
	_ -> do	_ <- tlsPut_ (t, undefined) TH.CTAlert "\2\10"
		E.throwError . strMsg $
			moduleName ++ ".checkAppData: not application data"

resetSequenceNumber :: HandleLike h => TH.RW -> HandshakeM h g ()
resetSequenceNumber rw = gets fst >>= lift . flip TH.resetSequenceNumber rw

tlsGet_ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) ->
	(TH.TlsHandleBase h g, SHA256.Ctx) -> Int -> TH.TlsM h g ((TH.ContentType, BS.ByteString), (TH.TlsHandleBase h g, SHA256.Ctx))
tlsGet_ = TH.tlsGet_

tlsGet__ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandleBase h g, SHA256.Ctx) -> Int -> TH.TlsM h g ((TH.ContentType, BS.ByteString), (TH.TlsHandleBase h g, SHA256.Ctx))
tlsGet__ = TH.tlsGet True

tGetLine_, tGetContent_ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) ->
	TH.TlsHandleBase h g -> TH.TlsM h g (TH.ContentType, BS.ByteString)
tGetLine_ = TH.tGetLine_

flushAppData_ :: (HandleLike h, CPRG g) => HandshakeM h g (BS.ByteString, Bool)
flushAppData_ = gets fst >>= lift . TH.flushAppData

tGetContent_ rn t = do
	ct <- TH.getContentType t
	case ct of
		TH.CTHandshake -> rn t >> tGetContent_ rn t
		_ -> TH.tGetContent t

tlsPut_ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandleBase h g, SHA256.Ctx) -> TH.ContentType -> BS.ByteString -> TH.TlsM h g (TH.TlsHandleBase h g, SHA256.Ctx)
tlsPut_ = TH.tlsPut True

throwError :: HandleLike h =>
	TH.AlertLevel -> TH.AlertDesc -> String -> HandshakeM h g a
throwError al ad m = E.throwError $ TH.Alert al ad m

type HandshakeM h g = StateT (TH.TlsHandleBase h g, SHA256.Ctx) (TH.TlsM h g)

execHandshakeM :: HandleLike h =>
	h -> HandshakeM h g () -> TH.TlsM h g (TH.TlsHandleBase h g)
execHandshakeM h =
	liftM fst . ((, SHA256.init) `liftM` TH.newHandle h >>=) . execStateT

rerunHandshakeM ::
	HandleLike h => TH.TlsHandleBase h g -> HandshakeM h g a -> TH.TlsM h g a
rerunHandshakeM t hm = evalStateT hm (t, SHA256.init)

withRandom :: HandleLike h => (g -> (a, g)) -> HandshakeM h g a
withRandom = lift . TH.withRandom

randomByteString :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
randomByteString = lift . TH.randomByteString

class HandleLike h => ValidateHandle h where
	validate :: h -> X509.CertificateStore -> X509.CertificateChain ->
		HandleMonad h [X509.FailedReason]

instance ValidateHandle Handle where
	validate _ cs (X509.CertificateChain cc) =
		X509.validate X509.HashSHA256 X509.defaultHooks
			validationChecks cs validationCache ("", "") $
				X509.CertificateChain cc
		where
		validationCache = X509.ValidationCache
			(\_ _ _ -> return X509.ValidationCacheUnknown)
			(\_ _ _ -> return ())
		validationChecks = X509.defaultChecks { X509.checkFQHN = False }

certNames :: X509.Certificate -> [String]
certNames = nms
	where
	nms c = maybe id (:) <$> nms_ <*> ans $ c
	nms_ = (ASN1.asn1CharacterToString =<<) .
		X509.getDnElement X509.DnCommonName . X509.certSubjectDN
	ans = maybe [] ((\ns -> [s | X509.AltNameDNS s <- ns])
				. \(X509.ExtSubjectAltName ns) -> ns)
			. X509.extensionGet . X509.certExtensions

handshakeValidate :: ValidateHandle h =>
	X509.CertificateStore -> X509.CertificateChain ->
	HandshakeM h g [X509.FailedReason]
handshakeValidate cs cc@(X509.CertificateChain c) = gets fst >>= \t -> do
	modify . first $ const t { TH.names = certNames . X509.getCertificate $ head c }
	lift . lift . lift $ validate (TH.tlsHandle t) cs cc

setCipherSuite :: HandleLike h => TH.CipherSuite -> HandshakeM h g ()
setCipherSuite cs = do
	t <- gets fst
	lift $ TH.setCipherSuiteSt (TH.clientId t) cs

getCipherSuite :: HandleLike h => HandshakeM h g TH.CipherSuite
getCipherSuite = do
	t <- gets fst
	lift . TH.getCipherSuiteSt $ TH.clientId t

flushCipherSuite :: (HandleLike h, CPRG g) => TH.RW -> HandshakeM h g ()
flushCipherSuite p = do
	t <- gets fst
	lift $ TH.flushCipherSuiteSt p (TH.clientId t)

debugCipherSuite :: HandleLike h => String -> HandshakeM h g ()
debugCipherSuite m = do t <- gets fst; lift $ TH.debugCipherSuite t m

tlsGetContentType :: (HandleLike h, CPRG g) => HandshakeM h g TH.ContentType
tlsGetContentType = gets fst >>= lift . TH.getContentType

tlsGet :: (HandleLike h, CPRG g) => Bool -> Int -> HandshakeM h g BS.ByteString
tlsGet b n = do ((_, bs), t') <- lift . flip (TH.tlsGet b) n =<< get; put t'; return bs

tlsPut, tlsPutNH :: (HandleLike h, CPRG g) =>
	TH.ContentType -> BS.ByteString -> HandshakeM h g ()
tlsPut ct bs = get >>= lift . (\t -> TH.tlsPut True t ct bs) >>= put
tlsPutNH ct bs = get >>= lift . (\t -> TH.tlsPut False t ct bs) >>= put

generateKeys :: HandleLike h => TH.Side ->
	(BS.ByteString, BS.ByteString) -> BS.ByteString -> HandshakeM h g ()
generateKeys p (cr, sr) pms = do
	t <- gets fst
	cs <- lift $ TH.getCipherSuiteSt (TH.clientId t)
	k <- lift $ TH.generateKeys t p cs cr sr pms
	lift $ TH.setKeys (TH.clientId t) k

handshakeHash :: HandleLike h => HandshakeM h g BS.ByteString
handshakeHash = get >>= lift . TH.handshakeHash

finishedHash :: (HandleLike h, CPRG g) => TH.Side -> HandshakeM h g BS.ByteString
finishedHash p = get >>= lift . flip TH.finishedHash p

getClFinished, getSvFinished :: HandleLike h => HandshakeM h g BS.ByteString
getClFinished = gets fst >>= lift . TH.getClientFinishedT
getSvFinished = gets fst >>= lift . TH.getServerFinishedT

setClFinished, setSvFinished :: HandleLike h => BS.ByteString -> HandshakeM h g ()
setClFinished cf = gets fst >>= lift . flip TH.setClientFinishedT cf
setSvFinished cf = gets fst >>= lift . flip TH.setServerFinishedT cf

getSettingsS :: HandleLike h => HandshakeM h g TH.SettingsS
getSettingsS = gets fst >>= lift . TH.getInitSetT

getSettingsC :: HandleLike h => HandshakeM h g TH.Settings
getSettingsC = gets fst >>= lift . TH.getSettingsT

setSettingsS :: HandleLike h => TH.SettingsS -> HandshakeM h g ()
setSettingsS is = gets fst >>= lift . flip TH.setInitSetT is

setSettingsC :: HandleLike h => TH.Settings -> HandshakeM h g ()
setSettingsC is = gets fst >>= lift . flip TH.setSettingsT is

getAdBuf :: HandleLike h => TH.TlsHandleBase h g -> TH.TlsM h g BS.ByteString
getAdBuf = TH.getAdBufT

setAdBuf :: HandleLike h =>
	TH.TlsHandleBase h g -> BS.ByteString -> TH.TlsM h g ()
setAdBuf = TH.setAdBufT

getAdBufH :: HandleLike h => HandshakeM h g BS.ByteString
getAdBufH = gets fst >>= lift . TH.getAdBufT

setAdBufH :: HandleLike h => BS.ByteString -> HandshakeM h g ()
setAdBufH bs = gets fst >>= lift . flip TH.setAdBufT bs

pushAdBuf :: HandleLike h => BS.ByteString -> HandshakeM h g ()
pushAdBuf bs = do
	bf <- getAdBufH
	setAdBufH $ bf `BS.append` bs

adGet, hlGetRn_ :: (ValidateHandle h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) -> TH.TlsHandleBase h g -> Int ->
	TH.TlsM h g BS.ByteString
adGet = hlGetRn
hlGetRn_ rh = (.) <$> checkAppData <*> ((fst `liftM`) .) . TH.tlsGet_ rh
	. (, undefined)

hlGetLineRn_, hlGetContentRn_, adGetLine, adGetContent ::
	(ValidateHandle h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) -> TH.TlsHandleBase h g -> TH.TlsM h g BS.ByteString
adGetLine = hlGetLineRn
hlGetLineRn_ rh = ($) <$> checkAppData <*> tGetLine_ rh
adGetContent = hlGetContentRn
hlGetContentRn_ rh = ($) <$> checkAppData <*> tGetContent_ rh

hsGet :: (HandleLike h, CPRG g) => HandshakeM h g BS.ByteString
hsGet = do
	ct <- tlsGetContentType
	case ct of
		TH.CTHandshake -> do
			t <- tlsGet True 1
			len <- tlsGet (t /= "\0") 3
			body <- tlsGet True . either error id $ B.decode len
			return $ BS.concat [t, len, body]
		_ -> throwError
			TH.ALFatal TH.ADUnexpectedMessage $
			"HandshakeBase.readHandshake: not handshake: " ++ show ct

ccsGet :: (HandleLike h, CPRG g) => HandshakeM h g Word8
ccsGet = do
	ct <- tlsGetContentType
	bs <- case ct of
		TH.CTCCSpec -> tlsGet True 1
		_ -> throwError TH.ALFatal TH.ADUnexpectedMessage $
			"HandshakeBase.getChangeCipherSpec: " ++
			"not change cipher spec: " ++ show ct
	resetSequenceNumber TH.Read
	return $ let [w] = BS.unpack bs in w

hsPut :: (HandleLike h, CPRG g) => BS.ByteString -> HandshakeM h g ()
hsPut = tlsPut TH.CTHandshake

ccsPut :: (HandleLike h, CPRG g) => Word8 -> HandshakeM h g ()
ccsPut w = do
	tlsPut TH.CTCCSpec $ BS.pack [w]
	resetSequenceNumber TH.Write

updateHash :: HandleLike h => BS.ByteString -> HandshakeM h g ()
updateHash bs = get >>= lift . flip TH.updateHash bs >>= put

flushAppData :: (HandleLike h, CPRG g) => HandshakeM h g Bool
flushAppData = uncurry (>>) . (pushAdBuf *** return) =<< flushAppData_

hlGetRn :: (ValidateHandle h, CPRG g) => (TH.TlsHandleBase h g -> TH.TlsM h g ()) ->
	TH.TlsHandleBase h g -> Int -> TH.TlsM h g BS.ByteString
hlGetRn rn t n = do
	bf <- getAdBuf t
	if BS.length bf >= n
	then do	let (ret, rest) = BS.splitAt n bf
		setAdBuf t rest
		return ret
	else (bf `BS.append`) `liftM` hlGetRn_ rn t (n - BS.length bf)

hlGetLineRn :: (ValidateHandle h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) -> TH.TlsHandleBase h g ->
	TH.TlsM h g BS.ByteString
hlGetLineRn rn t = do
	bf <- getAdBuf t
	if '\n' `BSC.elem` bf || '\r' `BSC.elem` bf
	then do	let (ret, rest) = splitOneLine bf
		setAdBuf t $ BS.tail rest
		return ret
	else (bf `BS.append`) `liftM` hlGetLineRn_ rn t

splitOneLine :: BS.ByteString -> (BS.ByteString, BS.ByteString)
splitOneLine bs = case BSC.span (/= '\r') bs of
	(_, "") -> second BS.tail $ BSC.span (/= '\n') bs
	(l, ls) -> (l, dropRet ls)

dropRet :: BS.ByteString -> BS.ByteString
dropRet bs = case BSC.uncons bs of
	Just ('\r', bs') -> case BSC.uncons bs' of
		Just ('\n', bs'') -> bs''
		_ -> bs'
	_ -> bs

hlGetContentRn :: (ValidateHandle h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) ->
	TH.TlsHandleBase h g -> TH.TlsM h g BS.ByteString
hlGetContentRn rn t = do
	bf <- getAdBuf t
	if BS.null bf
	then hlGetContentRn_ rn t
	else do	setAdBuf t ""
		return bf
