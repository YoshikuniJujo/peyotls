{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Run (
	TH.TlsM, TH.run, TH.TlsHandleBase(..),
		chGet, ccsPut, hsPut, updateHash,
		adGet, adGetLine, adGetContent, TH.adPut, TH.adDebug, TH.adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		withRandom, flushAppData,
		TH.SettingsS, getSettingsS, setSettingsS,
		getSettingsC, setSettingsC,
		getCipherSuite, setCipherSuite,
		TH.CertSecretKey(..), TH.isRsaKey, TH.isEcdsaKey,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		TH.RW(..), flushCipherSuite, generateKeys,
		TH.Side(..), handshakeHash, finishedHash,
	ValidateHandle(..), handshakeValidate, validateAlert,
	TH.AlertLevel(..), TH.AlertDesc(..), debugCipherSuite, throw ) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first, second, (***))
import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (
	StateT, evalStateT, execStateT, get, gets, modify )
import "monads-tf" Control.Monad.Error (throwError)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ASN1.Types as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Hash.SHA256 as SHA256

import qualified Network.PeyoTLS.Handle as TH (
	TlsM, run, withRandom,
	TlsHandleBase(..), CipherSuite,
		newHandle, chGet, ccsPut, hsPut,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
		flushAppData, getAdBuf, setAdBuf,
		getCipherSuite, setCipherSuite,
		SettingsC, getSettingsC, setSettingsC,
		SettingsS, getSettingsS, setSettingsS,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		generateKeys, setKeys,
		Side(..), finishedHash,
		RW(..), flushCipherSuite,
	CertSecretKey(..), isRsaKey, isEcdsaKey,
	Alert(..), AlertLevel(..), AlertDesc(..), debugCipherSuite )

moduleName :: String
moduleName = "Network.PeyoTLS.Run"

chGet :: (HandleLike h, CPRG g) => HandshakeM h g (Either Word8 BS.ByteString)
chGet = do
	ch <- lift . flip TH.chGet 1 =<< gets fst
	case ch of
		Left w -> return $ Left w
		Right t -> Right `liftM` do
			len <- hsGet 3
			body <- hsGet . either error id $ B.decode len
			return $ BS.concat [t, len, body]

hsGet :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
hsGet n = do
	ch <- lift . flip TH.chGet n =<< gets fst
	case ch of
		Right bs -> return bs
		_ -> throw TH.ALFatal TH.ADUnexpectedMessage $
			moduleName ++ ".hsGet: not handshake"

ccsPut :: (HandleLike h, CPRG g) => Word8 -> HandshakeM h g ()
ccsPut w = lift . flip TH.ccsPut w =<< gets fst

hsPut :: (HandleLike h, CPRG g) => BS.ByteString -> HandshakeM h g ()
hsPut bs = lift . flip TH.hsPut bs =<< gets fst

adGet :: (ValidateHandle h, CPRG g) => (TH.TlsHandleBase h g -> TH.TlsM h g ()) ->
	TH.TlsHandleBase h g -> Int -> TH.TlsM h g BS.ByteString
adGet rn t n = do
	bf <- TH.getAdBuf t
	if BS.length bf >= n
	then do	let (ret, rest) = BS.splitAt n bf
		TH.setAdBuf t rest
		return ret
	else (bf `BS.append`) `liftM` TH.adGet rn t (n - BS.length bf)

type HandshakeM h g = StateT (TH.TlsHandleBase h g, SHA256.Ctx) (TH.TlsM h g)

execHandshakeM ::
	HandleLike h => h -> HandshakeM h g () -> TH.TlsM h g (TH.TlsHandleBase h g)
execHandshakeM h =
	liftM fst . ((, SHA256.init) `liftM` TH.newHandle h >>=) . execStateT

rerunHandshakeM ::
	HandleLike h => TH.TlsHandleBase h g -> HandshakeM h g a -> TH.TlsM h g a
rerunHandshakeM = flip evalStateT . (, SHA256.init)

flushAppData :: (HandleLike h, CPRG g) => HandshakeM h g Bool
flushAppData = gets fst >>=
	lift . TH.flushAppData >>= uncurry (>>) . (pushAdBuf *** return)

throw :: HandleLike h => TH.AlertLevel -> TH.AlertDesc -> String -> HandshakeM h g a
throw al ad m = throwError $ TH.Alert al ad m

withRandom :: HandleLike h => (g -> (a, g)) -> HandshakeM h g a
withRandom = lift . TH.withRandom

class HandleLike h => ValidateHandle h where
	validate :: h -> X509.CertificateStore -> X509.CertificateChain ->
		HandleMonad h [X509.FailedReason]

validateAlert :: [X509.FailedReason] -> TH.AlertDesc
validateAlert vr
	| X509.UnknownCA `elem` vr = TH.ADUnknownCa
	| X509.Expired `elem` vr = TH.ADCertificateExpired
	| X509.InFuture `elem` vr = TH.ADCertificateExpired
	| otherwise = TH.ADCertificateUnknown

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

handshakeValidate :: ValidateHandle h =>
	X509.CertificateStore -> X509.CertificateChain ->
	HandshakeM h g [X509.FailedReason]
handshakeValidate cs cc@(X509.CertificateChain c) = gets fst >>= \t -> do
	modify . first $ const t { TH.names = certNames . X509.getCertificate $ head c }
	lift . lift . lift $ validate (TH.tlsHandle t) cs cc

certNames :: X509.Certificate -> [String]
certNames = nms
	where
	nms c = maybe id (:) <$> nms_ <*> ans $ c
	nms_ = (ASN1.asn1CharacterToString =<<) .
		X509.getDnElement X509.DnCommonName . X509.certSubjectDN
	ans = maybe [] ((\ns -> [s | X509.AltNameDNS s <- ns])
				. \(X509.ExtSubjectAltName ns) -> ns)
			. X509.extensionGet . X509.certExtensions

setCipherSuite :: HandleLike h => TH.CipherSuite -> HandshakeM h g ()
setCipherSuite cs = gets fst >>= lift . flip TH.setCipherSuite cs

getCipherSuite :: HandleLike h => HandshakeM h g TH.CipherSuite
getCipherSuite = gets fst >>= lift . TH.getCipherSuite

flushCipherSuite :: (HandleLike h, CPRG g) => TH.RW -> HandshakeM h g ()
flushCipherSuite p = gets fst >>= lift . TH.flushCipherSuite p

debugCipherSuite :: HandleLike h => String -> HandshakeM h g ()
debugCipherSuite m = do t <- gets fst; lift $ TH.debugCipherSuite t m

generateKeys :: HandleLike h => TH.Side ->
	(BS.ByteString, BS.ByteString) -> BS.ByteString -> HandshakeM h g ()
generateKeys p (cr, sr) pms = do
	t <- gets fst
	cs <- lift $ TH.getCipherSuite t
	k <- lift $ TH.generateKeys t p cs cr sr pms
	lift $ TH.setKeys t k

handshakeHash :: HandleLike h => HandshakeM h g BS.ByteString
handshakeHash = SHA256.finalize `liftM` gets snd

finishedHash :: (HandleLike h, CPRG g) => TH.Side -> HandshakeM h g BS.ByteString
finishedHash p = get >>= lift . flip (uncurry TH.finishedHash) p

getClFinished, getSvFinished :: HandleLike h => HandshakeM h g BS.ByteString
getClFinished = gets fst >>= lift . TH.getClFinished
getSvFinished = gets fst >>= lift . TH.getSvFinished

setClFinished, setSvFinished :: HandleLike h => BS.ByteString -> HandshakeM h g ()
setClFinished cf = gets fst >>= lift . flip TH.setClFinished cf
setSvFinished cf = gets fst >>= lift . flip TH.setSvFinished cf

getSettingsS :: HandleLike h => HandshakeM h g TH.SettingsS
getSettingsS = gets fst >>= lift . TH.getSettingsS

setSettingsS :: HandleLike h => TH.SettingsS -> HandshakeM h g ()
setSettingsS is = gets fst >>= lift . flip TH.setSettingsS is

getSettingsC :: HandleLike h => HandshakeM h g TH.SettingsC
getSettingsC = gets fst >>= lift . TH.getSettingsC

setSettingsC :: HandleLike h => TH.SettingsC -> HandshakeM h g ()
setSettingsC s = gets fst >>= lift . flip TH.setSettingsC s

pushAdBuf :: HandleLike h => BS.ByteString -> HandshakeM h g ()
pushAdBuf bs = do
	bf <- gets fst >>= lift . TH.getAdBuf
	gets fst >>= lift . flip TH.setAdBuf (bf `BS.append` bs)

updateHash :: HandleLike h => BS.ByteString -> HandshakeM h g ()
updateHash = modify . second . flip SHA256.update

adGetLine :: (ValidateHandle h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) -> TH.TlsHandleBase h g ->
	TH.TlsM h g BS.ByteString
adGetLine rn t = do
	bf <- TH.getAdBuf t
	if '\n' `BSC.elem` bf || '\r' `BSC.elem` bf
	then do	let (ret, rest) = splitOneLine bf
		TH.setAdBuf t $ BS.tail rest
		return ret
	else (bf `BS.append`) `liftM` TH.adGetLine rn t

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

adGetContent :: (ValidateHandle h, CPRG g) =>
	(TH.TlsHandleBase h g -> TH.TlsM h g ()) ->
	TH.TlsHandleBase h g -> TH.TlsM h g BS.ByteString
adGetContent rn t = do
	bf <- TH.getAdBuf t
	if BS.null bf
	then TH.adGetContent rn t
	else do	TH.setAdBuf t ""
		return bf
