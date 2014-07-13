{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Run ( H.debug,
	H.TlsM, H.run, H.HandleBase,
		adGet, adGetLine, adGetContent, H.adPut, H.adDebug, H.adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM, withRandom,
		chGet, ccsPut, hsPut, updateHash, flushAd,
		H.CertSecretKey(..), H.isRsaKey, H.isEcdsaKey,
		H.SettingsC, getSettingsC, setSettingsC,
		H.SettingsS, getSettingsS, setSettingsS,
		getCipherSuite, setCipherSuite,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		H.getNames,
		H.RW(..), flushCipherSuite, makeKeys,
		H.Side(..), handshakeHash, finishedHash,
	H.ValidateHandle(..), handshakeValidate, validateAlert,
	H.AlertLevel(..), H.AlertDesc(..), debugCipherSuite, throw ) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (second, (***))
import Control.Monad (liftM)
import "monads-tf" Control.Monad.Reader (ReaderT, runReaderT, lift, ask)
import "monads-tf" Control.Monad.State (StateT, evalStateT, get, modify )
import "monads-tf" Control.Monad.Error (throwError)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ASN1.Types as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Hash.SHA256 as SHA256

import qualified Network.PeyoTLS.Handle as H ( debug,
	TlsM, run, withRandom,
	HandleBase, CipherSuite,
		newHandle, chGet, ccsPut, hsPut,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
		flushAd, getBuf, setBuf,
		getCipherSuite, setCipherSuite,
		SettingsC, getSettingsC, setSettingsC,
		SettingsS, getSettingsS, setSettingsS,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		makeKeys, setKeys,
		getNames, setNames,
		Side(..), finishedHash,
		RW(..), flushCipherSuite,
	ValidateHandle(..), tValidate,
	CertSecretKey(..), isRsaKey, isEcdsaKey,
	Alert(..), AlertLevel(..), AlertDesc(..), debugCipherSuite )

modNm :: String
modNm = "Network.PeyoTLS.Run"

type RenegoProc h g = H.HandleBase h g -> H.TlsM h g ()

adGet :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> H.HandleBase h g -> Int -> H.TlsM h g BS.ByteString
adGet rp t n = H.getBuf t >>= \b -> if BS.length b >= n
	then uncurry (>>) . (H.setBuf t *** return) $ BS.splitAt n b
	else BS.append b `liftM` H.adGet rp t (n - BS.length b)

adGetLine :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> H.HandleBase h g -> H.TlsM h g BS.ByteString
adGetLine rp t = H.getBuf t >>= \b -> if '\n' `BSC.elem` b || '\r' `BSC.elem` b
	then uncurry (>>) . (H.setBuf t *** return) $ case BSC.span (/= '\r') b of
		(_, "") -> second BS.tail $ BSC.span (/= '\n') b
		(l, ls) -> case BSC.uncons ls of
			Just ('\r', ls') -> case BSC.uncons ls' of
				Just ('\n', ls'') -> (l, ls'')
				_ -> (l, ls')
			_ -> (l, ls)
	else (b `BS.append`) `liftM` H.adGetLine rp t

adGetContent :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> H.HandleBase h g -> H.TlsM h g BS.ByteString
adGetContent rp t = H.getBuf t >>= \b ->
	if BS.null b then H.adGetContent rp t else H.setBuf t "" >> return b

type HandshakeM h g =
	ReaderT (H.HandleBase h g) (StateT SHA256.Ctx (H.TlsM h g))

execHandshakeM ::
	HandleLike h => h -> HandshakeM h g () -> H.TlsM h g (H.HandleBase h g)
execHandshakeM h m = do
	t <- H.newHandle h
	m `runReaderT` t `evalStateT` SHA256.init
	return t
--	liftM fst . ((, SHA256.init) `liftM` H.newHandle h >>=) . execStateT

rerunHandshakeM ::
	HandleLike h => H.HandleBase h g -> HandshakeM h g a -> H.TlsM h g a
rerunHandshakeM t m = m `runReaderT` t `evalStateT` SHA256.init

withRandom :: HandleLike h => (g -> (a, g)) -> HandshakeM h g a
withRandom = lift . lift . H.withRandom

chGet :: (HandleLike h, CPRG g) => HandshakeM h g (Either Word8 BS.ByteString)
chGet = ask >>= lift . lift . flip H.chGet 1 >>= \ch -> case ch of
	Left w -> return $ Left w
	Right t -> Right `liftM` do
		len <- hsGet 3
		body <- hsGet . either error id $ B.decode len
		return $ BS.concat [t, len, body]

hsGet :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
hsGet n = ask >>= lift . lift . flip H.chGet n >>= \ch -> case ch of
	Right bs -> return bs
	_ -> throw H.ALFatal H.ADUnexMsg $ modNm ++ ".hsGet: not handshake"

ccsPut :: (HandleLike h, CPRG g) => Word8 -> HandshakeM h g ()
ccsPut = (ask >>=) . ((lift . lift) .) . flip H.ccsPut

hsPut :: (HandleLike h, CPRG g) => BS.ByteString -> HandshakeM h g ()
hsPut = (ask >>=) . ((lift . lift) .) . flip H.hsPut

updateHash :: HandleLike h => BS.ByteString -> HandshakeM h g ()
updateHash = modify . flip SHA256.update

flushAd :: (HandleLike h, CPRG g) => HandshakeM h g Bool
flushAd = ask >>= lift . lift . H.flushAd >>= uncurry (>>) . (push *** return)
	where push bs = ask >>= lift . lift . H.getBuf >>=
		(ask >>=) . ((lift . lift) .) . flip H.setBuf . (`BS.append` bs)

getSettingsC :: HandleLike h => HandshakeM h g H.SettingsC
getSettingsC = ask >>= lift . lift . H.getSettingsC

setSettingsC :: HandleLike h => H.SettingsC -> HandshakeM h g ()
setSettingsC = (ask >>=) . ((lift . lift) .) . flip H.setSettingsC

getSettingsS :: HandleLike h => HandshakeM h g H.SettingsS
getSettingsS = ask >>= lift . lift . H.getSettingsS

setSettingsS :: HandleLike h => H.SettingsS -> HandshakeM h g ()
setSettingsS = (ask >>=) . ((lift . lift) .) . flip H.setSettingsS

getCipherSuite :: HandleLike h => HandshakeM h g H.CipherSuite
getCipherSuite = ask >>= lift . lift . H.getCipherSuite

setCipherSuite :: HandleLike h => H.CipherSuite -> HandshakeM h g ()
setCipherSuite = (ask >>=) . ((lift . lift) .) . flip H.setCipherSuite

getClFinished, getSvFinished :: HandleLike h => HandshakeM h g BS.ByteString
getClFinished = ask >>= lift . lift . H.getClFinished
getSvFinished = ask >>= lift . lift . H.getSvFinished

setClFinished, setSvFinished :: HandleLike h => BS.ByteString -> HandshakeM h g ()
setClFinished = (ask >>=) . ((lift . lift) .) . flip H.setClFinished
setSvFinished = (ask >>=) . ((lift . lift) .) . flip H.setSvFinished

flushCipherSuite :: (HandleLike h, CPRG g) => H.RW -> HandshakeM h g ()
flushCipherSuite = (ask >>=) . ((lift . lift) .) . H.flushCipherSuite

makeKeys :: HandleLike h => H.Side ->
	(BS.ByteString, BS.ByteString) -> BS.ByteString -> HandshakeM h g ()
makeKeys s (cr, sr) pms = ask >>= \t -> lift . lift $
	H.getCipherSuite t >>= H.makeKeys t s cr sr pms >>= H.setKeys t

handshakeHash :: HandleLike h => HandshakeM h g BS.ByteString
handshakeHash = SHA256.finalize `liftM` get

finishedHash :: (HandleLike h, CPRG g) => H.Side -> HandshakeM h g BS.ByteString
finishedHash s = do
	t <- ask
	h <- get
	lift . lift $ H.finishedHash s t (SHA256.finalize h)

validateAlert :: [X509.FailedReason] -> H.AlertDesc
validateAlert vr
	| X509.UnknownCA `elem` vr = H.ADUnknownCa
	| X509.Expired `elem` vr = H.ADCertificateExpired
	| X509.InFuture `elem` vr = H.ADCertificateExpired
	| otherwise = H.ADCertificateUnknown

handshakeValidate :: H.ValidateHandle h => X509.CertificateStore ->
	X509.CertificateChain -> HandshakeM h g [X509.FailedReason]
handshakeValidate cs cc@(X509.CertificateChain (c : _)) =  ask >>= \t -> do
	lift . lift . H.setNames t . certNames $ X509.getCertificate c
	lift . lift $ H.tValidate t cs cc
handshakeValidate _ _ = error $ modNm ++ ".handshakeValidate: empty cert chain"

certNames :: X509.Certificate -> [String]
certNames = maybe id (:) <$> nm <*> nms
	where
	nm = (ASN1.asn1CharacterToString =<<) .
		X509.getDnElement X509.DnCommonName . X509.certSubjectDN
	nms = maybe [] ((\ns -> [s | X509.AltNameDNS s <- ns])
				. \(X509.ExtSubjectAltName ns) -> ns)
			. X509.extensionGet . X509.certExtensions

debugCipherSuite :: HandleLike h => String -> HandshakeM h g ()
debugCipherSuite = (ask >>=) . ((lift . lift) .) . flip H.debugCipherSuite

throw :: HandleLike h => H.AlertLevel -> H.AlertDesc -> String -> HandshakeM h g a
throw = ((throwError .) .) . H.Alert
