{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Run (
	H.TlsM, H.run, H.TlsHandleBase(..),
		adGet, adGetLine, adGetContent, H.adPut, H.adDebug, H.adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM, withRandom,
		chGet, ccsPut, hsPut, updateHash, flushAd,
		H.CertSecretKey(..), H.isRsaKey, H.isEcdsaKey,
		H.SettingsC, getSettingsC, setSettingsC,
		H.SettingsS, getSettingsS, setSettingsS,
		getCipherSuite, setCipherSuite,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		H.RW(..), flushCipherSuite, makeKeys,
		H.Side(..), handshakeHash, finishedHash,
	ValidateHandle(..), handshakeValidate, validateAlert,
	H.AlertLevel(..), H.AlertDesc(..), debugCipherSuite, throw ) where

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

import qualified Network.PeyoTLS.Handle as H (
	TlsM, run, withRandom,
	TlsHandleBase(..), CipherSuite,
		newHandle, chGet, ccsPut, hsPut,
		adGet, adGetLine, adGetContent, adPut, adDebug, adClose,
		flushAd, getBuf, setBuf,
		getCipherSuite, setCipherSuite,
		SettingsC, getSettingsC, setSettingsC,
		SettingsS, getSettingsS, setSettingsS,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		makeKeys, setKeys,
		Side(..), finishedHash,
		RW(..), flushCipherSuite,
	CertSecretKey(..), isRsaKey, isEcdsaKey,
	Alert(..), AlertLevel(..), AlertDesc(..), debugCipherSuite )

modNm :: String
modNm = "Network.PeyoTLS.Run"

type RenegoProc h g = H.TlsHandleBase h g -> H.TlsM h g ()

adGet :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> H.TlsHandleBase h g -> Int -> H.TlsM h g BS.ByteString
adGet rp t n = H.getBuf t >>= \b -> if BS.length b >= n
	then uncurry (>>) . (H.setBuf t *** return) $ BS.splitAt n b
	else BS.append b `liftM` H.adGet rp t (n - BS.length b)

adGetLine :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> H.TlsHandleBase h g -> H.TlsM h g BS.ByteString
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
	RenegoProc h g -> H.TlsHandleBase h g -> H.TlsM h g BS.ByteString
adGetContent rp t = H.getBuf t >>= \b ->
	if BS.null b then H.adGetContent rp t else H.setBuf t "" >> return b

type HandshakeM h g = StateT (H.TlsHandleBase h g, SHA256.Ctx) (H.TlsM h g)

execHandshakeM ::
	HandleLike h => h -> HandshakeM h g () -> H.TlsM h g (H.TlsHandleBase h g)
execHandshakeM h =
	liftM fst . ((, SHA256.init) `liftM` H.newHandle h >>=) . execStateT

rerunHandshakeM ::
	HandleLike h => H.TlsHandleBase h g -> HandshakeM h g a -> H.TlsM h g a
rerunHandshakeM = flip evalStateT . (, SHA256.init)

withRandom :: HandleLike h => (g -> (a, g)) -> HandshakeM h g a
withRandom = lift . H.withRandom

chGet :: (HandleLike h, CPRG g) => HandshakeM h g (Either Word8 BS.ByteString)
chGet = gets fst >>= lift . flip H.chGet 1 >>= \ch -> case ch of
	Left w -> return $ Left w
	Right t -> Right `liftM` do
		len <- hsGet 3
		body <- hsGet . either error id $ B.decode len
		return $ BS.concat [t, len, body]

hsGet :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
hsGet n = gets fst >>= lift . flip H.chGet n >>= \ch -> case ch of
	Right bs -> return bs
	_ -> throw H.ALFatal H.ADUnexMsg $ modNm ++ ".hsGet: not handshake"

ccsPut :: (HandleLike h, CPRG g) => Word8 -> HandshakeM h g ()
ccsPut = (gets fst >>=) . (lift .) . flip H.ccsPut

hsPut :: (HandleLike h, CPRG g) => BS.ByteString -> HandshakeM h g ()
hsPut = (gets fst >>=) . (lift .) . flip H.hsPut

updateHash :: HandleLike h => BS.ByteString -> HandshakeM h g ()
updateHash = modify . second . flip SHA256.update

flushAd :: (HandleLike h, CPRG g) => HandshakeM h g Bool
flushAd = gets fst >>= lift . H.flushAd >>= uncurry (>>) . (push *** return)
	where push bs = gets fst >>= lift . H.getBuf >>=
		(gets fst >>=) . (lift .) . flip H.setBuf . (`BS.append` bs)

getSettingsC :: HandleLike h => HandshakeM h g H.SettingsC
getSettingsC = gets fst >>= lift . H.getSettingsC

setSettingsC :: HandleLike h => H.SettingsC -> HandshakeM h g ()
setSettingsC = (gets fst >>=) . (lift .) . flip H.setSettingsC

getSettingsS :: HandleLike h => HandshakeM h g H.SettingsS
getSettingsS = gets fst >>= lift . H.getSettingsS

setSettingsS :: HandleLike h => H.SettingsS -> HandshakeM h g ()
setSettingsS = (gets fst >>=) . (lift .) . flip H.setSettingsS

getCipherSuite :: HandleLike h => HandshakeM h g H.CipherSuite
getCipherSuite = gets fst >>= lift . H.getCipherSuite

setCipherSuite :: HandleLike h => H.CipherSuite -> HandshakeM h g ()
setCipherSuite = (gets fst >>=) . (lift .) . flip H.setCipherSuite

getClFinished, getSvFinished :: HandleLike h => HandshakeM h g BS.ByteString
getClFinished = gets fst >>= lift . H.getClFinished
getSvFinished = gets fst >>= lift . H.getSvFinished

setClFinished, setSvFinished :: HandleLike h => BS.ByteString -> HandshakeM h g ()
setClFinished = (gets fst >>=) . (lift .) . flip H.setClFinished
setSvFinished = (gets fst >>=) . (lift .) . flip H.setSvFinished

flushCipherSuite :: (HandleLike h, CPRG g) => H.RW -> HandshakeM h g ()
flushCipherSuite = (gets fst >>=) . (lift .) . H.flushCipherSuite

makeKeys :: HandleLike h => H.Side ->
	(BS.ByteString, BS.ByteString) -> BS.ByteString -> HandshakeM h g ()
makeKeys s (cr, sr) pms = gets fst >>= \t -> lift $
	H.getCipherSuite t >>= H.makeKeys t s cr sr pms >>= H.setKeys t

handshakeHash :: HandleLike h => HandshakeM h g BS.ByteString
handshakeHash = SHA256.finalize `liftM` gets snd

finishedHash :: (HandleLike h, CPRG g) => H.Side -> HandshakeM h g BS.ByteString
finishedHash s = get >>= lift . uncurry (H.finishedHash s) . second SHA256.finalize

class HandleLike h => ValidateHandle h where
	validate :: h -> X509.CertificateStore -> X509.CertificateChain ->
		HandleMonad h [X509.FailedReason]

validateAlert :: [X509.FailedReason] -> H.AlertDesc
validateAlert vr
	| X509.UnknownCA `elem` vr = H.ADUnknownCa
	| X509.Expired `elem` vr = H.ADCertificateExpired
	| X509.InFuture `elem` vr = H.ADCertificateExpired
	| otherwise = H.ADCertificateUnknown

instance ValidateHandle Handle where
	validate _ cs cc =
		X509.validate X509.HashSHA256 X509.defaultHooks ch cs ca ("", "") cc
		where
		ch = X509.defaultChecks { X509.checkFQHN = False }
		ca = X509.ValidationCache
			(\_ _ _ -> return X509.ValidationCacheUnknown)
			(\_ _ _ -> return ())

handshakeValidate :: ValidateHandle h => X509.CertificateStore ->
	X509.CertificateChain -> HandshakeM h g [X509.FailedReason]
handshakeValidate cs cc@(X509.CertificateChain (c : _)) = gets fst >>= \t -> do
	modify . first $ const t { H.names = certNames $ X509.getCertificate c }
	lift . lift . lift $ validate (H.tlsHandle t) cs cc
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
debugCipherSuite = (gets fst >>=) . (lift .) . flip H.debugCipherSuite

throw :: HandleLike h => H.AlertLevel -> H.AlertDesc -> String -> HandshakeM h g a
throw = ((throwError .) .) . H.Alert
