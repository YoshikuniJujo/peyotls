{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Run (
	TH.TlsM, TH.run, TH.TlsHandleBase(..),
		adGet, adGetLine, adGetContent, TH.adPut, TH.adDebug, TH.adClose,
	HandshakeM, execHandshakeM, rerunHandshakeM, withRandom,
		chGet, ccsPut, hsPut, updateHash, flushAd,
		TH.CertSecretKey(..), TH.isRsaKey, TH.isEcdsaKey,
		TH.SettingsC, getSettingsC, setSettingsC,
		TH.SettingsS, getSettingsS, setSettingsS,
		getCipherSuite, setCipherSuite,
		getClFinished, getSvFinished, setClFinished, setSvFinished,
		TH.RW(..), flushCipherSuite, makeKeys,
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

type RenegoProc h g = TH.TlsHandleBase h g -> TH.TlsM h g ()

adGet :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> TH.TlsHandleBase h g -> Int -> TH.TlsM h g BS.ByteString
adGet rp t n = TH.getBuf t >>= \b -> if BS.length b >= n
	then uncurry (>>) . (TH.setBuf t *** return) $ BS.splitAt n b
	else BS.append b `liftM` TH.adGet rp t (n - BS.length b)

adGetLine :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> TH.TlsHandleBase h g -> TH.TlsM h g BS.ByteString
adGetLine rp t = TH.getBuf t >>= \b -> if '\n' `BSC.elem` b || '\r' `BSC.elem` b
	then uncurry (>>) . (TH.setBuf t *** return) $ case BSC.span (/= '\r') b of
		(_, "") -> second BS.tail $ BSC.span (/= '\n') b
		(l, ls) -> case BSC.uncons ls of
			Just ('\r', ls') -> case BSC.uncons ls' of
				Just ('\n', ls'') -> (l, ls'')
				_ -> (l, ls')
			_ -> (l, ls)
	else (b `BS.append`) `liftM` TH.adGetLine rp t

adGetContent :: (HandleLike h, CPRG g) =>
	RenegoProc h g -> TH.TlsHandleBase h g -> TH.TlsM h g BS.ByteString
adGetContent rp t = TH.getBuf t >>= \b ->
	if BS.null b then TH.adGetContent rp t else TH.setBuf t "" >> return b

type HandshakeM h g = StateT (TH.TlsHandleBase h g, SHA256.Ctx) (TH.TlsM h g)

execHandshakeM ::
	HandleLike h => h -> HandshakeM h g () -> TH.TlsM h g (TH.TlsHandleBase h g)
execHandshakeM h =
	liftM fst . ((, SHA256.init) `liftM` TH.newHandle h >>=) . execStateT

rerunHandshakeM ::
	HandleLike h => TH.TlsHandleBase h g -> HandshakeM h g a -> TH.TlsM h g a
rerunHandshakeM = flip evalStateT . (, SHA256.init)

withRandom :: HandleLike h => (g -> (a, g)) -> HandshakeM h g a
withRandom = lift . TH.withRandom

chGet :: (HandleLike h, CPRG g) => HandshakeM h g (Either Word8 BS.ByteString)
chGet = gets fst >>= lift . flip TH.chGet 1 >>= \ch -> case ch of
	Left w -> return $ Left w
	Right t -> Right `liftM` do
		len <- hsGet 3
		body <- hsGet . either error id $ B.decode len
		return $ BS.concat [t, len, body]

hsGet :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
hsGet n = gets fst >>= lift . flip TH.chGet n >>= \ch -> case ch of
	Right bs -> return bs
	_ -> throw TH.ALFatal TH.ADUnexMsg $ modNm ++ ".hsGet: not handshake"

ccsPut :: (HandleLike h, CPRG g) => Word8 -> HandshakeM h g ()
ccsPut = (gets fst >>=) . (lift .) . flip TH.ccsPut

hsPut :: (HandleLike h, CPRG g) => BS.ByteString -> HandshakeM h g ()
hsPut = (gets fst >>=) . (lift .) . flip TH.hsPut

updateHash :: HandleLike h => BS.ByteString -> HandshakeM h g ()
updateHash = modify . second . flip SHA256.update

flushAd :: (HandleLike h, CPRG g) => HandshakeM h g Bool
flushAd = gets fst >>= lift . TH.flushAd >>= uncurry (>>) . (push *** return)
	where push bs = gets fst >>= lift . TH.getBuf >>=
		(gets fst >>=) . (lift .) . flip TH.setBuf . (`BS.append` bs)

getSettingsC :: HandleLike h => HandshakeM h g TH.SettingsC
getSettingsC = gets fst >>= lift . TH.getSettingsC

setSettingsC :: HandleLike h => TH.SettingsC -> HandshakeM h g ()
setSettingsC = (gets fst >>=) . (lift .) . flip TH.setSettingsC

getSettingsS :: HandleLike h => HandshakeM h g TH.SettingsS
getSettingsS = gets fst >>= lift . TH.getSettingsS

setSettingsS :: HandleLike h => TH.SettingsS -> HandshakeM h g ()
setSettingsS = (gets fst >>=) . (lift .) . flip TH.setSettingsS

getCipherSuite :: HandleLike h => HandshakeM h g TH.CipherSuite
getCipherSuite = gets fst >>= lift . TH.getCipherSuite

setCipherSuite :: HandleLike h => TH.CipherSuite -> HandshakeM h g ()
setCipherSuite = (gets fst >>=) . (lift .) . flip TH.setCipherSuite

getClFinished, getSvFinished :: HandleLike h => HandshakeM h g BS.ByteString
getClFinished = gets fst >>= lift . TH.getClFinished
getSvFinished = gets fst >>= lift . TH.getSvFinished

setClFinished, setSvFinished :: HandleLike h => BS.ByteString -> HandshakeM h g ()
setClFinished = (gets fst >>=) . (lift .) . flip TH.setClFinished
setSvFinished = (gets fst >>=) . (lift .) . flip TH.setSvFinished

flushCipherSuite :: (HandleLike h, CPRG g) => TH.RW -> HandshakeM h g ()
flushCipherSuite = (gets fst >>=) . (lift .) . TH.flushCipherSuite

makeKeys :: HandleLike h => TH.Side ->
	(BS.ByteString, BS.ByteString) -> BS.ByteString -> HandshakeM h g ()
makeKeys s (cr, sr) pms = gets fst >>= \t -> lift $
	TH.getCipherSuite t >>= TH.makeKeys t s cr sr pms >>= TH.setKeys t

handshakeHash :: HandleLike h => HandshakeM h g BS.ByteString
handshakeHash = SHA256.finalize `liftM` gets snd

finishedHash :: (HandleLike h, CPRG g) => TH.Side -> HandshakeM h g BS.ByteString
finishedHash s = get >>= lift . uncurry (TH.finishedHash s) . second SHA256.finalize

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
	modify . first $ const t { TH.names = certNames $ X509.getCertificate c }
	lift . lift . lift $ validate (TH.tlsHandle t) cs cc
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
debugCipherSuite = (gets fst >>=) . (lift .) . flip TH.debugCipherSuite

throw :: HandleLike h => TH.AlertLevel -> TH.AlertDesc -> String -> HandshakeM h g a
throw = ((throwError .) .) . TH.Alert
