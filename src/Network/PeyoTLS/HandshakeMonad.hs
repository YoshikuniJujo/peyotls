{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports, TypeFamilies #-}

module Network.PeyoTLS.HandshakeMonad (
	TH.TlsM, TH.run, HandshakeM, execHandshakeM, rerunHandshakeM,
	withRandom, randomByteString,
	ValidateHandle(..), handshakeValidate,
	TH.TlsHandle(..), TH.ContentType(..),
		setCipherSuite, flushCipherSuite, debugCipherSuite,
		tlsGetContentType, tlsGet, tlsPut,
		generateKeys, encryptRsa, decryptRsa, rsaPadding,
	TH.Alert(..), TH.AlertLevel(..), TH.AlertDesc(..),
	TH.Side(..), TH.RW(..), handshakeHash, finishedHash, throwError,
	TH.hlPut_, TH.hlDebug_, TH.hlClose_,
	TH.tGetLine, TH.tGetContent, tlsGet_, tlsPut_, tlsGet__,
	tGetLine_, tGetContent_,
	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,

	resetSequenceNumber,

	getInitSet, setInitSet,
	flushAppData,
	) where

import Prelude hiding (read)

import Control.Applicative
import qualified Data.ASN1.Types as ASN1
import Control.Arrow (first)
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
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as HD
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified Network.PeyoTLS.TlsHandle as TH (
	TlsM, Alert(..), AlertLevel(..), AlertDesc(..),
		run, withRandom, randomByteString,
	TlsHandle(..), ContentType(..),
		newHandle, getContentType, tlsGet, tlsPut, generateKeys,
		debugCipherSuite,
		getCipherSuiteSt, setCipherSuiteSt, flushCipherSuiteSt, setKeys,
	Side(..), RW(..), finishedHash, handshakeHash, CipherSuite(..),
	hlPut_, hlDebug_, hlClose_, tGetContent, tGetLine, tGetLine_,
	getClientFinishedT, setClientFinishedT,
	getServerFinishedT, setServerFinishedT,

	resetSequenceNumber,

	getInitSetT, setInitSetT, InitialSettings,
	tlsGet_,
	flushAppData,
	)

resetSequenceNumber :: HandleLike h => TH.RW -> HandshakeM h g ()
resetSequenceNumber rw = gets fst >>= lift . flip TH.resetSequenceNumber rw

tlsGet_ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandle h g -> TH.TlsM h g ()) ->
	(TH.TlsHandle h g, SHA256.Ctx) -> Int -> TH.TlsM h g ((TH.ContentType, BS.ByteString), (TH.TlsHandle h g, SHA256.Ctx))
tlsGet_ = TH.tlsGet_
	{-
tlsGet_ rn th@(t, _) n = do
	ct <- TH.getContentType t
	case ct of
		TH.CTHandshake -> do
			rn t
			tlsGet_ rn th n
		_ -> TH.tlsGet th n
		-}

tlsGet__ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandle h g, SHA256.Ctx) -> Int -> TH.TlsM h g ((TH.ContentType, BS.ByteString), (TH.TlsHandle h g, SHA256.Ctx))
tlsGet__ = TH.tlsGet

tGetLine_, tGetContent_ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandle h g -> TH.TlsM h g ()) ->
	TH.TlsHandle h g -> TH.TlsM h g (TH.ContentType, BS.ByteString)
tGetLine_ = TH.tGetLine_

flushAppData :: (HandleLike h, CPRG g) => HandshakeM h g BS.ByteString
flushAppData = gets fst >>= lift . TH.flushAppData

tGetContent_ rn t = do
	ct <- TH.getContentType t
	case ct of
		TH.CTHandshake -> rn t >> tGetContent_ rn t
		_ -> TH.tGetContent t

tlsPut_ :: (HandleLike h, CPRG g) =>
	(TH.TlsHandle h g, SHA256.Ctx) -> TH.ContentType -> BS.ByteString -> TH.TlsM h g (TH.TlsHandle h g, SHA256.Ctx)
tlsPut_ = TH.tlsPut

throwError :: HandleLike h =>
	TH.AlertLevel -> TH.AlertDesc -> String -> HandshakeM h g a
throwError al ad m = E.throwError $ TH.Alert al ad m

type HandshakeM h g = StateT (TH.TlsHandle h g, SHA256.Ctx) (TH.TlsM h g)

execHandshakeM :: HandleLike h =>
	h -> HandshakeM h g () -> TH.TlsM h g (TH.TlsHandle h g)
execHandshakeM h =
	liftM fst . ((, SHA256.init) `liftM` TH.newHandle h >>=) . execStateT

rerunHandshakeM ::
	HandleLike h => TH.TlsHandle h g -> HandshakeM h g a -> TH.TlsM h g a
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
	modify . first $ const t { TH.names = certNames . X509.getCertificate $ last c }
	lift . lift . lift $ validate (TH.tlsHandle t) cs cc

setCipherSuite :: HandleLike h => TH.CipherSuite -> HandshakeM h g ()
setCipherSuite cs = do
	t <- gets fst
	lift $ TH.setCipherSuiteSt (TH.clientId t) cs

flushCipherSuite :: (HandleLike h, CPRG g) => TH.RW -> HandshakeM h g ()
flushCipherSuite p = do
	t <- gets fst
	lift $ TH.flushCipherSuiteSt p (TH.clientId t)

debugCipherSuite :: HandleLike h => String -> HandshakeM h g ()
debugCipherSuite m = do t <- gets fst; lift $ TH.debugCipherSuite t m

tlsGetContentType :: (HandleLike h, CPRG g) => HandshakeM h g TH.ContentType
tlsGetContentType = gets fst >>= lift . TH.getContentType

tlsGet :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
tlsGet n = do ((_, bs), t') <- lift . flip TH.tlsGet n =<< get; put t'; return bs

tlsPut :: (HandleLike h, CPRG g) =>
	TH.ContentType -> BS.ByteString -> HandshakeM h g ()
tlsPut ct bs = get >>= lift . (\t -> TH.tlsPut t ct bs) >>= put

generateKeys :: HandleLike h => TH.Side ->
	(BS.ByteString, BS.ByteString) -> BS.ByteString -> HandshakeM h g ()
generateKeys p (cr, sr) pms = do
	t <- gets fst
	cs <- lift $ TH.getCipherSuiteSt (TH.clientId t)
	k <- lift $ TH.generateKeys t p cs cr sr pms
	lift $ TH.setKeys (TH.clientId t) k

encryptRsa :: (HandleLike h, CPRG g) =>
	RSA.PublicKey -> BS.ByteString -> HandshakeM h g BS.ByteString
encryptRsa pk p = either (E.throwError . strMsg . show) return =<<
	withRandom (\g -> RSA.encrypt g pk p)

decryptRsa :: (HandleLike h, CPRG g) =>
	RSA.PrivateKey -> BS.ByteString -> HandshakeM h g BS.ByteString
decryptRsa sk e = either (E.throwError . strMsg . show) return =<<
	withRandom (\g -> RSA.decryptSafer g sk e)

rsaPadding :: RSA.PublicKey -> BS.ByteString -> BS.ByteString
rsaPadding pk bs = case RSA.padSignature (RSA.public_size pk) $
			HD.digestToASN1 HD.hashDescrSHA256 bs of
		Right pd -> pd; Left m -> error $ show m

handshakeHash :: HandleLike h => HandshakeM h g BS.ByteString
handshakeHash = get >>= lift . TH.handshakeHash

finishedHash :: (HandleLike h, CPRG g) => TH.Side -> HandshakeM h g BS.ByteString
finishedHash p = get >>= lift . flip TH.finishedHash p

getClientFinished, getServerFinished :: HandleLike h => HandshakeM h g BS.ByteString
getClientFinished = gets fst >>= lift . TH.getClientFinishedT
getServerFinished = gets fst >>= lift . TH.getServerFinishedT

setClientFinished, setServerFinished ::
	HandleLike h => BS.ByteString -> HandshakeM h g ()
setClientFinished cf = gets fst >>= lift . flip TH.setClientFinishedT cf
setServerFinished cf = gets fst >>= lift . flip TH.setServerFinishedT cf

getInitSet :: HandleLike h => HandshakeM h g TH.InitialSettings
getInitSet = gets fst >>= lift . TH.getInitSetT

setInitSet :: HandleLike h => TH.InitialSettings -> HandshakeM h g ()
setInitSet is = gets fst >>= lift . flip TH.setInitSetT is
