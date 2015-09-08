{-|

Module		: Network.PeyoTLS.Server
Copyright	: (c) Yoshikuni Jujo, 2014
License		: BSD3
Maintainer	: PAF01143@nifty.ne.jp
Stability	: Experimental

-}

module Network.PeyoTLS.Server (
	-- * Basic
	PeyotlsM, PeyotlsHandle, TlsM, TlsHandle, Alert(..),
	run, open, getNames, checkName, getCertificate,
	-- * Renegotiation
	renegotiate, setCipherSuites, setKeyCerts, setCertificateStore,
	-- * Cipher Suite
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	-- * Others
	ValidateHandle(..), CertSecretKey(..) ) where

import Data.HandleLike
import Network.PeyoTLS.Server.Body

checkName :: HandleLike h => TlsHandle h g -> String -> TlsM h g Bool
checkName t n = do
	ns <- getNames t
	return . maybe False ($ n) $ toCheckName ns
