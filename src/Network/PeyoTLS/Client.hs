{-|

Module		: Network.PeyoTLS.Client
Copyright	: (c) Yoshikuni Jujo, 2014
License		: BSD3
Maintainer	: PAF01143@nifty.ne.jp
Stability	: Experimental

-}

module Network.PeyoTLS.Client (
	-- * Basic
	PeyotlsM, PeyotlsHandle, TlsM, TlsHandle, Alert(..),
	run, open, open', getNames, checkName,
	-- * Renegotiation
	renegotiate, setCipherSuites, setKeyCerts, setCertificateStore,
	-- * Cipher Suite
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	-- * Others
	ValidateHandle(..), CertSecretKey(..) ) where

import Network.PeyoTLS.Client.Body
