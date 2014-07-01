{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TestClient ( CertSecretKey,
	client, CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..) ) where

import Network.PeyoTLS.Client
import Control.Monad
import "crypto-random" Crypto.Random
import Data.HandleLike

import qualified Data.ByteString as BS
-- import qualified Data.ByteString.Char8 as BSC
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

cipherSuites :: [CipherSuite]
cipherSuites = [
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA" ]

client :: (ValidateHandle h, CPRG g) => g -> h ->
	[(CertSecretKey, X509.CertificateChain)] ->
	X509.CertificateStore ->
	HandleMonad h ()
client g h crt crtS = (`run` g) $ do
	t <- open h cipherSuites crt crtS
--	hlDebug t "medium" . BSC.pack . (++ "\n") . show $ names t
	unless ("localhost" `elem` names t) $
		error "certificate name mismatch"
	hlPut t request
	const () `liftM` hlGetContent t

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"
