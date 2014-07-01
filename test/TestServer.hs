{-# LANGUAGE OverloadedStrings, ScopedTypeVariables, PackageImports #-}

module TestServer (server, ValidateHandle(..), CipherSuite(..)) where

import Control.Monad (liftM)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import Network.PeyoTLS.Server ( CertSecretKey,
	run, open, names,
	ValidateHandle(..), CipherSuite(..) )

server :: (ValidateHandle h, CPRG g)  => g -> h ->
	[CipherSuite] ->
	(CertSecretKey, X509.CertificateChain) ->
	(CertSecretKey, X509.CertificateChain) ->
	Maybe X509.CertificateStore -> HandleMonad h ()
server g h css rsa ec mcs = (`run` g) $ do
	cl <- open h css [rsa, ec] mcs
	const () `liftM` doUntil BS.null (hlGetLine cl)
	hlPut cl . answer . fromMaybe "Anonym" . listToMaybe $ names cl
	hlClose cl

answer :: String -> BS.ByteString
answer name = BS.concat [
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n",
	"Date: Wed, 07 May 2014 02:27:34 GMT\r\nServer: Warp/2.1.4\r\n",
	"Content-Type: text/plain\r\n\r\n007\r\nHello, \r\n",
	BSC.pack . show $ length name, "\r\n", BSC.pack name, "\r\n",
	"001\r\n!\r\n0\r\n\r\n" ]

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
