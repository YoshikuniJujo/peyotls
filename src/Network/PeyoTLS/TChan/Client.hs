{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.TChan.Client (
	-- * Basic
	open, open',
	-- * Cipher Suite
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	-- * Others
	ValidateHandle(..), CertSecretKey(..) ) where

import Control.Applicative
import "monads-tf" Control.Monad.State
import Control.Monad.Trans.Control
import Control.Monad.Base
import Control.Concurrent
import Control.Concurrent.STM
import Data.Maybe
import Data.Word
import Data.HandleLike
import Data.X509
import Data.X509.CertificateStore
import Network.PeyoTLS.Client.Body hiding (open, open')
import qualified Network.PeyoTLS.Client.Body as C
import Network.PeyoTLS.Run.Crypto
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B

open' :: (CPRG g, ValidateHandle h, MonadBaseControl IO (HandleMonad h)) => h ->
	String -> [CipherSuite] -> [(CertSecretKey, CertificateChain)] ->
	CertificateStore -> g ->
	HandleMonad h (TChan BSC.ByteString, TChan BSC.ByteString)
open' h dn cs kc ca g = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	((k, _ns, _), g') <- (`run'` g) $ C.open' h dn cs kc ca
	let	rk = kRKey k
		rmk = kRMKey k
		wk = kWKey k
		wmk = kWMKey k
		CipherSuite _ rcs = kRCSuite k
		CipherSuite _ wcs = kWCSuite k
	_ <- liftBaseDiscard forkIO . (`evalStateT` (g', 1)) . forever $ do
		wpln <- liftBase . atomically $ readTChan otc
		(g0, sn) <- get
		let	hs = case wcs of
				AES_128_CBC_SHA -> sha1
				AES_128_CBC_SHA256 -> sha256
				_ -> error "Network.PeyoTLS.TChan.Client.open': bad"
			(wenc, g1) = encrypt hs wk wmk sn "\ETB\ETX\ETX" wpln g0
		put (g1, succ sn)
		lift $ do
			hlPut h "\ETB\ETX\ETX"
			hlPut h . (B.encode :: Word16 -> BSC.ByteString)
				. fromIntegral $ BSC.length wenc
			hlPut h wenc
	_ <- liftBaseDiscard forkIO . (`evalStateT` 1) . forever $ do
		sn <- get
		modify succ
		pre <- lift $ hlGet h 3
		Right n <- B.decode <$> lift (hlGet h 2)
		enc <- lift $ hlGet h n
		let	hs = case rcs of
				AES_128_CBC_SHA -> sha1
				AES_128_CBC_SHA256 -> sha256
				_ -> error "Network.PeyoTLS.TChan.Client.open': bad"
			Right pln = decrypt hs rk rmk sn pre enc
		liftBase . atomically $ writeTChan inc pln
	return (inc, otc)

open :: (CPRG g, ValidateHandle h, MonadBaseControl IO (HandleMonad h)) => h ->
	[CipherSuite] -> [(CertSecretKey, CertificateChain)] ->
	CertificateStore -> g ->
	HandleMonad h (
		(String -> Bool, SignedCertificate),
		(TChan BSC.ByteString, TChan BSC.ByteString))
open h cs kc ca g = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	((k, ns, crt), g') <- (`run'` g) $ C.open h cs kc ca
	let	rk = kRKey k
		rmk = kRMKey k
		wk = kWKey k
		wmk = kWMKey k
		CipherSuite _ rcs = kRCSuite k
		CipherSuite _ wcs = kWCSuite k
	_ <- liftBaseDiscard forkIO . (`evalStateT` (g', 1)) . forever $ do
		wpln <- liftBase . atomically $ readTChan otc
--		(g0, sn) <- get
		let	hs = case wcs of
				AES_128_CBC_SHA -> sha1
				AES_128_CBC_SHA256 -> sha256
				_ -> error "Network.PeyoTLS.TChan.Client.open': bad"
		putEncrypted h hs wk wmk wpln
	_ <- liftBaseDiscard forkIO . (`evalStateT` 1) . forever $ do
		sn <- get
		modify succ
		pre <- lift $ hlGet h 3
		Right n <- B.decode <$> lift (hlGet h 2)
		enc <- lift $ hlGet h n
		let	hs = case rcs of
				AES_128_CBC_SHA -> sha1
				AES_128_CBC_SHA256 -> sha256
				_ -> error "Network.PeyoTLS.TChan.Client.open': bad"
			Right pln = decrypt hs rk rmk sn pre enc
		liftBase . atomically $ writeTChan inc pln
	return ((toCheckName ns, fromJust crt), (inc, otc))

putEncrypted :: (HandleLike h, CPRG g) =>
	h -> (Hash, Int) -> BSC.ByteString -> BSC.ByteString
		-> BSC.ByteString -> StateT (g, Word64) (HandleMonad h) ()
putEncrypted h hs wk wmk wpln = do
		(g0, sn) <- get
		let	(wenc, g1) = encrypt hs wk wmk sn "\ETB\ETX\ETX" wpln g0
		put (g1, succ sn)
		lift $ do
			hlPut h "\ETB\ETX\ETX"
			hlPut h . (B.encode :: Word16 -> BSC.ByteString)
				. fromIntegral $ BSC.length wenc
			hlPut h wenc
