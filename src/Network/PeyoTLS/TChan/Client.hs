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
	((k, _ns), g') <- (`run'` g) $ C.open' h dn cs kc ca
	liftBase $ putStrLn ""
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
		lift $ hlPut h "\ETB\ETX\ETX"
		lift $ hlPut h
			. (B.encode :: Word16 -> BSC.ByteString) . fromIntegral
			$ BSC.length wenc
		lift $ hlPut h wenc
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
	HandleMonad h (String -> Bool, (TChan BSC.ByteString, TChan BSC.ByteString))
open h cs kc ca g = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	((k, ns), g') <- (`run'` g) $ C.open h cs kc ca
	liftBase $ putStrLn ""
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
		lift $ hlPut h "\ETB\ETX\ETX"
		lift $ hlPut h
			. (B.encode :: Word16 -> BSC.ByteString) . fromIntegral
			$ BSC.length wenc
		lift $ hlPut h wenc
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
	return (toCheckName ns, (inc, otc))
