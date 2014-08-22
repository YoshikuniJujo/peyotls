{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.TChan.Client (
	open'
	) where

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
	TChan BSC.ByteString -> TChan BSC.ByteString -> String ->
	[CipherSuite] -> [(CertSecretKey, CertificateChain)] ->
	CertificateStore -> g -> HandleMonad h ()
open' h inc otc dn cs kc ca g = do
	((k, _n), g') <- (`run'` g) $ C.open' h dn cs kc ca
	liftBase $ putStrLn ""
	let	rk = kRKey k
		rmk = kRMKey k
		wk = kWKey k
		wmk = kWMKey k
		rcs = kRCSuite k
		wcs = kWCSuite k
	liftBase $ do
		print rcs
		print wcs
		putStrLn $ "READ      KEY: " ++ show rk
		putStrLn $ "READ  MAC KEY: " ++ show rmk
		putStrLn $ "WRITE     KEY: " ++ show wk
		putStrLn $ "WRITE MAC KEY: " ++ show wmk
	_ <- liftBaseDiscard forkIO . forever . (`runStateT` (g', 1)) $ do
		wpln <- liftBase . atomically $ readTChan otc
		(g0, sn) <- get
		let	(wenc, g1) = encrypt sha1 wk wmk sn "\ETB\ETX\ETX" wpln g0
		put (g1, succ sn)
		lift $ hlPut h "\ETB\ETX\ETX"
		lift $ hlPut h
			. (B.encode :: Word16 -> BSC.ByteString) . fromIntegral
			$ BSC.length wenc
		lift $ hlPut h wenc
	_ <- liftBaseDiscard forkIO . forever . (`runStateT` 1) $ do
		sn <- get
		modify succ
		pre <- lift $ hlGet h 3
		liftBase $ print pre
		Right n <- B.decode <$> lift (hlGet h 2)
		enc <- lift $ hlGet h n
		liftBase $ print enc
		let	Right pln = decrypt sha1 rk rmk sn pre enc
		liftBase $ putStrLn ""
		liftBase . atomically $ writeTChan inc pln
	return ()
