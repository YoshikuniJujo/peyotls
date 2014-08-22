{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts,
	PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.State
import Control.Monad.Trans.Control
import Control.Monad.Base
import Control.Concurrent
import Control.Concurrent.STM
import Data.Word
import Data.HandleLike
import Data.X509
import Data.X509.CertificateStore
import System.Environment
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Client.Body hiding (open, open')
import qualified Network.PeyoTLS.Client.Body as C
import Network.PeyoTLS.Run.Crypto
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B

main :: IO ()
main = do
	inc <- atomically newTChan
	otc <- atomically newTChan
	d : _ <- getArgs
	ca <- readCertificateStore [d ++ "/cacert.pem"]
	h <- connectTo "localhost" $ PortNumber 443
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	open' (DebugHandle h $ Just "low") inc otc "localhost"
		["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca g
	atomically $ writeTChan otc "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
	BSC.putStr =<< atomically (readTChan inc)

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
	_ <- liftBaseDiscard forkIO . forever $ do
		pre <- hlGet h 3
		liftBase $ print pre
		Right n <- B.decode <$> hlGet h 2
		enc <- hlGet h n
		liftBase $ print enc
		let	Right pln = decrypt sha1 rk rmk 1 pre enc
		liftBase $ putStrLn ""
		liftBase . atomically $ writeTChan inc pln
	return ()

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
