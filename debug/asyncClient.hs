{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

import Control.Applicative
import Control.Monad
-- import "monads-tf" Control.Monad.Trans
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

open' :: (CPRG g, ValidateHandle h, HandleMonad h ~ IO) => h ->
	TChan BSC.ByteString -> TChan BSC.ByteString -> String ->
	[CipherSuite] -> [(CertSecretKey, CertificateChain)] ->
	CertificateStore -> g -> IO ()
open' h inc otc dn cs kc ca g = do
	((k, _n), g') <- (`run'` g) $ C.open' h dn cs kc ca
	putStrLn ""
	let	rk = kRKey k
		rmk = kRMKey k
		wk = kWKey k
		wmk = kWMKey k
		rcs = kRCSuite k
		wcs = kWCSuite k
	print rcs
	print wcs
	putStrLn $ "READ      KEY: " ++ show rk
	putStrLn $ "READ  MAC KEY: " ++ show rmk
	putStrLn $ "WRITE     KEY: " ++ show wk
	putStrLn $ "WRITE MAC KEY: " ++ show wmk
	_ <- forkIO . forever $ do
		wpln <- atomically $ readTChan otc
		let	(wenc, g'') = encrypt sha1 wk wmk 1 "\ETB\ETX\ETX" wpln g'
--				"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" g'
		hlPut h "\ETB\ETX\ETX"
		hlPut h . (B.encode :: Word16 -> BSC.ByteString) . fromIntegral $
			BSC.length wenc
		hlPut h wenc
	_ <- forkIO . forever $ do
		pre <- hlGet h 3
		print pre
		Right n <- B.decode <$> hlGet h 2
		enc <- hlGet h n
		print enc
		let	Right pln = decrypt sha1 rk rmk 1 pre enc
		putStrLn ""
		atomically $ writeTChan inc pln
	return ()

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
