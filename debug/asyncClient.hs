{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Concurrent
import Control.Concurrent.STM
import Data.Word
import Data.HandleLike
import System.Environment
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Client.Body
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
	((k, n), g') <- (`run'` g) $ do
		open' (DebugHandle h $ Just "low") "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
	putStrLn ""
	let	rk = kRKey k
		rmk = kRMKey k
		wk = kWKey k
		wmk = kWMKey k
		rcs = kRCSuite k
		wcs = kWCSuite k
	forkIO . forever $ do
		wpln <- atomically $ readTChan otc
		let	(wenc, g'') = encrypt sha1 wk wmk 1 "\ETB\ETX\ETX" wpln g'
--				"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" g'
		hlPut h "\ETB\ETX\ETX"
		hlPut h . (B.encode :: Word16 -> BSC.ByteString) . fromIntegral $
			BSC.length wenc
		hlPut h wenc
	forkIO . forever $ do
		pre <- hlGet h 3
		print pre
		Right n <- B.decode <$> hlGet h 2
		enc <- hlGet h n
		print enc
		let	Right pln = decrypt sha1 rk rmk 1 pre enc
		putStrLn ""
		atomically $ writeTChan inc pln
	atomically $ writeTChan otc "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
	BSC.putStr =<< atomically (readTChan inc)
	print rcs
	print wcs
	putStrLn $ "READ      KEY: " ++ show rk
	putStrLn $ "READ  MAC KEY: " ++ show rmk
	putStrLn $ "WRITE     KEY: " ++ show wk
	putStrLn $ "WRITE MAC KEY: " ++ show wmk
	print n

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
