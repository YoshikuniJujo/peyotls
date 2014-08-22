{-# LANGUAGE OverloadedStrings, FlexibleContexts,
	PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.State
import Control.Concurrent
import Control.Concurrent.STM
import System.Environment
import Network
import Network.PeyoTLS.TChan.Server
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

main :: IO ()
main = do
	d : _ <- getArgs
	k <- readKey $ d ++ "/localhost.sample_key"
	c <- readCertificateChain [d ++ "/localhost.sample_crt"]
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	soc <- listenOn $ PortNumber 443
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . forkIO $ do
			(_n, (inc, otc)) <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"]
				[(k, c)] Nothing g

			let	wpln = BS.concat [
					"HTTP/1.1 200 OK\r\n",
					"Transfer-Encoding: chunked\r\n",
					"Content-Type: text/plain\r\n\r\n",
					"5\r\nHello\r\n5\r\nWorld0\r\n\r\n" ]
			BS.putStr =<< atomically (readTChan inc)
			atomically $ writeTChan otc wpln
			BS.putStr =<< atomically (readTChan inc)
			atomically $ writeTChan otc wpln
			BS.putStr =<< atomically (readTChan inc)
			atomically $ writeTChan otc wpln
