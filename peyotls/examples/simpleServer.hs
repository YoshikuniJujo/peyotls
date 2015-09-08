{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.State
import Control.Concurrent
import Data.HandleLike
import System.Environment
import Network
import Network.PeyoTLS.Server
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

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
		liftIO . forkIO . (`run` g) $ do
			p <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)]
				Nothing
			doUntil BS.null (hlGetLine p) >>= liftIO . mapM_ BSC.putStrLn
			hlPut p $ BS.concat [
				"HTTP/1.1 200 OK\r\n",
				"Transfer-Encoding: chunked\r\n",
				"Content-Type: text/plain\r\n\r\n",
				"5\r\nHello0\r\n\r\n" ]
			hlClose p

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
