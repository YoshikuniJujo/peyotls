{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.State
import Control.Concurrent
import Data.Word
import Data.HandleLike
import System.Environment
import Network
import Network.PeyoTLS.Server
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Run.Crypto
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B

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
			((k, n), g') <- (`run'` g) $ do
				p <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"]
					[(k, c)] Nothing
				hlFlush p
			pre <- hlGet h 3
			print pre
			Right n <- B.decode <$> hlGet h 2
			print n
			renc <- hlGet h n
			let	rk = kRKey k
				rmk = kRMKey k
				wk = kWKey k
				wmk = kWMKey k
				Right rpln = decrypt sha1 rk rmk 1 pre renc
				wpln = BS.concat [
					"HTTP/1.1 200 OK\r\n",
					"Transfer-Encoding: chunked\r\n",
					"Content-Type: text/plain\r\n\r\n",
					"5\r\nHello\r\n5\r\nWorld0\r\n\r\n" ]
				(wenc, g'') =
					encrypt sha1 wk wmk 1 "\ETB\ETX\ETX" wpln g'
			BS.putStr rpln
			hlPut h "\ETB\ETX\ETX"
			hlPut h . (B.encode :: Word16 -> BSC.ByteString)
				. fromIntegral $ BSC.length wenc
			hlPut h wenc
			putStrLn $ "READ      KEY: " ++ show rk
			putStrLn $ "READ  MAC KEY: " ++ show rmk
			putStrLn $ "WRITE     KEY: " ++ show wk
			putStrLn $ "WRITE MAC KEY: " ++ show wmk

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
