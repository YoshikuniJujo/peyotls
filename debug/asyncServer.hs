{-# LANGUAGE OverloadedStrings, FlexibleContexts,
	PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.State
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent
import Control.Concurrent.STM
import Data.Word
import Data.HandleLike
import Data.X509
import Data.X509.CertificateStore
import System.Environment
import Network
import Network.PeyoTLS.Server hiding (open)
import qualified Network.PeyoTLS.Server as S
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

open :: (CPRG g, ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	h -> [CipherSuite] -> [(CertSecretKey, CertificateChain)] ->
	Maybe CertificateStore -> g ->
	HandleMonad h (
		Maybe (String -> Bool),
		(TChan BSC.ByteString, TChan BSC.ByteString))
open h cs kcs ca g = do
			inc <- liftBase $ atomically newTChan
			otc <- liftBase $ atomically newTChan
			((k, ns), g') <- (`run'` g) $ do
				p <- S.open h cs kcs ca
				hlFlush p
			let	rk = kRKey k
				rmk = kRMKey k
				wk = kWKey k
				wmk = kWMKey k
			_ <- liftBaseDiscard forkIO
				. (`evalStateT` 1) . forever $ do
				sn <- get
				modify succ
				liftBase $ putStrLn $ "sn = " ++ show sn
				pre <- lift $ hlGet h 3
				when (BSC.null pre) $
					lift (hlClose h) >> error "bad"
				liftBase $ print pre
				Right n <- B.decode <$> lift (hlGet h 2)
				liftBase $ print n
				renc <- lift $ hlGet h n
				let Right rpln = decrypt sha1 rk rmk sn pre renc
				liftBase $ do
					BS.putStr rpln
					atomically $ writeTChan inc rpln

			_ <- liftBaseDiscard forkIO
				. (`evalStateT` (1, g')) . forever $ do
				(sn, g0) <- get
				wpln <- liftBase . atomically $ readTChan otc
				let	(wenc, g1) =
						encrypt sha1 wk wmk sn "\ETB\ETX\ETX" wpln g0
				put (succ sn, g1)
				lift $ hlPut h "\ETB\ETX\ETX"
				lift . hlPut h
					. (B.encode :: Word16 -> BSC.ByteString)
					. fromIntegral $ BSC.length wenc
				lift $ hlPut h wenc

			return (toCheckName ns, (inc, otc))
