{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts,
	PackageImports #-}

import Control.Applicative
import Control.Monad
import Control.Concurrent.STM
import Data.HandleLike
import System.Environment
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.TChan.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC

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

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
