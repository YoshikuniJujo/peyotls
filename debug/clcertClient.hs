{-# LANGUAGE OverloadedStrings, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.HandleLike
import System.Environment
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC

main :: IO ()
main = do
	d : _ <- getArgs
	rk <- readKey $ d ++ "/yoshikuni.sample_key"
	rc <- readCertificateChain $ d ++ "/yoshikuni.sample_crt"
	ca <- readCertificateStore [d ++ "/cacert.pem"]
	h <- connectTo "localhost" $ PortNumber 443
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`run` g) $ do
		p <- open (DebugHandle h $ Just "low") [
--			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_RSA_WITH_AES_128_CBC_SHA"
			] [(rk, rc)] ca
		unless ("localhost" `elem` names p) . error $
			"certificate name mismatch: " ++ show (names p)
		hlPut p "GET / HTTP/1.1 \r\n"
		hlPut p "Host: localhost\r\n\r\n"
		doUntil BSC.null (hlGetLine p) >>= liftIO . mapM_ BSC.putStrLn
		hlClose p

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x

instance ValidateHandle h => ValidateHandle (DebugHandle h) where
	validate (DebugHandle h _) = validate h
