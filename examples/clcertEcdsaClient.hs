{-# LANGUAGE OverloadedStrings, PackageImports #-}

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
	ek <- readKey $ d ++ "/client_ecdsa.sample_key"
	ec <- readCertificateChain $ d ++ "/client_ecdsa.sample_crt"
	ca <- readCertificateStore [d ++ "/cacert.pem"]
	h <- connectTo "localhost" $ PortNumber 443
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`run` g) $ do
		p <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(ek, ec), (rk, rc)] ca
		unless ("localhost" `elem` names p) $
			error "certificate name mismatch"
		hlPut p "GET / HTTP/1.1 \r\n"
		hlPut p "Host: localhost\r\n\r\n"
		doUntil BSC.null (hlGetLine p) >>= liftIO . mapM_ BSC.putStrLn
		hlClose p

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
