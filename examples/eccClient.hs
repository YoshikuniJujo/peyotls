{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.HandleLike
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC

cipherSuites :: [CipherSuite]
cipherSuites = [
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA" ]

main :: IO ()
main = do
	ca <- readCertificateStore ["cacert.pem"]
	h <- connectTo "localhost" $ PortNumber 443
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`run` g) $ do
		p <- open h cipherSuites [] ca
		unless ("localhost" `elem` names p) $
			error "certificate name mismatch"
		hlPut p "GET / HTTP/1.1 \r\n"
		hlPut p "Host: localhost\r\n\r\n"
		doUntil BSC.null (hlGetLine p) >>= liftIO . mapM_ BSC.putStrLn
		hlClose p

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
