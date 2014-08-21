{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Word
import Data.HandleLike
import System.Environment
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Client
import Network.PeyoTLS.Run.Crypto
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B

main :: IO ()
main = do
	d : _ <- getArgs
	ca <- readCertificateStore [d ++ "/cacert.pem"]
	h <- connectTo "localhost" $ PortNumber 443
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(p, s) <- (`run'` g) $ do
		open' (DebugHandle h $ Just "low") "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
--		unless ("localhost" `elem` names p) .
--			error $ "certificate name mismatch: " ++ show (names p)
--		hlPut p "GET / HTTP/1.1 \r\n"
--		hlPut p "Host: localhost\r\n\r\n"
--		hlFlush p
		{-
		doUntil BSC.null (hlGetLine p) >>= liftIO . mapM_ BSC.putStrLn
		hlClose p
		-}
	putStrLn ""
	let	g = gen s
		rk = kRKey . sKeys . snd . head $ states s
		rmk = kRMKey . sKeys . snd . head $ states s
		wk = kWKey . sKeys . snd . head $ states s
		wmk = kWMKey . sKeys . snd . head $ states s
		(wenc, g') = encrypt sha1 wk wmk 1 "\ETB\ETX\ETX"
			"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" g
	hlPut h "\ETB\ETX\ETX"
	hlPut h . (B.encode :: Word16 -> BSC.ByteString) . fromIntegral $
		BSC.length wenc
	hlPut h wenc
	pre <- hlGet h 3
	print pre
	Right n <- B.decode <$> hlGet h 2
	enc <- hlGet h n
	print enc
	let	Right pln = decrypt sha1 rk rmk 1 pre enc
	putStrLn ""
	BSC.putStr pln
	putStrLn $ "READ      KEY: " ++ show rk
	putStrLn $ "READ  MAC KEY: " ++ show rmk
	putStrLn $ "WRITE     KEY: " ++ show wk
	putStrLn $ "WRITE MAC KEY: " ++ show wmk
	print $ readSN $ snd $ head $ states s
	print $ writeSN $ snd $ head $ states s
	print $ sNames $ snd $ head $ states s

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
