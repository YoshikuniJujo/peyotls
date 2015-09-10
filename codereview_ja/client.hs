{-# LANGUAGE PackageImports, OverloadedStrings #-}

import Control.Applicative
import Data.Word
import Data.X509 (CertificateChain)
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import System.IO
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Codec
import Network.PeyoTLS.Codec.ContentTypes
import qualified Codec.Bytable.BigEndian as B
import "crypto-random" Crypto.Random (
	SystemRNG, cprgGenerate, cprgCreate, createEntropyPool)

import qualified Data.ByteString as BS

main :: IO ()
main = do
	cs <- readCertificateStore ["codereview_ja/cacert.pem"]
	h <- connectTo "localhost" $ PortNumber 443
	hl <- hello <$> clientRandom
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) $ B.encode hl ]
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	print (B.decode bs :: Either String Handshake)
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
--	putStrLn $ take 100 (show (B.decode bs :: Either String Handshake)) ++ "..."
	let	Right hs = B.decode bs :: Either String Handshake
		Just cc = fromHandshake hs :: Maybe CertificateChain
	putStrLn $ take 80 (show cc) ++ "..."
	X509.validate X509.HashSHA256 X509.defaultHooks X509.defaultChecks cs
		(X509.ValidationCache
			(\_ _ _ -> return X509.ValidationCacheUnknown)
			(\_ _ _ -> return ()))
		("localhost", "") cc >>= print
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	print n
	bs <- BS.hGet h n
	print (B.decode bs :: Either String Handshake)

clientRandom :: IO BS.ByteString
clientRandom = fst . cprgGenerate 32 <$>
	(cprgCreate <$> createEntropyPool :: IO SystemRNG)

hello :: BS.ByteString -> Handshake
hello cr = toHandshake $ ClHello (PrtVrsn 3 3) cr (SssnId "") [
		"TLS_RSA_WITH_AES_128_CBC_SHA"
	] [CmpMtdNull] Nothing

getB :: B.Bytable b => Handle -> Int -> IO (Either String b)
getB h n = B.decode <$> BS.hGet h n
