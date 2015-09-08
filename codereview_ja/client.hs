{-# LANGUAGE PackageImports, OverloadedStrings #-}

import Control.Applicative
import Data.Word
import System.IO
import Network
import Network.PeyoTLS.Run.State
import Network.PeyoTLS.Codec
import Network.PeyoTLS.Codec.Hello
import Codec.Bytable.BigEndian
import "crypto-random" Crypto.Random (
	SystemRNG, cprgGenerate, cprgCreate, createEntropyPool)

import qualified Data.ByteString as BS

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 443
	hl <- hello <$> clientRandom
	BS.hPut h $ BS.concat [
		encode CTHandshake,
		"\x03\x03",
		addLen (undefined :: Word16) $ encode hl ]
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String ProtocolVersion -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	print (decode bs :: Either String Handshake)

clientRandom :: IO BS.ByteString
clientRandom = fst . cprgGenerate 32 <$>
	(cprgCreate <$> createEntropyPool :: IO SystemRNG)

hello :: BS.ByteString -> Handshake
hello cr = HClHello $ ClHello (3, 3) cr (SssnId "") [
		"TLS_RSA_WITH_AES_128_CBC_SHA"
	] [CmpMtdNull] Nothing

getB :: Bytable b => Handle -> Int -> IO (Either String b)
getB h n = decode <$> BS.hGet h n
