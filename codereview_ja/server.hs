{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Data.Word
import System.IO
import Network
import Network.PeyoTLS.Codec
import Network.PeyoTLS.Codec.ContentTypes
import Codec.Bytable.BigEndian
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 443
	(h, _, _) <- accept soc
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String ProtocolVersion -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	hl <- hello <$> serverRandom
	print (decode bs :: Either String Handshake)
	BS.hPut h $ BS.concat [
		encode CTHandshake,
		"\x03\x03",
		addLen (undefined :: Word16) $ encode hl ]

getB :: Bytable b => Handle -> Int -> IO (Either String b)
getB h n = decode <$> BS.hGet h n

serverRandom :: IO BS.ByteString
serverRandom = fst . cprgGenerate 32 <$>
	(cprgCreate <$> createEntropyPool :: IO SystemRNG)

hello :: BS.ByteString -> Handshake
hello sr = HSvHello $ SvHello (3, 3) sr (SssnId "")
	"TLS_RSA_WITH_AES_128_CBC_SHA" CmpMtdNull Nothing
