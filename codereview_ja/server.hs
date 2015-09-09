{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import Data.Word
import System.IO
import Network
import Network.PeyoTLS.Codec
import Network.PeyoTLS.Codec.Alert
import Codec.Bytable.BigEndian
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 443
	(h, _, _) <- accept soc
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	hl <- hello <$> serverRandom
	let Right (Just ch@(ClHello pv _ _ _ _ _)) =
		fromHandshake <$> (decode bs :: Either String Handshake)
	when (pv < PrtVrsn 3 3) $ do
	{-
		BS.hPut h $ BS.concat [
			encode CTAlert,
			encode $ PrtVrsn 3 3,
			addLen (undefined :: Word16)
				$ encode $ Alert ALFtl ADProtoVer "" ]
		BS.hGet h 1 >>= print
--		getB h 1 >>= (print :: Either String ContType -> IO ())
--		-}
		error "bad"
	print (ch :: ClHello)
	BS.hPut h $ BS.concat [
		encode CTHandshake,
		encode $ PrtVrsn 3 3,
		addLen (undefined :: Word16) $ encode hl ]
--	getB h 1 >>= (print :: Either String ContType -> IO ())

getB :: Bytable b => Handle -> Int -> IO (Either String b)
getB h n = decode <$> BS.hGet h n

serverRandom :: IO BS.ByteString
serverRandom = fst . cprgGenerate 32 <$>
	(cprgCreate <$> createEntropyPool :: IO SystemRNG)

hello :: BS.ByteString -> Handshake
hello sr = toHandshake $ SvHello (PrtVrsn 3 3) sr (SssnId "")
	"TLS_RSA_WITH_AES_128_CBC_SHA" CmpMtdNull Nothing
