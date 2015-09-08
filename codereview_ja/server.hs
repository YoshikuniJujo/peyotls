{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import Data.Word
import System.IO
import Network
import Network.PeyoTLS.Run.State
import Network.PeyoTLS.Codec
import Codec.Bytable.BigEndian

import qualified Data.ByteString as BS

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 443
	(h, _, _) <- accept soc
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String ProtocolVersion -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	print (decode bs :: Either String Handshake)

getB :: Bytable b => Handle -> Int -> IO (Either String b)
getB h n = decode <$> BS.hGet h n
