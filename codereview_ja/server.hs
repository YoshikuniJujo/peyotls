{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import Data.Word
import System.IO
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Server
import qualified Network.PeyoTLS.Run.Crypto as C
import Network.PeyoTLS.Codec
import Network.PeyoTLS.Codec.Alert
import qualified Codec.Bytable.BigEndian as B
import "crypto-random" Crypto.Random
import Crypto.PubKey.RSA.PKCS15 as RSA

import qualified Data.ByteString as BS

main :: IO ()
main = do
	cc <- readCertificateChain ["codereview_ja/newcert.pem"]
	sk <- readKey "codereview_ja/newkey_dec.pem"
	soc <- listenOn $ PortNumber 443
	(h, _, _) <- accept soc
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	sr <- serverRandom
	let	hl = hello sr
		Right (Just ch@(ClHello pv cr _ _ _ _)) =
			fromHandshake <$> (B.decode bs :: Either String Handshake)
	when (pv < PrtVrsn 3 3) $ do
	{-
		BS.hPut h $ BS.concat [
			B.encode CTAlert,
			B.encode $ PrtVrsn 3 3,
			B.addLen (undefined :: Word16)
				$ B.encode $ Alert ALFtl ADProtoVer "" ]
		BS.hGet h 1 >>= print
--		getB h 1 >>= (print :: Either String ContType -> IO ())
--		-}
		error "bad"
	putStrLn $ take 50 (show (ch :: ClHello)) ++ "..."
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) $
--			B.encode hl `BS.append` B.encode (toHandshake cc) ]
			B.encode hl ]
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) . B.encode $ toHandshake cc ]
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) . B.encode $ toHandshake SHDone ]
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	Right (Just (Epms epms)) <- (fromHandshake <$>) <$> getB h n
	g <- cprgCreate <$> createEntropyPool
	let	Right pms = fst $ RSA.decryptSafer (g :: SystemRNG) (rsaKey sk) epms
		(ms, cwmk, swmk, cwk, swk) = C.makeKeys 20 cr sr pms
	print pms
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	BS.hGet h n >>= print
	Right ct <- getB h 1
	(print :: ContType -> IO ()) ct
	Right vrsn <- getB h 2
	(print :: PrtVrsn -> IO ()) vrsn
	Right n <- getB h 2
	ef <- BS.hGet h n
--	print ef
	print . either Left (B.decode :: BS.ByteString -> Either String Handshake)
		$ C.decrypt C.sha1 cwk cwmk 0
		(B.encode ct `BS.append` B.encode vrsn) ef

getB :: B.Bytable b => Handle -> Int -> IO (Either String b)
getB h n = B.decode <$> BS.hGet h n

serverRandom :: IO BS.ByteString
serverRandom = fst . cprgGenerate 32 <$>
	(cprgCreate <$> createEntropyPool :: IO SystemRNG)

hello :: BS.ByteString -> Handshake
hello sr = toHandshake $ SvHello (PrtVrsn 3 3) sr (SssnId "")
	"TLS_RSA_WITH_AES_128_CBC_SHA" CmpMtdNull Nothing
