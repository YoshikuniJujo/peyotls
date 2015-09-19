{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import Control.Concurrent
import Data.Word
import Data.IORef
import System.IO
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Server
import qualified Network.PeyoTLS.Run.Crypto as C
import Network.PeyoTLS.Codec
import Network.PeyoTLS.Codec.Alert
import qualified Codec.Bytable.BigEndian as B
import "crypto-random" Crypto.Random
import Crypto.Hash.SHA256 as SHA256
import Crypto.PubKey.RSA.PKCS15 as RSA

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = do
	cc <- readCertificateChain ["codereview_ja/newcert.pem"]
	sk <- readKey "codereview_ja/newkey_dec.pem"
	soc <- listenOn $ PortNumber 443
	forever $ do
--	2 `timesDo_` do
		(h, _, _) <- accept soc
		forkIO $ send True h cc sk
--		(h, _, _) <- accept soc
--		send True h cc sk

timesDo_ :: Monad m => Int -> m a -> m ()
timesDo_ 0 a = return ()
timesDo_ n a = a >> timesDo_ (n - 1) a

send b h cc sk = do
	hs <- newIORef ""
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	modifyIORef hs (`BS.append` bs)
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
	let sh = B.encode hl
--			B.encode hl `BS.append` B.encode (toHandshake cc) ]
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) sh ]
	modifyIORef hs (`BS.append` sh)
	let bs = B.encode $ toHandshake cc
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) bs ]
	modifyIORef hs (`BS.append` bs)
	let bs = B.encode $ toHandshake SHDone
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) bs ]
	modifyIORef hs (`BS.append` bs)
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	modifyIORef hs (`BS.append` bs)
	let Right (Just (Epms epms)) = fromHandshake <$> B.decode bs
	g <- cprgCreate <$> createEntropyPool
	let	Right pms = fst $ RSA.decryptSafer (g :: SystemRNG) (rsaKey sk) epms
		(ms, cwmk, swmk, cwk, swk) = C.makeKeys 20 cr sr pms
	print pms
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	readIORef hs >>= print . SHA256.hash
	putStr "ClientFinished: "
	readIORef hs >>= print . LBS.take 12 . C.prf ms . ("client finished" `BS.append`) . SHA256.hash
--	modifyIORef hs (`BS.append` bs)
	Right ct <- getB h 1
	(print :: ContType -> IO ()) ct
	Right vrsn <- getB h 2
	(print :: PrtVrsn -> IO ()) vrsn
	Right n <- getB h 2
	ef <- BS.hGet h n
	print ef
	let Right f = C.decrypt C.sha1 cwk cwmk 0
		(B.encode ct `BS.append` B.encode vrsn) ef
	print f
	putStrLn "here"
	modifyIORef hs (`BS.append` f)
	sf <- LBS.take 12 . C.prf ms . ("server finished" `BS.append`) . SHA256.hash <$> readIORef hs
	print sf
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let (esf, g') = C.encrypt C.sha1 swk swmk 0
		(B.encode CTHandshake `BS.append` B.encode (PrtVrsn 3 3))
			(B.encode . toHandshake . Finished $ LBS.toStrict sf) g
	BS.hPut h $ BS.concat [
		B.encode CTCCSpec,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) . B.encode $ toHandshake CCSpec
		]
	putStrLn "here"
	when b $ do
		BS.hPut h $ BS.concat [
			B.encode CTHandshake,
			B.encode $ PrtVrsn 3 3,
			B.addLen (undefined :: Word16) esf
			]
		getB h 1 >>= (print :: Either String ContType -> IO ())
		getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
		Right n <- getB h 2
		ebs <- BS.hGet h n
		let Right bs = C.decrypt C.sha1 cwk cwmk 1
			(B.encode CTAppData `BS.append` B.encode vrsn) ebs
		BS.putStr bs

getB :: B.Bytable b => Handle -> Int -> IO (Either String b)
getB h n = B.decode <$> BS.hGet h n

serverRandom :: IO BS.ByteString
serverRandom = fst . cprgGenerate 32 <$>
	(cprgCreate <$> createEntropyPool :: IO SystemRNG)

hello :: BS.ByteString -> Handshake
hello sr = toHandshake $ SvHello (PrtVrsn 3 3) sr (SssnId "")
	"TLS_RSA_WITH_AES_128_CBC_SHA" CmpMtdNull Nothing
