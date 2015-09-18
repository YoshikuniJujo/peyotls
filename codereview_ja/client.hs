{-# LANGUAGE PackageImports, OverloadedStrings #-}

import Control.Applicative
import Control.Arrow
import Data.Word
import Data.X509 (CertificateChain, Certificate(..))
import Data.IORef
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import System.IO
import Network
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Run.Crypto as C
import Network.PeyoTLS.Codec
import Network.PeyoTLS.Codec.ContentTypes
import qualified Codec.Bytable.BigEndian as B
import "crypto-random" Crypto.Random (
	SystemRNG, cprgGenerate, cprgCreate, createEntropyPool)
import Crypto.Hash.SHA256 as SHA256
import Crypto.PubKey.RSA.PKCS15 as RSA

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = do
	cs <- readCertificateStore ["codereview_ja/cacert.pem"]
	h <- connectTo "localhost" $ PortNumber 443
	log <- newIORef ""
	cr <- clientRandom
	let hl = hello cr
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) $ B.encode hl ]
	modifyIORef log (`BS.append` B.encode hl)
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	modifyIORef log (`BS.append` bs)
	let	Right (Just sh@(SvHello _ sr _ _ _ _)) =
			fromHandshake <$> (B.decode bs :: Either String Handshake)
	print sh -- (B.decode bs :: Either String Handshake)
	getB h 1 >>= (print :: Either String ContType -> IO ())
	getB h 2 >>= (print :: Either String PrtVrsn -> IO ())
	Right n <- getB h 2
	bs <- BS.hGet h n
	modifyIORef log (`BS.append` bs)
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
	modifyIORef log (`BS.append` bs)
	print (B.decode bs :: Either String Handshake)
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(pms, g') = ("\ETX\ETX" `BS.append`) `first` (cprgGenerate 46 g)
		X509.CertificateChain (cc1 : _) = cc
		X509.PubKeyRSA pk = X509.certPubKey . X509.signedObject $ X509.getSigned cc1
		(Right epms, g'') = RSA.encrypt g' pk pms
		(ms, cwmk, swmk, cwk, swk) = C.makeKeys 20 cr sr pms
	print pms
	print epms
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) . B.encode . toHandshake $ Epms epms ]
	modifyIORef log (`BS.append` (B.encode . toHandshake $ Epms epms))
	BS.hPut h $ BS.concat [
		B.encode CTCCSpec,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) . B.encode $ toHandshake CCSpec
		]
	readIORef log >>= print . SHA256.hash
	f <- LBS.take 12 . C.prf ms . ("client finished" `BS.append`) . SHA256.hash
		<$> readIORef log
	print f
	let (ef, g''') = C.encrypt C.sha1 cwk cwmk 0
		(B.encode CTHandshake `BS.append` B.encode (PrtVrsn 3 3)) 
			(B.encode . toHandshake . Finished $ LBS.toStrict f) g''
	print ef
	BS.hPut h $ BS.concat [
		B.encode CTHandshake,
		B.encode $ PrtVrsn 3 3,
		B.addLen (undefined :: Word16) ef
		]
	modifyIORef log
		(`BS.append` (B.encode . toHandshake . Finished $ LBS.toStrict f))
	Right ct <- getB h 1
	(print :: ContType -> IO ()) ct
	Right vrsn <- getB h 2
	(print :: PrtVrsn -> IO ()) vrsn
	Right n <- getB h 2
	BS.hGet h n >>= print
	Right ct <- getB h 1
	(print :: ContType -> IO ()) ct
	Right vrsn <- getB h 2
	(print :: PrtVrsn -> IO ()) vrsn
	Right n <- getB h 2
	esf <- BS.hGet h n
	print . either Left (B.decode :: BS.ByteString -> Either String Handshake)
		$ C.decrypt C.sha1 swk swmk 0
		(B.encode ct `BS.append` B.encode vrsn) esf
	readIORef log >>= print . LBS.take 12 . C.prf ms . ("server finished" `BS.append`) . SHA256.hash

clientRandom :: IO BS.ByteString
clientRandom = fst . cprgGenerate 32 <$>
	(cprgCreate <$> createEntropyPool :: IO SystemRNG)

hello :: BS.ByteString -> Handshake
hello cr = toHandshake $ ClHello (PrtVrsn 3 3) cr (SssnId "") [
		"TLS_RSA_WITH_AES_128_CBC_SHA"
	] [CmpMtdNull] Nothing

getB :: B.Bytable b => Handle -> Int -> IO (Either String b)
getB h n = B.decode <$> BS.hGet h n
