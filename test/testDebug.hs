{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

import Control.Applicative
import Control.Monad
import Control.Concurrent
import "crypto-random" Crypto.Random

import TestClient
import Data.HandleLike

import Control.Concurrent.STM
import qualified Data.ByteString as BS
import System.IO
import CommandLine
import System.Environment

import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import TestServer
import System.Random

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite DHE_RSA AES_128_CBC_SHA256,
	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA256,
	CipherSuite RSA AES_128_CBC_SHA
 ]

randomFrom :: [a] -> IO [a]
randomFrom [] = return []
randomFrom (x : xs) = do
	b <- randomIO
	(if b then (x :) else id) <$> randomFrom xs

len :: Int
len = length cipherSuites - 1

main :: IO ()
main = do
	b <- randomIO
	forM_ ["low" .. "critical"] $ \p -> do
		print p
		(if b then runRsa p else ecdsa p) =<< randomFrom cipherSuites

runRsa :: Priority -> [CipherSuite] -> IO ()
runRsa p cs = do
	(cw, sw) <- getPair p
	_ <- forkIO $ srv sw cs
	(rsk, rcc, crtS) <- readFiles
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw [(rsk, rcc)] crtS

ecdsa :: Priority -> [CipherSuite] -> IO ()
ecdsa p cs = do
	(cw, sw) <- getPair p
	_ <- forkIO $ srv sw cs
	(rsk, rcc, crtS) <- readFilesEcdsa
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw [(rsk, rcc)] crtS

srv :: ChanHandle -> [CipherSuite] -> IO ()
srv sw cs = do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(_prt, _cs, rsa, ec, mcs, _td) <- readOptions =<< getArgs
	server g sw cs rsa ec mcs

readFiles :: IO (CertSecretKey, X509.CertificateChain, X509.CertificateStore)
readFiles = (,,)
	<$> readPathKey "certs/yoshikuni.sample_key"
	<*> readPathCertificateChain "certs/yoshikuni.sample_crt"
	<*> readPathCertificateStore ["certs/cacert.pem"]

readFilesEcdsa :: IO
	(CertSecretKey, X509.CertificateChain, X509.CertificateStore)
readFilesEcdsa = (,,)
	<$> readPathKey "certs/client_ecdsa.sample_key"
	<*> readPathCertificateChain "certs/client_ecdsa.sample_crt"
	<*> readPathCertificateStore ["certs/cacert.pem"]

data ChanHandle = ChanHandle (TChan BS.ByteString) (TChan BS.ByteString) Priority

instance HandleLike ChanHandle where
	type HandleMonad ChanHandle = IO
	hlPut (ChanHandle _ w _) = atomically . writeTChan w
	hlGet h@(ChanHandle r _ _) n = do
		(b, l, bs) <- atomically $ do
			bs <- readTChan r
			let l = BS.length bs
			if l < n
				then return (True, l, bs)
				else do	let (x, y) = BS.splitAt n bs
					unGetTChan r y
					return (False, l, x)
		if b	then (bs `BS.append`) <$> hlGet h (n - l)
			else return bs
	hlDebug (ChanHandle _ _ p) dl
		| dl >= p = BS.putStr
		| otherwise = const $ return ()
	hlClose _ = return ()

instance ValidateHandle ChanHandle where
	validate _ = validate (undefined :: Handle)

getPair :: Priority -> IO (ChanHandle, ChanHandle)
getPair p = do
	c1 <- newTChanIO
	c2 <- newTChanIO
	return (ChanHandle c1 c2 p, ChanHandle c2 c1 p)
