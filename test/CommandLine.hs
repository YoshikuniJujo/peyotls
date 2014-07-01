{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module CommandLine (readOptions) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first)
import Control.Monad (unless)
import Data.Maybe (fromMaybe)
import System.Console.GetOpt (getOpt, ArgOrder(..), OptDescr(..), ArgDescr(..))
import System.Exit (exitFailure)
import Network (PortID(..), PortNumber)
import Network.PeyoTLS.ReadFile ( CertSecretKey,
	readKey, readCertificateChain, readCertificateStore)
import Network.PeyoTLS.Server (CipherSuite(..), KeyExchange(..), BulkEncryption(..))

import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

readOptions :: [String] -> IO (
	PortID,
	[CipherSuite],
	(CertSecretKey, X509.CertificateChain),
	(CertSecretKey, X509.CertificateChain),
	Maybe X509.CertificateStore,
	FilePath )
readOptions args = do
	let (os, as, es) = getOpt Permute options args
	unless (null es) $ mapM_ putStr es >> exitFailure
	unless (null as) $ putStrLn ("naked args: " ++ show as) >> exitFailure
	opts <- either ((>> exitFailure) . putStr) return $ construct os
	let	prt = PortNumber 443 `fromMaybe` optPort opts
		css = maybe id (drop . fromEnum) (optLevel opts) cipherSuites
		td = "test" `fromMaybe` optTestDirectory opts
		rkf = "certFiles/localhost.sample_key" `fromMaybe`
			optRsaKeyFile opts
		rcf = "certFiles/localhost.sample_crt" `fromMaybe`
			optRsaCertFile opts
		ekf = "certFiles/localhost_ecdsa.sample_key" `fromMaybe`
			optEcKeyFile opts
		ecf = "certFiles/localhost_ecdsa.sample_crt" `fromMaybe`
			optEcCertFile opts
	rsa <- (,) <$> readKey rkf <*> readCertificateChain rcf
	ec <- (,) <$> readKey ekf <*> readCertificateChain ecf
	mcs <- if optDisableClientCert opts then return Nothing else Just <$>
		readCertificateStore ["certFiles/cacert.pem"]
	return (prt, css, rsa, ec, mcs, td)

data Options = Options {
	optPort :: Maybe PortID,
	optLevel :: Maybe CipherSuiteLevel,
	optRsaKeyFile :: Maybe FilePath,
	optRsaCertFile :: Maybe FilePath,
	optEcKeyFile :: Maybe FilePath,
	optEcCertFile :: Maybe FilePath,
	optDisableClientCert :: Bool,
	optTestDirectory :: Maybe FilePath }
	deriving Show

nullOptions :: Options
nullOptions = Options {
	optPort = Nothing,
	optLevel = Nothing,
	optRsaKeyFile = Nothing,
	optRsaCertFile = Nothing,
	optEcKeyFile = Nothing,
	optEcCertFile = Nothing,
	optDisableClientCert = False,
	optTestDirectory = Nothing }

construct :: [Option] -> Either String Options
construct [] = return nullOptions
construct (o : os) = do
	c <- construct os
	case o of
		OptPort p -> ck (optPort c) >> return c { optPort = Just p }
		OptDisableClientCert -> if optDisableClientCert c
			then Left "CommandLine.construct: duplicated -d options\n"
			else return c { optDisableClientCert = True }
		OptLevel (NoLevel l) -> Left $
			"CommandLine.construct: no such level " ++ show l ++ "\n"
		OptLevel csl -> ck (optLevel c) >> return c { optLevel = Just csl }
		OptTestDirectory td -> ck (optTestDirectory c) >>
			return c { optTestDirectory = Just td }
		OptRsaKeyFile kf -> ck (optRsaKeyFile c) >>
			return c { optRsaKeyFile = Just kf }
		OptRsaCertFile cf -> ck (optRsaCertFile c) >>
			return c { optRsaCertFile = Just cf }
		OptEcKeyFile ekf -> ck (optEcKeyFile c) >>
			return c { optEcKeyFile = Just ekf }
		OptEcCertFile ecf -> ck (optEcCertFile c) >>
			return c { optEcCertFile = Just ecf }
	where
	ck :: Show a => Maybe a -> Either String ()
	ck = maybe (Right ()) (Left . ("Can't set: already " ++) . (++ "\n") . show)

data Option
	= OptPort PortID
	| OptLevel CipherSuiteLevel
	| OptRsaKeyFile FilePath
	| OptRsaCertFile FilePath
	| OptEcKeyFile FilePath
	| OptEcCertFile FilePath
	| OptDisableClientCert
	| OptTestDirectory FilePath
	deriving (Show, Eq)

options :: [OptDescr Option]
options = [
	Option "p" ["port"]
		(ReqArg (OptPort . PortNumber . read) "port number")
		"set port number",
	Option "l" ["level"]
		(ReqArg (OptLevel . readCipherSuiteLevel) "cipher suite level")
		"set cipher suite level",
	Option "k" ["rsa-key-file"]
		(ReqArg OptRsaKeyFile "RSA key file") "set RSA key file",
	Option "c" ["rsa-cert-file"]
		(ReqArg OptRsaCertFile "RSA cert file") "set RSA cert file",
	Option "K" ["ecdsa-key-file"]
		(ReqArg OptEcKeyFile "ECDSA key file") "set ECDSA key file",
	Option "C" ["ecdsa-cert-file"]
		(ReqArg OptEcCertFile "ECDSA cert file") "set ECDSA cert file",
	Option "d" ["disable-client-cert"]
		(NoArg OptDisableClientCert) "disable client certification",
	Option "t" ["test-directory"]
		(ReqArg OptTestDirectory "test directory") "set test directory" ]

instance Read PortNumber where
	readsPrec n = map (first (fromIntegral :: Int -> PortNumber)) . readsPrec n

data CipherSuiteLevel
	= ToEcdsa256 | ToEcdsa | ToEcdhe256 | ToEcdhe
	| ToDhe256   | ToDhe   | ToRsa256   | ToRsa   | NoLevel String
	deriving (Show, Eq)

instance Enum CipherSuiteLevel where
	toEnum 0 = ToEcdsa256
	toEnum 1 = ToEcdsa
	toEnum 2 = ToEcdhe256
	toEnum 3 = ToEcdhe
	toEnum 4 = ToDhe256
	toEnum 5 = ToDhe
	toEnum 6 = ToRsa256
	toEnum 7 = ToRsa
	toEnum _ = NoLevel ""
	fromEnum ToEcdsa256 = 0
	fromEnum ToEcdsa = 1
	fromEnum ToEcdhe256 = 2
	fromEnum ToEcdhe = 3
	fromEnum ToDhe256 = 4
	fromEnum ToDhe = 5
	fromEnum ToRsa256 = 6
	fromEnum ToRsa = 7
	fromEnum (NoLevel _) = 8

readCipherSuiteLevel :: String -> CipherSuiteLevel
readCipherSuiteLevel "ecdsa256" = ToEcdsa256
readCipherSuiteLevel "ecdsa" = ToEcdsa
readCipherSuiteLevel "ecdhe256" = ToEcdhe256
readCipherSuiteLevel "ecdhe" = ToEcdhe
readCipherSuiteLevel "dhe256" = ToDhe256
readCipherSuiteLevel "dhe" = ToDhe
readCipherSuiteLevel "rsa256" = ToRsa256
readCipherSuiteLevel "rsa" = ToRsa
readCipherSuiteLevel l = NoLevel l

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite DHE_RSA AES_128_CBC_SHA256,
	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA256,
	CipherSuite RSA AES_128_CBC_SHA ]
