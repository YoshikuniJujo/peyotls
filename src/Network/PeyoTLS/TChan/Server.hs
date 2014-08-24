{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.PeyoTLS.TChan.Server (
	-- * Basic
	open,
	-- * Cipher Suite
	CipherSuite(..), KeyEx(..), BulkEnc(..),
	-- * Others
	ValidateHandle(..), CertSecretKey(..) ) where

import Control.Applicative
import "monads-tf" Control.Monad.State
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent
import Control.Concurrent.STM
import Data.Word
import Data.HandleLike
import Data.X509
import Data.X509.CertificateStore
import Network.PeyoTLS.Server.Body hiding (open)
import qualified Network.PeyoTLS.Server.Body as S
import Network.PeyoTLS.Run.Crypto
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable.BigEndian as B

open :: (CPRG g, ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	h -> [CipherSuite] -> [(CertSecretKey, CertificateChain)] ->
	Maybe CertificateStore -> g ->
	HandleMonad h (
		Maybe (String -> Bool),
		(TChan BSC.ByteString, TChan BSC.ByteString))
open h cs kcs ca g = do
			inc <- liftBase $ atomically newTChan
			otc <- liftBase $ atomically newTChan
			((k, ns), g') <- (`run'` g) $ do
				p <- S.open h cs kcs ca
				hlFlush p
			let	rk = kRKey k
				rmk = kRMKey k
				wk = kWKey k
				wmk = kWMKey k
			_ <- liftBaseDiscard forkIO
				. (`evalStateT` 1) . forever $ do
				sn <- get
				modify succ
				pre <- lift $ hlGet h 3
				when (BSC.null pre) $
					lift (hlClose h) >> error "bad"
				Right n <- B.decode <$> lift (hlGet h 2)
				renc <- lift $ hlGet h n
				let Right rpln = decrypt sha1 rk rmk sn pre renc
				liftBase . atomically $ writeTChan inc rpln

			_ <- liftBaseDiscard forkIO
				. (`evalStateT` (1, g')) . forever $ do
				(sn, g0) <- get
				wpln <- liftBase . atomically $ readTChan otc
				let	(wenc, g1) =
						encrypt sha1 wk wmk sn "\ETB\ETX\ETX" wpln g0
				put (succ sn, g1)
				lift $ hlPut h "\ETB\ETX\ETX"
				lift . hlPut h
					. (B.encode :: Word16 -> BSC.ByteString)
					. fromIntegral $ BSC.length wenc
				lift $ hlPut h wenc

			return (toCheckName ns, (inc, otc))
