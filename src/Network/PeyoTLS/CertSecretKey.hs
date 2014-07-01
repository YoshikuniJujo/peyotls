module Network.PeyoTLS.CertSecretKey (CertSecretKey(..)) where

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

data CertSecretKey = RsaKey RSA.PrivateKey | EcdsaKey ECDSA.PrivateKey
	deriving Show
