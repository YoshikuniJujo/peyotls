module Network.PeyoTLS.CertSecretKey (
	CertSecretKey(..), isRsaKey, isEcdsaKey ) where

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

data CertSecretKey
	= RsaKey { rsaKey :: RSA.PrivateKey }
	| EcdsaKey { ecdsaKey :: ECDSA.PrivateKey }
	deriving Show

isEcdsaKey :: CertSecretKey -> Bool
isEcdsaKey (EcdsaKey _) = True
isEcdsaKey _ = False

isRsaKey :: CertSecretKey -> Bool
isRsaKey (RsaKey _) = True
isRsaKey _ = False
