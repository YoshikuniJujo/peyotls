{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.Ecdsa (blindSign, generateKs) where

import Control.Applicative ((<$>), (<*>))
import Data.Maybe (mapMaybe)
import Data.Bits (shiftR, xor)
import Crypto.Number.ModArithmetic (inverse)

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1

instance B.Bytable ECDSA.Signature where
	encode (ECDSA.Signature r s) = ASN1.encodeASN1' ASN1.DER [
		ASN1.Start ASN1.Sequence,
			ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence ]
	decode bs = case ASN1.decodeASN1' ASN1.DER bs of
		Right [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s,
			ASN1.End ASN1.Sequence] -> Right $ ECDSA.Signature r s
		Right _ -> Left "KeyExchange.decodeSignature"
		Left err -> Left $ "KeyExchange.decodeSignature: " ++ show err

type Hash = BS.ByteString -> BS.ByteString

blindSign :: Integer -> Hash -> ECDSA.PrivateKey -> [Integer] ->
	BS.ByteString -> ECDSA.Signature
blindSign bl hs (ECDSA.PrivateKey crv d) ks m = head $ bs `mapMaybe` ks
	where
	bs k = do
		r <- case bPointMul bl crv k g of
			ECC.PointO -> Nothing
			ECC.Point 0 _ -> Nothing
			ECC.Point x _ -> return $ x `mod` n
		ki <- inverse k n
		case ki * (z + r * d) `mod` n of
			0 -> Nothing
			s -> return $ ECDSA.Signature r s
	ECC.CurveCommon _ _ g n _ = ECC.common_curve crv
	Right e = B.decode $ hs m
	dl = qlen e - qlen n
	z = if dl > 0 then e `shiftR` dl else e

bPointMul :: Integer -> ECC.Curve -> Integer -> ECC.Point -> ECC.Point
bPointMul bl c@(ECC.CurveFP (ECC.CurvePrime _ cc)) k p =
	ECC.pointMul c (bl * ECC.ecc_n cc + k) p
bPointMul _ _ _ _ = error "Ecdsa.bPointMul: not implemented"

-- RFC 6979

generateKs :: (Hash, Int) -> Integer -> Integer -> BS.ByteString -> [Integer]
generateKs hsbl@(hs, _) q x m = filter ((&&) <$> (> 0) <*> (< q)) .
	uncurry (createKs hsbl q) . initializeKV hsbl q x $ hs m

initializeKV :: (Hash, Int) ->
	Integer -> Integer -> BS.ByteString -> (BS.ByteString, BS.ByteString)
initializeKV (hs, bls) q x h = (k2, v2)
	where
	k0 = BS.replicate (BS.length h) 0
	v0 = BS.replicate (BS.length h) 1
	k1 = hmac hs bls k0 $
		BS.concat [v0, "\x00", int2octets q x, bits2octets q h]
	v1 = hmac hs bls k1 v0
	k2 = hmac hs bls k1 $
		BS.concat [v1, "\x01", int2octets q x, bits2octets q h]
	v2 = hmac hs bls k2 v1

createKs :: (Hash, Int) -> Integer -> BS.ByteString -> BS.ByteString -> [Integer]
createKs hsbl@(hs, bls) q k v = kk : createKs hsbl q k' v''
	where
	(t, v') = createT hsbl q k v ""
	kk = bits2int q t
	k' = hmac hs bls k $ v' `BS.append` "\x00"
	v'' = hmac hs bls k' v'

createT :: (Hash, Int) -> Integer -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> (BS.ByteString, BS.ByteString)
createT hsbl@(hs, bls) q k v t
	| blen t < qlen q = createT hsbl q k v' $ t `BS.append` v'
	| otherwise = (t, v)
	where
	v' = hmac hs bls k v

hmac :: (BS.ByteString -> BS.ByteString) -> Int ->
	BS.ByteString -> BS.ByteString -> BS.ByteString
hmac hs bls sk =
	hs . BS.append (BS.map (0x5c `xor`) k) .
	hs . BS.append (BS.map (0x36 `xor`) k)
	where
       	k = padd $ if BS.length sk > bls then hs sk else sk
	padd bs = bs `BS.append` BS.replicate (bls - BS.length bs) 0

qlen :: Integer -> Int
qlen 0 = 0
qlen q = succ . qlen $ q `shiftR` 1

rlen :: Integer -> Int
rlen 0 = 0
rlen q = 8 + rlen (q `shiftR` 8)

blen :: BS.ByteString -> Int
blen = (8 *) . BS.length

bits2int :: Integer -> BS.ByteString -> Integer
bits2int q bs
	| bl > ql = i `shiftR` (bl - ql)
	| otherwise = i
	where
	ql = qlen q
	bl = blen bs
	i = either error id $ B.decode bs

int2octets :: Integer -> Integer -> BS.ByteString
int2octets q i
	| bl <= rl = BS.replicate (rl - bl) 0 `BS.append` bs
	| otherwise = error "Functions.int2octets: too large integer"
	where
	rl = rlen q `div` 8
	bs = B.encode i
	bl = BS.length bs

bits2octets :: Integer -> BS.ByteString -> BS.ByteString
bits2octets q bs = int2octets q $ bits2int q bs `mod` q
