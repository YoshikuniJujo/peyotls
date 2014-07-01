{-# LANGUAGE OverloadedStrings, PackageImports, TupleSections #-}

module Network.PeyoTLS.CryptoTools (
	makeKeys, encrypt, decrypt, hashSha1, hashSha256, finishedHash) where

import Prelude hiding (splitAt, take)

import Control.Arrow (first)
import Data.Bits (xor)
import Data.Word (Word8, Word16, Word64)
import "crypto-random" Crypto.Random (CPRG, cprgGenerate)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Cipher.AES as AES

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

makeKeys :: Int -> BS.ByteString -> BS.ByteString -> BS.ByteString ->
	(BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString)
makeKeys kl cr sr pms = let
	kls = [kl, kl, 16, 16]
	ms = take 48 . prf pms $ BS.concat ["master secret", cr, sr]
	ems = prf ms $ BS.concat ["key expansion", sr, cr]
	[cwmk, swmk, cwk, swk] = divide kls ems in
	(ms, cwmk, swmk, cwk, swk)
	where
	divide [] _ = []
	divide (n : ns) bs
		| BSL.null bs = []
		| otherwise = let (x, bs') = splitAt n bs in x : divide ns bs'

prf :: BS.ByteString -> BS.ByteString -> BSL.ByteString
prf sk sd = BSL.fromChunks . ph $ hm sk sd
	where
	hm = hmac SHA256.hash 64
	ph a = hm sk (a `BS.append` sd) : ph (hm sk a)

hmac :: (BS.ByteString -> BS.ByteString) -> Int ->
	BS.ByteString -> BS.ByteString -> BS.ByteString
hmac hs bls sk =
	hs . BS.append (BS.map (0x5c `xor`) k) .
	hs . BS.append (BS.map (0x36 `xor`) k)
	where
	k = pd $ if BS.length sk > bls then hs sk else sk
	pd bs = bs `BS.append` BS.replicate (bls - BS.length bs) 0

type Hash = BS.ByteString -> BS.ByteString

hashSha1, hashSha256 :: (Hash, Int)
hashSha1 = (SHA1.hash, 20)
hashSha256 = (SHA256.hash, 32)

encrypt :: CPRG g => (Hash, Int) -> BS.ByteString -> BS.ByteString -> Word64 ->
	BS.ByteString -> BS.ByteString -> g -> (BS.ByteString, g)
encrypt (hs, _) k mk sn p m g = (, g') $
	iv `BS.append` AES.encryptCBC (AES.initAES k) iv (pln `BS.append` pd)
	where
	(iv, g') = cprgGenerate 16 g
	pln = m `BS.append` calcMac hs mk sn (p `BS.append` B.addLen w16 m)
	l = 16 - (BS.length pln + 1) `mod` 16
	pd = BS.replicate (l + 1) $ fromIntegral l

decrypt :: (Hash, Int) ->
	BS.ByteString -> BS.ByteString -> Word64 ->
	BS.ByteString -> BS.ByteString -> Either String BS.ByteString
decrypt (hs, ml) k mk sn p enc = if rm == em then Right b else Left $ if BS.null enc
	then "CryptoTools.decrypt: enc is null\n"
	else "CryptoTools.decrypt: bad MAC:" ++
		"\n\tsn: " ++ show sn ++
		"\n\tplain: " ++ BSC.unpack pln ++
		"\n\tExpected: " ++ BSC.unpack em ++
		"\n\tRecieved: " ++ BSC.unpack rm ++
		"\n\tml: " ++ show ml ++ "\n"
	where
	pln = uncurry (AES.decryptCBC $ AES.initAES k) $ BS.splitAt 16 enc
	up = BS.take (BS.length pln - fromIntegral (myLast "decrypt" pln) - 1) pln
	(b, rm) = BS.splitAt (BS.length up - ml) up
	em = calcMac hs mk sn $ p `BS.append` B.addLen w16 b

calcMac :: Hash -> BS.ByteString -> Word64 -> BS.ByteString -> BS.ByteString
calcMac hs mk sn m = hmac hs 64 mk $ B.encode sn `BS.append` m

finishedHash :: Bool -> BS.ByteString -> BS.ByteString -> BS.ByteString
finishedHash c ms hash = take 12 . prf ms . (`BS.append` hash) $ if c
	then "client finished"
	else "server finished"

myLast :: String -> BS.ByteString -> Word8
myLast msg "" = error msg
myLast _ bs = BS.last bs

take :: Int -> BSL.ByteString -> BS.ByteString
take = (fst .) . splitAt

splitAt :: Int -> BSL.ByteString -> (BS.ByteString, BSL.ByteString)
splitAt n = first BSL.toStrict . BSL.splitAt (fromIntegral n)

w16 :: Word16; w16 = undefined
