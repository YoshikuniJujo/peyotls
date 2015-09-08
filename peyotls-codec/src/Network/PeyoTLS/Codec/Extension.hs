{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.Codec.Extension (
	Extension(..), isRnInfo, emptyRnInfo, SignAlg(..), HashAlg(..) ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits (shiftL, (.|.))
import Data.Word (Word8, Word16)

import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import Network.PeyoTLS.Codec.HSAlg(HSAlg, HashAlg(..), SignAlg(..))

modNm :: String
modNm = "Network.PeyoTLS.Codec.Extension"

-- RFC 5246 7.4.1.4. Hello Wxtensions
--
-- struct {
-- 	ExtensionType extension_type;
-- 	opaque extension_data<0..2^16-1>;
-- } Extension;
--
-- enum {
-- 	signature_algorithms(13), (65535)
-- } ExtensionType

data Extension
	= ESName [SName]
	| EECrv [ECC.CurveName]     | EEPFrmt [EPFrmt]
	| ESAlg [HSAlg]       | ESsnTcktTls BS.ByteString
	| ENxPrtNego BS.ByteString  | ERnInfo BS.ByteString
	| ERaw EType BS.ByteString
	deriving (Show, Eq)

instance B.Bytable Extension where
	encode (ESName n) = B.encode . ERaw TSName . B.addLen w16 $ cmap B.encode n
	encode (EECrv c) = B.encode . ERaw TECrv . B.addLen w16 $ cmap B.encode c
	encode (EEPFrmt f) = B.encode . ERaw TEPFrmt . B.addLen w8 $ cmap B.encode f
	encode (ESAlg sa) = B.encode . ERaw TESAlg . B.addLen w16 $ cmap B.encode sa
	encode (ESsnTcktTls t) = B.encode $ ERaw TSsnTcktTls t
	encode (ENxPrtNego n) = B.encode $ ERaw TNxPrtNego n
	encode (ERnInfo i) = B.encode . ERaw TRnInfo $ B.addLen w8 i
	encode (ERaw t e) = B.encode t `BS.append` B.addLen w16 e
	decode = B.evalBytableM B.parse

instance B.Parsable Extension where
	parse = (,) <$> B.take 2 <*> B.take 2 >>= \(t, l) -> case t of
		TSName -> ESName <$> (flip B.list B.parse =<< B.take 2)
		TECrv -> EECrv <$> (flip B.list (B.take 2) =<< B.take 2)
		TEPFrmt -> EEPFrmt <$> (flip B.list (B.take 1) =<< B.take 1)
		TESAlg -> ESAlg <$> (flip B.list (B.take 2) =<< B.take 2)
		TSsnTcktTls -> ESsnTcktTls <$> B.take l
		TNxPrtNego -> ENxPrtNego <$> B.take l
		TRnInfo -> ERnInfo <$> (B.take =<< B.take 1)
		_ -> ERaw t <$> B.take l

cmap :: (a -> BS.ByteString) -> [a] -> BS.ByteString
cmap = (BS.concat .) . map

data EType
	= TSName     | TECrv   | TEPFrmt | TESAlg | TSsnTcktTls
	| TNxPrtNego | TRnInfo | TRaw Word16 deriving (Show, Eq)

instance B.Bytable EType where
	encode TSName = B.encode (0 :: Word16)
	encode TECrv = B.encode (10 :: Word16)
	encode TEPFrmt = B.encode (11 :: Word16)
	encode TESAlg = B.encode (13 :: Word16)
	encode TSsnTcktTls = B.encode (35 :: Word16)
	encode TNxPrtNego = B.encode (13172 :: Word16)
	encode TRnInfo = B.encode (65281 :: Word16)
	encode (TRaw et) = B.encode et
	decode bs = case BS.unpack bs of
		[w1, w2] -> Right $
			case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
				0 -> TSName
				10 -> TECrv
				11 -> TEPFrmt
				13 -> TESAlg
				35 -> TSsnTcktTls
				13172 -> TNxPrtNego
				65281 -> TRnInfo
				et -> TRaw et
		_ -> Left $ modNm ++ ": EType.decode"

data SName = SNHName BS.ByteString | SNRaw NType BS.ByteString deriving (Show, Eq)

instance B.Bytable SName where
	encode (SNHName nm) = B.encode $ SNRaw NTHName nm
	encode (SNRaw nt nm) = B.encode nt `BS.append` B.addLen w16 nm
	decode = B.evalBytableM B.parse

instance B.Parsable SName where
	parse = (\t n -> case t of NTHName -> SNHName n; _ -> SNRaw t n)
		<$> B.take 1 <*> (B.take =<< B.take 2)

data NType = NTHName | NTRaw Word8 deriving (Show, Eq)

instance B.Bytable NType where
	encode NTHName = BS.pack [0]
	encode (NTRaw t) = BS.pack [t]
	decode bs = case BS.unpack bs of
		[t] -> Right $ case t of 0 -> NTHName; _ -> NTRaw t
		_ -> Left $ modNm ++ ": NType.decode"

instance B.Bytable DH.Params where
	encode (DH.Params p g) = BS.concat
		[B.addLen w16 $ B.encode p, B.addLen w16 $ B.encode g]
	decode = B.evalBytableM B.parse

instance B.Parsable DH.Params where
	parse = DH.Params <$> (B.take =<< B.take 2) <*> (B.take =<< B.take 2)

instance B.Bytable DH.PublicNumber where
	encode = B.addLen w16 . B.encode . \(DH.PublicNumber pn) -> pn
	decode = B.evalBytableM B.parse

instance B.Parsable DH.PublicNumber where
	parse = fromInteger <$> (B.take =<< B.take 2)

data ECType = ExpPrm | ExpCh2 | NmdCrv | CRaw Word8 deriving Show

instance B.Bytable ECType where
	encode ExpPrm = BS.pack [1]
	encode ExpCh2 = BS.pack [2]
	encode NmdCrv = BS.pack [3]
	encode (CRaw w) = BS.pack [w]
	decode = B.evalBytableM B.parse

instance B.Parsable ECType where
	parse = (\t -> case t of 1 -> ExpPrm; 2 -> ExpCh2; 3 -> NmdCrv; _ -> CRaw t)
		<$> B.head

instance B.Bytable ECC.CurveName where
	encode ECC.SEC_t163k1 = B.encode (1 :: Word16)
	encode ECC.SEC_t163r1 = B.encode (2 :: Word16)
	encode ECC.SEC_t163r2 = B.encode (3 :: Word16)
	encode ECC.SEC_t193r1 = B.encode (4 :: Word16)
	encode ECC.SEC_t193r2 = B.encode (5 :: Word16)
	encode ECC.SEC_t233k1 = B.encode (6 :: Word16)
	encode ECC.SEC_t233r1 = B.encode (7 :: Word16)
	encode ECC.SEC_t239k1 = B.encode (8 :: Word16)
	encode ECC.SEC_t283k1 = B.encode (9 :: Word16)
	encode ECC.SEC_t283r1 = B.encode (10 :: Word16)
	encode ECC.SEC_t409k1 = B.encode (11 :: Word16)
	encode ECC.SEC_t409r1 = B.encode (12 :: Word16)
	encode ECC.SEC_t571k1 = B.encode (13 :: Word16)
	encode ECC.SEC_t571r1 = B.encode (14 :: Word16)
	encode ECC.SEC_p160k1 = B.encode (15 :: Word16)
	encode ECC.SEC_p160r1 = B.encode (16 :: Word16)
	encode ECC.SEC_p160r2 = B.encode (17 :: Word16)
	encode ECC.SEC_p192k1 = B.encode (18 :: Word16)
	encode ECC.SEC_p192r1 = B.encode (19 :: Word16)
	encode ECC.SEC_p224k1 = B.encode (20 :: Word16)
	encode ECC.SEC_p224r1 = B.encode (21 :: Word16)
	encode ECC.SEC_p256k1 = B.encode (22 :: Word16)
	encode ECC.SEC_p256r1 = B.encode (23 :: Word16)
	encode ECC.SEC_p384r1 = B.encode (24 :: Word16)
	encode ECC.SEC_p521r1 = B.encode (25 :: Word16)
	encode _ = error "Extension.encodeCN: not implemented"
	decode bs = case BS.unpack bs of
		[w1, w2] -> case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
			(1 :: Word16) -> Right ECC.SEC_t163k1
			(2 :: Word16) -> Right ECC.SEC_t163r1
			(3 :: Word16) -> Right ECC.SEC_t163r2
			(4 :: Word16) -> Right ECC.SEC_t193r1
			(5 :: Word16) -> Right ECC.SEC_t193r2
			(6 :: Word16) -> Right ECC.SEC_t233k1
			(7 :: Word16) -> Right ECC.SEC_t233r1
			(8 :: Word16) -> Right ECC.SEC_t239k1
			(9 :: Word16) -> Right ECC.SEC_t283k1
			(10 :: Word16) -> Right ECC.SEC_t283r1
			(11 :: Word16) -> Right ECC.SEC_t409k1
			(12 :: Word16) -> Right ECC.SEC_t409r1
			(13 :: Word16) -> Right ECC.SEC_t571k1
			(14 :: Word16) -> Right ECC.SEC_t571r1
			(15 :: Word16) -> Right ECC.SEC_p160k1
			(16 :: Word16) -> Right ECC.SEC_p160r1
			(17 :: Word16) -> Right ECC.SEC_p160r2
			(18 :: Word16) -> Right ECC.SEC_p192k1
			(19 :: Word16) -> Right ECC.SEC_p192r1
			(20 :: Word16) -> Right ECC.SEC_p224k1
			(21 :: Word16) -> Right ECC.SEC_p224r1
			(22 :: Word16) -> Right ECC.SEC_p256k1
			(23 :: Word16) -> Right ECC.SEC_p256r1
			(24 :: Word16) -> Right ECC.SEC_p384r1
			(25 :: Word16) -> Right ECC.SEC_p521r1
			n -> Left $ modNm ++ ": CurveName.decode: unknown crv: " ++
				show n
		_ -> Left $ modNm ++ ": CurveName.decode: bad format"

instance B.Parsable ECC.CurveName where parse = B.take 2

instance B.Bytable ECC.Curve where
	encode c
		| c == ECC.getCurveByName ECC.SEC_p256r1 =
			B.encode NmdCrv `BS.append` B.encode ECC.SEC_p256r1
		| c == ECC.getCurveByName ECC.SEC_p384r1 =
			B.encode NmdCrv `BS.append` B.encode ECC.SEC_p384r1
		| c == ECC.getCurveByName ECC.SEC_p521r1 =
			B.encode NmdCrv `BS.append` B.encode ECC.SEC_p521r1
		| otherwise = error $ modNm ++ ": ECC.Curve.encode: not implemented"
	decode = B.evalBytableM B.parse

instance B.Parsable ECC.Curve where
	parse = (ECC.getCurveByName <$>) $ B.parse >>= \t -> case t of
		NmdCrv -> B.parse
		_ -> error $ modNm ++ ": ECC.Curve.parse: not implemented"

data EPFrmt = EPFUncomp | EPFRaw Word8 deriving (Show, Eq)

instance B.Bytable EPFrmt where
	encode EPFUncomp = BS.pack [0]
	encode (EPFRaw f) = BS.pack [f]
	decode bs = case BS.unpack bs of
		[f] -> Right $ case f of 0 -> EPFUncomp; _ -> EPFRaw f
		_ -> Left $ modNm ++ ": Bytable.decode"

instance B.Bytable ECC.Point where
	encode (ECC.Point x y) = B.addLen w8 $
		4 `BS.cons` pad 32 0 (B.encode x) `BS.append` pad 32 0 (B.encode y)
		where pad n w s = BS.replicate (n - BS.length s) w `BS.append` s
	encode ECC.PointO = error $ modNm ++ ": EC.Point.encode"
	decode = B.evalBytableM B.parse

instance B.Parsable ECC.Point where
	parse = (B.take =<< B.take 1) >>= \bs -> case BS.uncons bs of
		Just (4, xy) -> return $ let (x, y) = BS.splitAt 32 xy in ECC.Point
			(either error id $ B.decode x)
			(either error id $ B.decode y)
		_ -> fail $ modNm ++ ": ECC.Point.parse"

isRnInfo :: Extension -> Bool
isRnInfo (ERnInfo _) = True
isRnInfo _ = False

emptyRnInfo :: Extension
emptyRnInfo = ERnInfo ""

w8 :: Word8; w8 = undefined
w16 :: Word16; w16 = undefined
