{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.Extension (Extension, SignAlg(..), HashAlg(..)) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits (shiftL, (.|.))
import Data.Word (Word8, Word16)

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import Network.PeyoTLS.HashSignAlgorithm(HashAlg(..), SignAlg(..))

data Extension
	= ESName [ServerName]
	| EECurve [ECC.CurveName] | EEcPFrt [EcPointFormat]
	| ESsnTicketTls BS.ByteString
	| ENextProtoNego BS.ByteString
	| ERenegoInfo BS.ByteString
	| ERaw EType BS.ByteString
	deriving Show

instance B.Bytable Extension where
	encode = encodeE; decode = B.evalBytableM B.parse

instance B.Parsable Extension where
	parse = parseE

encodeE :: Extension -> BS.ByteString
encodeE (ESName sn) = encodeE . ERaw TSName . B.addLen w16 $ cmap B.encode sn
encodeE (EECurve ec) = encodeE . ERaw TECurve . B.addLen w16 $ cmap B.encode ec
encodeE (EEcPFrt pf) = encodeE . ERaw TEcPFrt . B.addLen w8 $ cmap B.encode pf
encodeE (ESsnTicketTls stt) = encodeE $ ERaw TSsnTicketTls stt
encodeE (ENextProtoNego npn) = encodeE $ ERaw TNextProtoNego npn
encodeE (ERenegoInfo ri) = encodeE . ERaw TRenegoInfo $ B.addLen w8 ri
encodeE (ERaw et body) = B.encode et `BS.append` B.addLen w16 body

parseE :: B.BytableM Extension
parseE = do
	(t, l) <- (,) <$> B.take 2 <*> B.take 2
	case t of
		TSName -> ESName <$> (flip B.list B.parse =<< B.take 2)
		TECurve -> EECurve <$> (flip B.list (B.take 2) =<< B.take 2)
		TEcPFrt -> EEcPFrt <$> (flip B.list (B.take 1) =<< B.take 1)
		TSsnTicketTls -> ESsnTicketTls <$> B.take l
		TNextProtoNego -> ENextProtoNego <$> B.take l
		TRenegoInfo -> ERenegoInfo <$> (B.take =<< B.take 1)
		_ -> ERaw t <$> B.take l

data EType
	= TSName         | TECurve     | TEcPFrt     | TSsnTicketTls
	| TNextProtoNego | TRenegoInfo | TRaw Word16 deriving Show

instance B.Bytable EType where
	encode TSName = B.encode (0 :: Word16)
	encode TECurve = B.encode (10 :: Word16)
	encode TEcPFrt = B.encode (11 :: Word16)
	encode TSsnTicketTls = B.encode (35 :: Word16)
	encode TNextProtoNego = B.encode (13172 :: Word16)
	encode TRenegoInfo = B.encode (65281 :: Word16)
	encode (TRaw et) = B.encode et
	decode bs = case BS.unpack bs of
		[w1, w2] -> Right $
			case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
				0 -> TSName
				10 -> TECurve
				11 -> TEcPFrt
				35 -> TSsnTicketTls
				13172 -> TNextProtoNego
				65281 -> TRenegoInfo
				et -> TRaw et
		_ -> Left "Extension: EType.decode"

data ServerName = SNHostName BS.ByteString | SNRaw NameType BS.ByteString
	deriving Show

instance B.Bytable ServerName where
	encode (SNHostName nm) = B.encode $ SNRaw NTHostName nm
	encode (SNRaw nt nm) = B.encode nt `BS.append` B.addLen w16 nm
	decode = B.evalBytableM B.parse

instance B.Parsable ServerName where
	parse = do
		(t, n) <- (,) <$> B.take 1 <*> (B.take =<< B.take 2)
		return $ case t of
			NTHostName -> SNHostName n; _ -> SNRaw t n

data NameType = NTHostName | NTRaw Word8 deriving Show

instance B.Bytable NameType where
	encode NTHostName = BS.pack [0]
	encode (NTRaw t) = BS.pack [t]
	decode bs = case BS.unpack bs of
		[t] -> Right $ case t of 0 -> NTHostName; _ -> NTRaw t
		_ -> Left "Extension: NameType.decode"

instance B.Bytable DH.Params where
	encode (DH.Params p g) =
		BS.concat [B.addLen w16 $ B.encode p, B.addLen w16 $ B.encode g]
	decode = B.evalBytableM B.parse

instance B.Parsable DH.Params where
	parse = DH.Params
		<$> (B.take =<< B.take 2)
		<*> (B.take =<< B.take 2)

instance B.Bytable DH.PublicNumber where
	encode = B.addLen w16 . B.encode . \(DH.PublicNumber pn) -> pn
	decode = B.evalBytableM B.parse

instance B.Parsable DH.PublicNumber where
	parse = fromInteger <$> (B.take =<< B.take 2)

data EcCurveType = ExplicitPrime | ExplicitChar2 | NamedCurve | ECTRaw Word8
	deriving Show

instance B.Bytable EcCurveType where
	encode ExplicitPrime = BS.pack [1]
	encode ExplicitChar2 = BS.pack [2]
	encode NamedCurve = BS.pack [3]
	encode (ECTRaw w) = BS.pack [w]
	decode = B.evalBytableM B.parse

instance B.Parsable EcCurveType where
	parse = do
		ct <- B.head
		return $ case ct of
			1 -> ExplicitPrime
			2 -> ExplicitChar2
			3 -> NamedCurve
			w -> ECTRaw w

instance B.Bytable ECC.CurveName where
	encode ECC.SEC_p256r1 = B.encode (23 :: Word16)
	encode ECC.SEC_p384r1 = B.encode (24 :: Word16)
	encode ECC.SEC_p521r1 = B.encode (25 :: Word16)
	encode _ = error "Extension.encodeCN: not implemented"
	decode bs = case BS.unpack bs of
		[w1, w2] -> case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
			(23 :: Word16) -> Right ECC.SEC_p256r1
			(24 :: Word16) -> Right ECC.SEC_p384r1
			(25 :: Word16) -> Right ECC.SEC_p521r1
			n -> Left $ "Extension: CurveName.decode: unknown curve: " ++
				show n
		_ -> Left "Extension: CurveName.decode: bad format"

instance B.Parsable ECC.CurveName where
	parse = B.take 2

instance B.Bytable ECC.Curve where
	encode c
		| c == ECC.getCurveByName ECC.SEC_p256r1 =
			B.encode NamedCurve `BS.append` B.encode ECC.SEC_p256r1
		| otherwise = error "TlsServer.encodeC: not implemented"
	decode = B.evalBytableM B.parse

instance B.Parsable ECC.Curve where
	parse = ECC.getCurveByName <$> do
		NamedCurve <- B.parse
		B.parse

data EcPointFormat = EPFUncompressed | EPFRaw Word8 deriving Show

instance B.Bytable EcPointFormat where
	encode EPFUncompressed = BS.pack [0]
	encode (EPFRaw f) = BS.pack [f]
	decode bs = case BS.unpack bs of
		[f] -> Right $ case f of 0 -> EPFUncompressed; _ -> EPFRaw f
		_ -> Left "Extension: Bytable.decode"

instance B.Bytable ECC.Point where
	encode (ECC.Point x y) = B.addLen w8 $
		4 `BS.cons` padd 32 0 (B.encode x) `BS.append`
			padd 32 0 (B.encode y)
	encode ECC.PointO = error "Extension: EC.Point.encode"
	decode = B.evalBytableM B.parse

padd :: Int -> Word8 -> BS.ByteString -> BS.ByteString
padd n w s = BS.replicate (n - BS.length s) w `BS.append` s

instance B.Parsable ECC.Point where
	parse = do
		bs <- B.take =<< B.take 1
		case BS.uncons bs of
			Just (4, rest) -> return $ let (x, y) = BS.splitAt 32 rest in
				ECC.Point
					(either error id $ B.decode x)
					(either error id $ B.decode y)
			_ -> fail "Extension: ECC.Point.parse"

w8 :: Word8; w8 = undefined
w16 :: Word16; w16 = undefined

cmap :: (a -> BS.ByteString) -> [a] -> BS.ByteString
cmap = (BS.concat .) . map
