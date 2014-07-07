{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.PeyoTLS.Base ( Extension(..),
	PeyotlsM,
	debug, generateKs, blindSign, HM.CertSecretKey(..), isEcdsaKey, isRsaKey,
	HM.TlsM, HM.run, HM.HandshakeM, HM.execHandshakeM, HM.rerunHandshakeM,
	HM.withRandom, HM.randomByteString,
	HM.TlsHandle, HM.names,
		readHandshake, getChangeCipherSpec,
		writeHandshake, putChangeCipherSpec,
		writeHandshakeNH,
	HM.ValidateHandle(..), HM.handshakeValidate,
	HM.Alert(..), HM.AlertLevel(..), HM.AlertDesc(..),
	ServerKeyExchange(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
	ServerHelloDone(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		HM.getCipherSuite, HM.setCipherSuite,
	CertificateRequest(..), certificateRequest, ClientCertificateType(..), SecretKey(..),
	ClientKeyExchange(..), Epms(..),
		HM.generateKeys,
		HM.encryptRsa, HM.decryptRsa, HM.rsaPadding, HM.debugCipherSuite,
	DigitallySigned(..), HM.handshakeHash, HM.flushCipherSuite,
	HM.Side(..), HM.RW(..), finishedHash,
	DhParam(..), dh3072Modp, secp256r1, HM.throwError,
	HM.getClientFinished, HM.getServerFinished,
	Finished(..),
	HM.ContentType(CTAlert, CTHandshake, CTAppData),
	Handshake(..),
	HM.tlsHandle,
	hlGetRn, hlGetLineRn_, hlGetLineRn, hlGetContentRn_,
	hlGetContentRn,

	HM.getSettings, HM.setSettings,
	HM.flushAppData_,
	flushAppData,
	HM.pushAdBufH,
	) where

import Control.Applicative
import Control.Arrow (first, second, (***))
import Control.Monad (liftM)
import "monads-tf" Control.Monad.State (gets, lift)
import qualified "monads-tf" Control.Monad.Error as E
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import Numeric (readHex)
import "crypto-random" Crypto.Random (CPRG, SystemRNG, cprgGenerate)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA

import Network.PeyoTLS.Types ( Extension(..),
	Handshake(..), HandshakeItem(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..),
	ServerKeyExchange(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
	CertificateRequest(..), certificateRequest, ClientCertificateType(..),
		SignAlg(..), HashAlg(..),
	ServerHelloDone(..), ClientKeyExchange(..), Epms(..),
	DigitallySigned(..), Finished(..) )
import qualified Network.PeyoTLS.Run as HM (
	TlsM, run, HandshakeM, execHandshakeM, rerunHandshakeM,
	withRandom, randomByteString,
	ValidateHandle(..), handshakeValidate,
	TlsHandle(..), ContentType(..),
		names,
		getCipherSuite, setCipherSuite, flushCipherSuite, debugCipherSuite,
		tlsGetContentType, tlsGet, tlsPut, tlsPutNH,
		generateKeys, encryptRsa, decryptRsa, rsaPadding,
	Alert(..), AlertLevel(..), AlertDesc(..),
	Side(..), RW(..), handshakeHash, finishedHash, throwError,
	hlPut_, tGetLine, tGetContent, tlsGet_, tlsPut_,
	tGetLine_, tGetContent_, tlsGet__,
	hlDebug_, hlClose_,
	getClientFinished, setClientFinished,
	getServerFinished, setServerFinished,
	resetSequenceNumber,

	getSettings, setSettings,
	flushAppData_,
	getAdBuf,
	setAdBuf,
	pushAdBufH,

	CertSecretKey(..),
	)
import Network.PeyoTLS.Ecdsa (blindSign, generateKs)

-- import Network.PeyoTLS.CertSecretKey

type PeyotlsM = HM.TlsM Handle SystemRNG

debug :: (HandleLike h, Show a) => DebugLevel h -> a -> HM.HandshakeM h g ()
debug p x = do
	h <- gets $ HM.tlsHandle . fst
	lift . lift . lift . hlDebug h p . BSC.pack . (++ "\n") $ show x

readHandshake :: (HandleLike h, CPRG g, HandshakeItem hi) => HM.HandshakeM h g hi
readHandshake = do
	cnt <- readContent HM.tlsGet =<< HM.tlsGetContentType
	hs <- case cnt of
		CHandshake HHelloReq -> readHandshake
		CHandshake hs -> return hs
		_ -> HM.throwError
			HM.ALFatal HM.ADUnexpectedMessage $
			"HandshakeBase.readHandshake: not handshake: " ++ show cnt
	case fromHandshake hs of
		Just i -> return i
		_ -> HM.throwError
			HM.ALFatal HM.ADUnexpectedMessage $
			"HandshakeBase.readHandshake: type mismatch " ++ show hs

writeHandshake, writeHandshakeNH ::
	(HandleLike h, CPRG g, HandshakeItem hi) => hi -> HM.HandshakeM h g ()
writeHandshake = uncurry HM.tlsPut . encodeContent . CHandshake . toHandshake
writeHandshakeNH = uncurry HM.tlsPutNH . encodeContent . CHandshake . toHandshake

data ChangeCipherSpec = ChangeCipherSpec | ChangeCipherSpecRaw Word8 deriving Show

instance B.Bytable ChangeCipherSpec where
	decode bs = case BS.unpack bs of
		[1] -> Right ChangeCipherSpec
		[w] -> Right $ ChangeCipherSpecRaw w
		_ -> Left "HandshakeBase: ChangeCipherSpec.decode"
	encode ChangeCipherSpec = BS.pack [1]
	encode (ChangeCipherSpecRaw w) = BS.pack [w]

getChangeCipherSpec :: (HandleLike h, CPRG g) => HM.HandshakeM h g ()
getChangeCipherSpec = do
	cnt <- readContent HM.tlsGet =<< HM.tlsGetContentType
	case cnt of
		CCCSpec ChangeCipherSpec -> return ()
		_ -> HM.throwError
			HM.ALFatal HM.ADUnexpectedMessage $
			"HandshakeBase.getChangeCipherSpec: " ++
			"not change cipher spec: " ++
			show cnt
	HM.resetSequenceNumber HM.Read

putChangeCipherSpec :: (HandleLike h, CPRG g) => HM.HandshakeM h g ()
putChangeCipherSpec = do
	uncurry HM.tlsPut . encodeContent $ CCCSpec ChangeCipherSpec
	HM.resetSequenceNumber HM.Write

data Content = CCCSpec ChangeCipherSpec | CAlert Word8 Word8 | CHandshake Handshake
	deriving Show

readContent :: Monad m => (Bool -> Int -> m BS.ByteString) -> HM.ContentType -> m Content
readContent rd HM.CTCCSpec =
	(CCCSpec . either error id . B.decode) `liftM` rd True 1
readContent rd HM.CTAlert =
	((\[al, ad] -> CAlert al ad) . BS.unpack) `liftM` rd True 2
readContent rd HM.CTHandshake = CHandshake `liftM` do
	t <- rd True 1
	len <- rd (t /= "\0") 3
--	(t, len) <- (,) `liftM` rd True 1 `ap` rd True 3
	body <- rd True . either error id $ B.decode len
	return . either error id . B.decode $ BS.concat [t, len, body]
readContent _ _ = undefined

encodeContent :: Content -> (HM.ContentType, BS.ByteString)
encodeContent (CCCSpec ccs) = (HM.CTCCSpec, B.encode ccs)
encodeContent (CAlert al ad) = (HM.CTAlert, BS.pack [al, ad])
encodeContent (CHandshake hss) = (HM.CTHandshake, B.encode hss)

class SecretKey sk where
	type Blinder sk
	generateBlinder :: CPRG g => sk -> g -> (Blinder sk, g)
	sign :: HashAlg -> Blinder sk -> sk -> BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignAlg

instance SecretKey RSA.PrivateKey where
	type Blinder RSA.PrivateKey = RSA.Blinder
	generateBlinder sk rng =
		RSA.generateBlinder rng . RSA.public_n $ RSA.private_pub sk
	sign hs bl sk bs = let
		(h, oid) = first ($ bs) $ case hs of
			Sha1 -> (SHA1.hash,
				ASN1.OID [1, 3, 14, 3, 2, 26])
			Sha256 -> (SHA256.hash,
				ASN1.OID [2, 16, 840, 1, 101, 3, 4, 2, 1])
			_ -> error $ "HandshakeBase: " ++
				"not implemented bulk encryption type"
		a = [ASN1.Start ASN1.Sequence,
			ASN1.Start ASN1.Sequence,
				oid, ASN1.Null, ASN1.End ASN1.Sequence,
			ASN1.OctetString h, ASN1.End ASN1.Sequence]
		b = ASN1.encodeASN1' ASN1.DER a
		pd = BS.concat [ "\x00\x01",
			BS.replicate (ps - 3 - BS.length b) 0xff, "\NUL", b ]
		ps = RSA.public_size $ RSA.private_pub sk in
		RSA.dp (Just bl) sk pd
	signatureAlgorithm _ = Rsa

instance SecretKey ECDSA.PrivateKey where
	type Blinder ECDSA.PrivateKey = Integer
	generateBlinder _ rng = let
		(Right bl, rng') = first B.decode $ cprgGenerate 32 rng in
		(bl, rng')
	sign ha bl sk = B.encode .
		(($) <$> blindSign bl hs sk . generateKs (hs, bls) q x <*> id)
		where
		(hs, bls) = case ha of
			Sha1 -> (SHA1.hash, 64)
			Sha256 -> (SHA256.hash, 64)
			_ -> error $ "HandshakeBase: " ++
				"not implemented bulk encryption type"
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
	signatureAlgorithm _ = Ecdsa

class DhParam b where
	type Secret b
	type Public b
	generateSecret :: CPRG g => b -> g -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateShared :: b -> Secret b -> Public b -> BS.ByteString

instance DhParam DH.Params where
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateSecret = flip DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateShared ps sn pn = B.encode .
		(\(DH.SharedKey s) -> s) $ DH.getShared ps sn pn

dh3072Modp :: DH.Params
dh3072Modp = DH.Params p 2
	where [(p, "")] = readHex $
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1" ++
		"29024e088a67cc74020bbea63b139b22514a08798e3404dd" ++
		"ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245" ++
		"e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" ++
		"ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d" ++
		"c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" ++
		"83655d23dca3ad961c62f356208552bb9ed529077096966d" ++
		"670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" ++
		"e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9" ++
		"de2bcbf6955817183995497cea956ae515d2261898fa0510" ++
		"15728e5a8aaac42dad33170d04507a33a85521abdf1cba64" ++
		"ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" ++
		"abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b" ++
		"f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" ++
		"bbe117577a615d6c770988c0bad946e208e24fa074e5ab31" ++
		"43db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"

instance DhParam ECC.Curve where
	type Secret ECC.Curve = Integer
	type Public ECC.Curve = ECC.Point
	generateSecret c = getRangedInteger 32 1 (n - 1)
		where n = ECC.ecc_n $ ECC.common_curve c
	calculatePublic cv sn =
		ECC.pointMul cv sn . ECC.ecc_g $ ECC.common_curve cv
	calculateShared cv sn pp =
		let ECC.Point x _ = ECC.pointMul cv sn pp in B.encode x

getRangedInteger :: CPRG g => Int -> Integer -> Integer -> g -> (Integer, g)
getRangedInteger b mn mx g = let
	(n, g') = first (either error id . B.decode) $ cprgGenerate b g in
	if mn <= n && n <= mx then (n, g') else getRangedInteger b mn mx g'

secp256r1 :: ECC.Curve
secp256r1 = ECC.getCurveByName ECC.SEC_p256r1

finishedHash :: (HandleLike h, CPRG g) => HM.Side -> HM.HandshakeM h g Finished
finishedHash s = (Finished `liftM`) $ do
	fh <- HM.finishedHash s
	case s of
		HM.Client -> HM.setClientFinished fh
		HM.Server -> HM.setServerFinished fh
	return fh

instance (HandleLike h, CPRG g) => HandleLike (HM.TlsHandle h g) where
	type HandleMonad (HM.TlsHandle h g) = HM.TlsM h g
	type DebugLevel (HM.TlsHandle h g) = DebugLevel h
	hlPut = HM.hlPut_
	hlGet = (.) <$> checkAppData <*> ((fst `liftM`) .)
		. HM.tlsGet__ . (, undefined)
	hlGetLine = ($) <$> checkAppData <*> HM.tGetLine
	hlGetContent = ($) <$> checkAppData <*> HM.tGetContent
	hlDebug = HM.hlDebug_
	hlClose = HM.hlClose_

checkAppData :: (HandleLike h, CPRG g) => HM.TlsHandle h g ->
	HM.TlsM h g (HM.ContentType, BS.ByteString) -> HM.TlsM h g BS.ByteString
checkAppData t m = m >>= \cp -> case cp of
	(HM.CTAppData, ad) -> return ad
	(HM.CTAlert, "\SOH\NUL") -> do
		_ <- HM.tlsPut_ (t, undefined) HM.CTAlert "\SOH\NUL"
		E.throwError "TlsHandle.checkAppData: EOF"
	(HM.CTHandshake, hs) -> do
		lift . lift $ hlDebug (HM.tlsHandle t) "critical" "renegotiation?\n"
		lift . lift . hlDebug (HM.tlsHandle t) "critical" . BSC.pack
			. (++ "\n") $ show hs
		lift . lift . hlDebug (HM.tlsHandle t) "critical" . BSC.pack
			. (++ "\n") $ show (B.decode hs :: Either String Handshake)
		return ""
	_ -> do	_ <- HM.tlsPut_ (t, undefined) HM.CTAlert "\2\10"
		E.throwError "TlsHandle.checkAppData: not application data"

hlGetRn_ :: (HM.ValidateHandle h, CPRG g) => (HM.TlsHandle h g -> HM.TlsM h g ()) ->
	HM.TlsHandle h g -> Int -> HM.TlsM h g BS.ByteString
hlGetRn_ rh = (.) <$> checkAppData <*> ((fst `liftM`) .) . HM.tlsGet_ rh
	. (, undefined)

hlGetLineRn_, hlGetContentRn_ :: (HM.ValidateHandle h, CPRG g) =>
	(HM.TlsHandle h g -> HM.TlsM h g ()) -> HM.TlsHandle h g -> HM.TlsM h g BS.ByteString
hlGetLineRn_ rh = ($) <$> checkAppData <*> HM.tGetLine_ rh
hlGetContentRn_ rh = ($) <$> checkAppData <*> HM.tGetContent_ rh

hlGetRn :: (HM.ValidateHandle h, CPRG g) => (HM.TlsHandle h g -> HM.TlsM h g ()) ->
	HM.TlsHandle h g -> Int -> HM.TlsM h g BS.ByteString
hlGetRn rn t n = do
	bf <- HM.getAdBuf t
	if BS.length bf >= n
	then do	let (ret, rest) = BS.splitAt n bf
		HM.setAdBuf t rest
		return ret
	else (bf `BS.append`) `liftM` hlGetRn_ rn t (n - BS.length bf)

hlGetLineRn :: (HM.ValidateHandle h, CPRG g) =>
	(HM.TlsHandle h g -> HM.TlsM h g ()) -> HM.TlsHandle h g ->
	HM.TlsM h g BS.ByteString
hlGetLineRn rn t = do
	bf <- HM.getAdBuf t
	if '\n' `BSC.elem` bf || '\r' `BSC.elem` bf
	then do	let (ret, rest) = splitOneLine bf
		HM.setAdBuf t $ BS.tail rest
		return ret
	else (bf `BS.append`) `liftM` hlGetLineRn_ rn t

splitOneLine :: BS.ByteString -> (BS.ByteString, BS.ByteString)
splitOneLine bs = case BSC.span (/= '\r') bs of
	(_, "") -> second BS.tail $ BSC.span (/= '\n') bs
	(l, ls) -> (l, dropRet ls)

dropRet :: BS.ByteString -> BS.ByteString
dropRet bs = case BSC.uncons bs of
	Just ('\r', bs') -> case BSC.uncons bs' of
		Just ('\n', bs'') -> bs''
		_ -> bs'
	_ -> bs

hlGetContentRn :: (HM.ValidateHandle h, CPRG g) =>
	(HM.TlsHandle h g -> HM.TlsM h g ()) ->
	HM.TlsHandle h g -> HM.TlsM h g BS.ByteString
hlGetContentRn rn t = do
	bf <- HM.getAdBuf t
	if BS.null bf
	then hlGetContentRn_ rn t
	else do	HM.setAdBuf t ""
		return bf

flushAppData :: (HandleLike h, CPRG g) => HM.HandshakeM h g Bool
flushAppData = uncurry (>>) . (HM.pushAdBufH *** return) =<< HM.flushAppData_

isEcdsaKey :: HM.CertSecretKey -> Bool
isEcdsaKey (HM.EcdsaKey _) = True
isEcdsaKey _ = False

isRsaKey :: HM.CertSecretKey -> Bool
isRsaKey (HM.RsaKey _) = True
isRsaKey _ = False