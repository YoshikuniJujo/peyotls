{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module Network.PeyoTLS.Base (
	PeyotlsM, HM.TlsM, HM.run, HM.SettingsS,
		hlGetRn, hlGetLineRn, hlGetContentRn,
	HM.HandshakeM, HM.execHandshakeM, HM.rerunHandshakeM,
		getSettingsC, setSettingsC, HM.getSettingsS, HM.setSettingsS,
		HM.withRandom, HM.randomByteString, flushAppData,
		HM.AlertLevel(..), HM.AlertDesc(..), HM.throwError,
		HM.debugCipherSuite, debug,
	HM.ValidateHandle(..), HM.handshakeValidate, validateAlert,
	HM.TlsHandle_, HM.names, HM.CertSecretKey(..), HM.isRsaKey, HM.isEcdsaKey,
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	Handshake(HHelloReq),
	ClientHello(..), ServerHello(..), SessionId(..), Extension(..), eRenegoInfo,
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), HashAlg(..), SignAlg(..),
		HM.getCipherSuite, HM.setCipherSuite,
		checkClientRenego, makeClientRenego,
		checkServerRenego, makeServerRenego,
	ServerKeyEx(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
		SecretKey(..), SvSignPublicKey(..),
	CertReq(..), certReq, ClCertType(..),
	ServerHelloDone(..),
	ClientKeyEx(..), Epms(..),
		HM.generateKeys, HM.decryptRsa, HM.encryptRsa, HM.rsaPadding,
	DigitallySigned(..), ClSignPublicKey(..), ClSignSecretKey(..),
		HM.handshakeHash,
	HM.RW(..), HM.flushCipherSuite,
	HM.Side(..), finishedHash,
	DhParam(..), makeEcdsaPubKey, dh3072Modp, secp256r1 ) where

import Control.Applicative
import Control.Arrow (first, second, (***))
import Control.Monad (unless, liftM, ap)
import "monads-tf" Control.Monad.State (gets, lift)
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
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable.BigEndian as B
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import Network.PeyoTLS.Types (
	Handshake(..), HandshakeItem(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyEx(..), BulkEnc(..),
		CompMethod(..), Extension(..),
	ServerKeyEx(..), ServerKeyExDhe(..), ServerKeyExEcdhe(..),
	CertReq(..), certReq, ClCertType(..), SignAlg(..), HashAlg(..),
	ServerHelloDone(..), ClientKeyEx(..), Epms(..),
	DigitallySigned(..), Finished(..) )
import qualified Network.PeyoTLS.Run as HM (
	TlsM, run,
	HandshakeM, execHandshakeM, rerunHandshakeM,
		SettingsS, getSettingsC, setSettingsC, getSettingsS, setSettingsS,
		withRandom, randomByteString, flushAppData_,
		getClientFinished, setClientFinished,
		getServerFinished, setServerFinished,
		getCipherSuite, setCipherSuite, flushCipherSuite, debugCipherSuite,
		AlertLevel(..), AlertDesc(..),
	ValidateHandle(..), handshakeValidate,
	TlsHandle_(..), names, CertSecretKey(..), isRsaKey, isEcdsaKey,

	generateKeys, encryptRsa, decryptRsa, rsaPadding,
	handshakeHash, finishedHash, throwError,
	ContentType(..),
	Side(..), RW(..),

	getAdBuf, setAdBuf, pushAdBufH,

	hsGet, hsPut, ccsGet, ccsPut, adGet, adGetLine, adGetContent, updateHash,
	)
import Network.PeyoTLS.Ecdsa (blindSign, generateKs)

type PeyotlsM = HM.TlsM Handle SystemRNG

debug :: (HandleLike h, Show a) => DebugLevel h -> a -> HM.HandshakeM h g ()
debug p x = do
	h <- gets $ HM.tlsHandle . fst
	lift . lift . lift . hlDebug h p . BSC.pack . (++ "\n") $ show x

readHandshake :: (HandleLike h, CPRG g, HandshakeItem hi) => HM.HandshakeM h g hi
readHandshake = do
	bs <- HM.hsGet
	case B.decode bs of
		Right HHelloReq -> readHandshake
		Right hs -> case fromHandshake hs of
			Just i -> do
				HM.updateHash bs
				return i
			_ -> HM.throwError
				HM.ALFatal HM.ADUnexpectedMessage $ moduleName ++
				".readHandshake: type mismatch " ++ show hs
		_ -> HM.throwError HM.ALFatal HM.ADInternalError "bad"

writeHandshake::
	(HandleLike h, CPRG g, HandshakeItem hi) => hi -> HM.HandshakeM h g ()
writeHandshake hi = do
	let	hs = toHandshake hi
		bs = snd . encodeContent $ CHandshake hs
	HM.hsPut bs
	case hs of
		HHelloReq -> return ()
		_ -> HM.updateHash bs

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
	w <- HM.ccsGet
	case B.decode $ BS.pack [w] of
		Right ChangeCipherSpec -> return ()
		_ -> HM.throwError HM.ALFatal HM.ADUnexpectedMessage $
			"HandshakeBase.getChangeCipherSpec: " ++
			"not change cipher spec"

putChangeCipherSpec :: (HandleLike h, CPRG g) => HM.HandshakeM h g ()
putChangeCipherSpec =
	HM.ccsPut . (\[w] -> w) . BS.unpack $ B.encode ChangeCipherSpec

data Content = CCCSpec ChangeCipherSpec | CAlert Word8 Word8 | CHandshake Handshake
	deriving Show

encodeContent :: Content -> (HM.ContentType, BS.ByteString)
encodeContent (CCCSpec ccs) = (HM.CTCCSpec, B.encode ccs)
encodeContent (CAlert al ad) = (HM.CTAlert, BS.pack [al, ad])
encodeContent (CHandshake hss) = (HM.CTHandshake, B.encode hss)

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

hlGetRn :: (HM.ValidateHandle h, CPRG g) => (HM.TlsHandle_ h g -> HM.TlsM h g ()) ->
	HM.TlsHandle_ h g -> Int -> HM.TlsM h g BS.ByteString
hlGetRn rn t n = do
	bf <- HM.getAdBuf t
	if BS.length bf >= n
	then do	let (ret, rest) = BS.splitAt n bf
		HM.setAdBuf t rest
		return ret
	else (bf `BS.append`) `liftM` HM.adGet rn t (n - BS.length bf)

hlGetLineRn :: (HM.ValidateHandle h, CPRG g) =>
	(HM.TlsHandle_ h g -> HM.TlsM h g ()) -> HM.TlsHandle_ h g ->
	HM.TlsM h g BS.ByteString
hlGetLineRn rn t = do
	bf <- HM.getAdBuf t
	if '\n' `BSC.elem` bf || '\r' `BSC.elem` bf
	then do	let (ret, rest) = splitOneLine bf
		HM.setAdBuf t $ BS.tail rest
		return ret
	else (bf `BS.append`) `liftM` HM.adGetLine rn t

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
	(HM.TlsHandle_ h g -> HM.TlsM h g ()) ->
	HM.TlsHandle_ h g -> HM.TlsM h g BS.ByteString
hlGetContentRn rn t = do
	bf <- HM.getAdBuf t
	if BS.null bf
	then HM.adGetContent rn t
	else do	HM.setAdBuf t ""
		return bf

flushAppData :: (HandleLike h, CPRG g) => HM.HandshakeM h g Bool
flushAppData = uncurry (>>) . (HM.pushAdBufH *** return) =<< HM.flushAppData_

eRenegoInfo :: Extension -> Maybe BS.ByteString
eRenegoInfo (ERenegoInfo ri) = Just ri
eRenegoInfo _ = Nothing

checkClientRenego, checkServerRenego ::
	HandleLike h => BS.ByteString -> HM.HandshakeM h g ()
checkClientRenego cf = (cf ==) `liftM` HM.getClientFinished >>= \ok ->
	unless ok . HM.throwError HM.ALFatal HM.ADHsFailure $
		"Network.PeyoTLS.Base.checkClientRenego: bad renegotiation"
checkServerRenego ri = do
	cf <- HM.getClientFinished
	sf <- HM.getServerFinished
	unless (ri == cf `BS.append` sf) $ HM.throwError
		HM.ALFatal HM.ADHsFailure
		"Network.PeyoTLS.Base.checkServerRenego: bad renegotiation"

makeClientRenego, makeServerRenego :: HandleLike h => HM.HandshakeM h g Extension
makeClientRenego = ERenegoInfo `liftM` HM.getClientFinished
makeServerRenego = ERenegoInfo `liftM`
	(BS.append `liftM` HM.getClientFinished `ap` HM.getServerFinished)

validateAlert :: [X509.FailedReason] -> HM.AlertDesc
validateAlert vr
	| X509.UnknownCA `elem` vr = HM.ADUnknownCa
	| X509.Expired `elem` vr = HM.ADCertificateExpired
	| X509.InFuture `elem` vr = HM.ADCertificateExpired
	| otherwise = HM.ADCertificateUnknown

type SettingsC = (
	[CipherSuite],
	[(HM.CertSecretKey, X509.CertificateChain)],
	X509.CertificateStore )

getSettingsC :: HandleLike h => HM.HandshakeM h g SettingsC
getSettingsC = do
	(css, crts, mcs) <- HM.getSettingsC
	case mcs of
		Just cs -> return (css, crts, cs)
		_ -> HM.throwError HM.ALFatal HM.ADInternalError
			"Network.PeyoTLS.Base.getSettingsC"

setSettingsC :: HandleLike h => SettingsC -> HM.HandshakeM h g ()
setSettingsC (css, crts, cs) = HM.setSettingsC (css, crts, Just cs)

moduleName :: String
moduleName = "Network.PeyoTLS.Base"

decodePoint :: BS.ByteString -> ECC.Point
decodePoint s = case BS.uncons s of
	Just (4, p) -> let (x, y) = BS.splitAt 32 p in ECC.Point
		(either error id $ B.decode x)
		(either error id $ B.decode y)
	_ -> error $ moduleName ++ ".decodePoint: not implemented point"

class SvSignPublicKey pk where
	svpAlgorithm :: pk -> SignAlg
	verify :: HashAlg -> pk -> BS.ByteString -> BS.ByteString -> Bool

instance SvSignPublicKey RSA.PublicKey where
	svpAlgorithm _ = Rsa
	verify = rsaVerify

rsaVerify :: HashAlg -> RSA.PublicKey -> BS.ByteString -> BS.ByteString -> Bool
rsaVerify ha pk sn m = let
	(hs, oid0) = case ha of
		Sha1 -> (SHA1.hash, ASN1.OID [1, 3, 14, 3, 2, 26])
		Sha256 -> (SHA256.hash, ASN1.OID [2, 16, 840, 1, 101, 3, 4, 2, 1])
		_ -> error "not implemented"
	(o, oid) = case ASN1.decodeASN1' ASN1.DER . BS.tail
		. BS.dropWhile (== 255) . BS.drop 2 $ RSA.ep pk sn of
		Right [ASN1.Start ASN1.Sequence,
			ASN1.Start ASN1.Sequence, oid_, ASN1.Null, ASN1.End ASN1.Sequence,
			ASN1.OctetString o_, ASN1.End ASN1.Sequence ] -> (o_, oid_)
		e -> error $ show e in
	oid == oid0 && o == hs m

instance SvSignPublicKey ECDSA.PublicKey where
	svpAlgorithm _ = Ecdsa
	verify Sha1 pk = ECDSA.verify SHA1.hash pk . either error id . B.decode
	verify Sha256 pk = ECDSA.verify SHA256.hash pk . either error id . B.decode
	verify _ _ = error "TlsClient: ECDSA.PublicKey.verify: not implemented"

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

class ClSignSecretKey sk where
	csSign :: sk -> BS.ByteString -> BS.ByteString
	csAlgorithm :: sk -> (HashAlg, SignAlg)

instance ClSignSecretKey RSA.PrivateKey where
	csSign sk m = let pd = HM.rsaPadding (RSA.private_pub sk) m in RSA.dp Nothing sk pd
	csAlgorithm _ = (Sha256, Rsa)

instance ClSignSecretKey ECDSA.PrivateKey where
	csSign sk m = enc $ blindSign 0 id sk (generateKs (SHA256.hash, 64) q x m) m
		where
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
		enc (ECDSA.Signature r s) = ASN1.encodeASN1' ASN1.DER [
			ASN1.Start ASN1.Sequence,
				ASN1.IntVal r, ASN1.IntVal s,
				ASN1.End ASN1.Sequence]
	csAlgorithm _ = (Sha256, Ecdsa)

class ClSignPublicKey pk where
	cspAlgorithm :: pk -> SignAlg
	csVerify :: pk -> BS.ByteString -> BS.ByteString -> Bool

instance ClSignPublicKey RSA.PublicKey where
	cspAlgorithm _ = Rsa
	csVerify k s h = RSA.ep k s == HM.rsaPadding k h

instance ClSignPublicKey ECDSA.PublicKey where
	cspAlgorithm _ = Ecdsa
	csVerify k = ECDSA.verify id k . either error id . B.decode

makeEcdsaPubKey :: ECC.CurveName -> BS.ByteString -> ECDSA.PublicKey
makeEcdsaPubKey c xy = ECDSA.PublicKey (ECC.getCurveByName c) $ decodePoint xy
