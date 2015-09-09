{-# LANGUAGE PackageImports, OverloadedStrings #-}

module Network.PeyoTLS.Codec.Alert (Alert(..), AlertLevel(..), AlertDesc(..)) where

import Control.Applicative
import "monads-tf" Control.Monad.Error.Class (Error(..))
import Data.Word (Word8)
import qualified Data.ByteString as BS
import qualified Codec.Bytable.BigEndian as B

modNm :: String
modNm = "Network.PeyoTLS.Codec.Alert"

-- | RFC 5246 7.2. Alert Protocol
--
-- @
-- struct {
-- 	AlertLevel level;
-- 	AlertDescription description;
-- } Alert;
-- @

data Alert
	= Alert AlertLevel AlertDesc String
	| ExternalAlert String
	| NotDetected String deriving Show

instance B.Bytable Alert where
	encode (Alert al ad _) = B.encode al `BS.append` B.encode ad
	encode _ = error "Alert.encode"
	decode alad = let (al, ad) = BS.splitAt 1 alad in
		Alert <$> B.decode al <*> B.decode ad <*> return ""

-- | RFC 5246 7.2. Alert Protocol
--
-- @
-- enum { warning(1), fatal(2), (255) } AlertLevel;
-- @

data AlertLevel = ALWarning | ALFtl | ALRaw Word8 deriving Show

instance B.Bytable AlertLevel where
	encode ALWarning = "\x01"
	encode ALFtl = "\x02"
	encode (ALRaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[al] -> Right $ case al of
			1 -> ALWarning; 2 -> ALFtl; _ -> ALRaw al
		_ -> Left $ modNm ++ ": AlertLevel.decode"

-- | RFC 5246 7.2. Alert Protocol
--
-- @
-- enum {
-- 	close_notify(0),
-- 	unexpected_message(10),
-- 	bad_record_mac(20),
-- 	decryption_failed_RESERVED(21),
-- 	record_overflow(22),
-- 	decompression_failure(30),
-- 	handshake_failure(40),
-- 	no_certificate_RESERVED(41),
-- 	bad_certificate(42),
-- 	unsupported_certificate(43),
-- 	certificate_revoked(44),
-- 	certificate_expired(45),
-- 	certificate_unknown(46),
-- 	illegal_parameter(47),
-- 	unknown_ca(48),
-- 	access_denied(49),
-- 	decode_error(50),
-- 	decrypt_error(51),
--	export_restriction_RESERVED(60),
--	protocol_version(70),
--	insufficient_security(71),
--	internal_error(80),
--	user_canceled(90),
--	no_renegotiation(100),
--	unsupported_extension(110),
--	(255)
-- } AlertDescription;
-- @

data AlertDesc
	= ADCloseNotify | ADUnexMsg   | ADBadRecMac  | ADRecOverflow | ADDecFail
	| ADHsFailure   | ADUnsCert   | ADCertEx     | ADCertUnk     | ADIllParam
	| ADUnkCa       | ADDecodeErr | ADDecryptErr | ADProtoVer    | ADInsSec
	| ADInternalErr | ADUnk       | ADRaw Word8
	deriving Show

instance B.Bytable AlertDesc where
	encode ADCloseNotify = "\0"
	encode ADUnexMsg = "\10"
	encode ADBadRecMac = "\20"
	encode ADRecOverflow = "\22"
	encode ADDecFail = "\30"
	encode ADHsFailure = "\40"
	encode ADUnsCert = "\43"
	encode ADCertEx = "\45"
	encode ADCertUnk = "\46"
	encode ADIllParam = "\47"
	encode ADUnkCa = "\48"
	encode ADDecodeErr = "\50"
	encode ADDecryptErr = "\51"
	encode ADProtoVer = "\70"
	encode ADInsSec = "\71"
	encode ADInternalErr = "\80"
	encode ADUnk = error $ modNm ++ ": AlertDesc,encode"
	encode (ADRaw w) = BS.pack [w]
	decode bs = case BS.unpack bs of
		[ad] -> Right $ case ad of
			0 -> ADCloseNotify
			10 -> ADUnexMsg
			20 -> ADBadRecMac
			22 -> ADRecOverflow
			30 -> ADDecFail
			40 -> ADHsFailure
			43 -> ADUnsCert
			45 -> ADCertEx
			46 -> ADCertUnk
			47 -> ADIllParam
			48 -> ADUnkCa
			50 -> ADDecodeErr
			51 -> ADDecryptErr
			70 -> ADProtoVer
			71 -> ADInsSec
			80 -> ADInternalErr
			w -> ADRaw w
		_ -> Left $ modNm ++ ": AlertDesc.decode"

instance Error Alert where strMsg = NotDetected
