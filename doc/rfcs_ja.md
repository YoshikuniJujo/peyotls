関連するRFC
===========

RFC 5246
--------

### タイトル

The Transport Layer Security (TLS) Protocol Version 1.2

### 概要

TLS 1.2の全般的な仕様について書かれている。

RFC 4492
--------

### タイトル

Elliptic Curve Cryptography (ECC) Cipher Suites for
Transport Layer Security (TLS)

### 概要

TLSにおける楕円曲線暗号について書かれている。
RFC 5246で一部修正があるので注意が必要だ。

RFC 5746
--------

### タイトル

Transport Layer Security (TLS) Renegotiation Indication Extension

### 概要

再ネゴシエーションを利用したMITM攻撃への脆弱性の修正。

RFC 5878
--------

### タイトル

Transport Layer Security (TLS) Authorization Extensions

### 概要

サーバとクライアントの相互認証に関する拡張。

RFC 6176
--------

### タイトル

Prohibiting Secure Sockets Layer (SSL) Version 2.0

### 概要

SSL 2.0との互換性を持たせないように、という話。

RFC 7465
--------

### タイトル

Prohibiting RC4 Cipher Suites

### 概要

RC4による暗号化は使っちゃだめですよという話。

RFC 7507
--------

### タイトル

TLS Fallback Signaling Cipher Suite Value (SCSV)
for Preventing Progocol Downgrade Attacks

### 概要

ダウングレード攻撃を避けるためのSCSVの定義。

RFC 7568
--------

### タイトル

Deprecating Secure Sockets Layer Version 3.0

### 概要

SSLv3は使っちゃだめですよという話。

RFC 5077
--------

### タイトル

Transport Layer Security (TLS) Session Resumption without Server-Side State

### 概要

クライアントに対してチケットを発行することでサーバ側にデータを保存せずに
接続を再開できますよという話。
