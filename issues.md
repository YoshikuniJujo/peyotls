issues
======

リポジトリの移動
----------------

1. forestのissueで不要なものはcloseする
2. forestのissueで必要なものはコピーする
    1. まずはforestのissueをファイルにまとめてしまい、peyotlsリポジトリにup
    2. そこからpeyotlsのissueへ書き写す

enhancement
-----------

<dl>
    <dt>renegotiation</dt>
    <dd>RFC 5746</dd>
    <dt>Select curve from client hello</dt>
    <dd>Add curve list to arguments, and merge with client hello</dd>
    <dt>Process encrypted secret key</dt>
    <dd>rfc1421,
    	[page1](http://blog.livedoor.jp/k_urushima/archives/1707952.html),
	[page2](http://lowlife.jp/yasusii/weblog/2007/06/25.html)</dd>
</dl>

error check
-----------

<dl>
    <dt>Send alert to partner</dt>
    <dd>Now, not sending alert. but need to send alert to partner</dd>
    <dt>Process ByteString read error</dt>
    <dd>Now, ignore or pattern match error. Should use throwError or send Alert</dd>
    <dt>Now, if recieve Alert, send Alert</dt>
    <dd>If recieve Alert, Should only show it.</dd>
</dl>

bug
---

<dl>
    <dt>Buffering and flush buffer of HandleLike below TLS</dt>
    <dd>Think about timing of hlFlush and buffering mode.</dd>
</dl>

refactoring
-----------

<dl>
    <dt>Unify SignHashAlgorithm and CipherSuite</dt>
    <dd>data CipherSuite = CipherSuite DHAlg SignAlg BulkEncAlg HashAlg</dd>
    <dt>Unify some types</dt>
    <dd>eg. ClCertAlg, SignAlg, HashAlg, CipherSuite, KeyExchange, BulkEncryption</dd>
    <dt>Now, separate and join type and length from/to body</dt>
    <dd>Because of using Bytable. I shall correct if I can</dd>
</dl>

test
----

<dl>
    <dt>quick check</dt>
    <dd>Make test with quick check and use cabal test</dd>
    <dt>Test k value</dt>
    <dd>Test k value of RFC 6979</dd>
</dl>
