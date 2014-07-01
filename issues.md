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
    <dt>session resumption</dt>
    <dd>read RFC 5070</dd>
    <dt>Shamir&apos;s trick</dt>
    <dd>If the speed is not enough, and bottle neck is ECDSA.</dd>
    <dt>process revoked certificate</dt>
    <dd>Refuse revoked certificate by CRL or OCSP</dd>
</dl>

process error
-------------

<dl>
    <dt>Send alert to partner</dt>
    <dd>Now, not sending alert. but need to send alert to partner</dd>
    <dt>Process ByteString read error</dt>
    <dd>Now, ignore or pattern match error. Should use throwError or send Alert</dd>
    <dt>Now, if recieve Alert, send Alert</dt>
    <dd>If recieve Alert, Should only show it.</dd>
    <dt>Check fragment version</dt>
    <dd>To do or not to do, that is the question.</dd>
    <dt>Free Handle when exeption occur</dt>
    <dd>Now, not problem. But in future, problem occur.</dd>
    <dt>Send alert to server when matched client certificate file</dt>
    <dd>Send applicable alert to server when no match client certificate file.</dd>
</dl>

bug
---

<dl>
    <dt>Buffering and flush buffer of HandleLike below TLS</dt>
    <dd>Think about timing of hlFlush and buffering mode.</dd>
    <dt>Buffering problem</dt>
    <dd>To off or not to off, that is the question.</dd>
    <dt>close notify problem</dt>
    <dd>To wait or not to wait, that is the question.</dd>
    <dt>Set max size of fragment</dt>
    <dd>plain text &lt;= 2^14 byte, cipher text &lt; 2^14 + 2048 byte</dd>
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
    <dt>Test with expired certificate</dt>
    <dd>Test server and client with expired certificate.</dd>
    <dt>Test with revoked certificate</dt>
    <dd>Send revoked certificate to server.</dd>
    <dt>Check vulnerability of ECDSA to timing attack</dt>
    <dd>Check relationship of k value and processing time.</dd>
</dl>
