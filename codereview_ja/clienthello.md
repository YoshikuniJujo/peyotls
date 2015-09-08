Client Hello
============

いつ?
-----

クライアントがはじめにサーバに接続するとき。
HelloRequestへの返事として。
再ネゴシエーションを始めるとき。

構造
----

	struct {
		u8int32 gmt_unix_time;
		opaque random_bytes[28];
	} Random

	opaque SessionID<0..32>;

	uint8 CipherSuite[2];

	enum { null(0), (255) } CompressionMethod;

	struct {
		ProtocolVersion client_version;
		Random random;
		SessionID session_id;
		CipherSuite cipher_suites<2..2^16-2>;
		CompressionMethod compression_methods<1..2^8-1>;
		select (extensions_present) {
			case false:
				struct {};
			case true:
				Extension extensions<0..2^16-1>;
		};
	} ClientHello;
