Hello Extensions
================

	struct {
		ExtensionType extension_type;
		opaque extension_data<0..2^16-1>;
	} Extension;

	enum {
		signature_algorithms(13), (65535)
	} ExtensionType;

Signature Algorithms
--------------------

	enum {
		none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
		sha512(6), (255)
	} HashAlgorithm;

	enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
		SignatureAlgorithm;

	struct {
		HashAlgorithm hash;
		SignatureAlgorithm signature;
	} SignatureAndHashAlgorithm;

	SignatureAndHashAlgorithm
		supported_signature_algorithms<2..2^16-2>;
