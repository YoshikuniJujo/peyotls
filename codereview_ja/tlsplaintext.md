TLSPlaintext
============

	struct {
		uint8 major;
		uint8 minor;
	} ProtocolVersion;

	enum {
		change_cipher_spec(20), alert(21), handshake(22),
		application_data(23), (255)
	} ContentType;

	struct {
		ContentType type;
		ProtocolVersoin version;
		unint16 length;
		opaque fragment[TLSPlaintext.length];
	} TLSPlaintext;

lengthは2^14以下でなければならない。
Handshake, Alert, ChangeCipherSpecでは長さ0のFragmentを送ってはならない。
