Hello Extensions
================

	struct {
		ExtensionType extension_type;
		opaque extension_data<0..2^16-1>;
	} Extension;

	enum {
		signature_algorithms(13), (65535)
	} ExtensionType;
