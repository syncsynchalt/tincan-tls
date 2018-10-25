package tls

var (
	kTLS_VERSION_12 = []byte{0x03, 0x03}
	kTLS_VERSION_13 = []byte{0x03, 0x04}

	kTLS_AES_128_GCM_SHA256 = []byte{0x13, 0x01}
	kTLS_RSA_PKCS1_SHA256   = []byte{0x04, 0x01}

	kEXT_SERVER_NAME             = 0
	kEXT_SERVER_NAME_HOST        = byte(0)
	kEXT_SUPPORTED_GROUPS        = 10
	kEXT_SUPPORTED_GROUPS_X25519 = []byte{0, 29}
	kEXT_SIGNATURE_ALGORITHMS    = 13
	kEXT_SUPPORTED_VERSIONS      = 43
	kEXT_COOKIE                  = 44
	kEXT_KEY_SHARE               = 51

	kREC_TYPE_CHANGE_CIPHER_SPEC = byte(20)
	kREC_TYPE_ALERT              = byte(21)
	kREC_TYPE_HANDSHAKE          = byte(22)
	kREC_TYPE_APPLICATION_DATA   = byte(23)

	kHS_TYPE_CLIENT_HELLO         = byte(1)
	kHS_TYPE_SERVER_HELLO         = byte(2)
	kHS_TYPE_ENCRYPTED_EXTENSIONS = byte(8)
	kHS_TYPE_CERTIFICATE          = byte(11)
	kHS_TYPE_CERTIFICATE_VERIFY   = byte(15)
	kHS_TYPE_FINISHED             = byte(20)

	kHS_HELLO_RETRY_REQUEST = []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
)
