package jwt

// 本jwt是简化版 https://github.com/dgrijalva/jwt-go

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Implements the HMAC-SHA family of signing methods signing methods
type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}

// The error from Parse if token is not valid
type JWTError struct {
	_errmsg string
	_errid  int
}

func (m *JWTError) ErrMsg() string {
	return m._errmsg
}

func (m *JWTError) ErrId() int {
	return m._errid
}

// Error constants
var (
	SigningMethodHS256        *SigningMethodHMAC
	EncodedHS256Header        string
	HS256HeaderBytes          []byte
	JWTErrAtExpired           = &JWTError{_errid: 1, _errmsg: "AccessToken过期"}
	JWTErrAtNotValid          = &JWTError{_errid: 2, _errmsg: "AccessToken失效"}
	JWTErrAtIllegal           = &JWTError{_errid: 3, _errmsg: "AccessToken不合法"}
	JWTErrRtExpired           = &JWTError{_errid: 4, _errmsg: "RefreshToken过期"}
	JWTErrRtNotValid          = &JWTError{_errid: 5, _errmsg: "RefreshToken失效"}  //没过有效期
	JWTErrRtIllegal           = &JWTError{_errid: 6, _errmsg: "RefreshToken不合法"} //没过有效期
	JWTErrNotFoundUser        = &JWTError{_errid: 7, _errmsg: "用户名或密码错误"}
	JWTErrNotActivedUser      = &JWTError{_errid: 8, _errmsg: "该用户还未激活"}
	JWTErrBannedUser          = &JWTError{_errid: 9, _errmsg: "该用户被封"}
	JWTErrDeniedUser          = &JWTError{_errid: 10, _errmsg: "该用户禁止登录"}
	JWTErrInvalidKey          = &JWTError{_errid: 30, _errmsg: "无效Key"}
	JWTErrInvalidSign         = &JWTError{_errid: 31, _errmsg: "无效Sign"}
	JWTErrDecodeSign          = &JWTError{_errid: 32, _errmsg: "解码Sign失败"}
	JWTErrFailDoSign          = &JWTError{_errid: 33, _errmsg: "Sign失败"}
	JWTErrIllegalTokenFormat  = &JWTError{_errid: 34, _errmsg: "Illegal Token格式"}
	JWTErrInvalidTokenHeader  = &JWTError{_errid: 35, _errmsg: "无效Token[0]"}
	JWTErrNotSupportAlgorithm = &JWTError{_errid: 36, _errmsg: "不支持的加密算法"}
	JWTErrInvalidGrantType    = &JWTError{_errid: 37, _errmsg: "无效的grant type"}
	JWTErrMakeCalim           = &JWTError{_errid: 38, _errmsg: "生成Token失败"}
	JWTErrDecodeCalim         = &JWTError{_errid: 39, _errmsg: "解析Token失败"}
	JWTErrInvalidCalim        = &JWTError{_errid: 40, _errmsg: "解析Token失败"}
)

func init() {
	// HS256
	SigningMethodHS256 = &SigningMethodHMAC{"HS256", crypto.SHA256}

	//Hard code header
	HS256HeaderBytes, _ = json.Marshal(`{"typ":"JWT","alg":"HS256"}`)
	EncodedHS256Header = _encode_segment(HS256HeaderBytes)
}

func (m *SigningMethodHMAC) Alg() string {
	return m.Name
}

func (m *SigningMethodHMAC) Verify(signingString, signature string, key []byte) *JWTError {
	if len(key) <= 0 {
		return JWTErrInvalidKey
	}

	var sig []byte
	var err error
	if sig, err = _decode_segment(signature); err == nil {
		if !m.Hash.Available() {
			return JWTErrInvalidSign
		}

		hasher := hmac.New(m.Hash.New, key)
		hasher.Write([]byte(signingString))

		if !hmac.Equal(sig, hasher.Sum(nil)) {
			return JWTErrInvalidSign
		}
	}
	if err != nil {
		return JWTErrDecodeSign
	}
	return nil
}

// Implements the Sign method from SigningMethod for this signing method.
// Key must be []byte
func (m *SigningMethodHMAC) Sign(signingString string, key []byte) (string, *JWTError) {
	if len(key) <= 0 {
		return "", JWTErrInvalidKey
	}
	if !m.Hash.Available() {
		return "", JWTErrInvalidSign
	}

	hasher := hmac.New(m.Hash.New, key)
	hasher.Write([]byte(signingString))

	return _encode_segment(hasher.Sum(nil)), nil
}

// Encode JWT specific base64url encoding with padding stripped
func _encode_segment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func _decode_segment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

//////===========================================
func CreateToken(claims_json []byte, key []byte) (string, *JWTError) {
	var sig string
	var jwtErr *JWTError
	encoded_part2_claims := _encode_segment(claims_json)
	tmp_part1_part2 := EncodedHS256Header + "." + encoded_part2_claims
	if sig, jwtErr = SigningMethodHS256.Sign(tmp_part1_part2, key); jwtErr != nil {
		return "", jwtErr
	}
	return tmp_part1_part2 + "." + sig, nil
}

//return claims_json
func ParseToken(token string, key []byte) ([]byte, *JWTError) {
	var err error
	var jwtErr *JWTError
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, JWTErrIllegalTokenFormat
	}

	// parse Header
	var headerBytes []byte
	if headerBytes, err = _decode_segment(parts[0]); err != nil {
		return nil, JWTErrInvalidTokenHeader
	}

	if !bytes.Equal(headerBytes, HS256HeaderBytes) {
		return nil, JWTErrNotSupportAlgorithm
	}

	// Perform validation
	if jwtErr = SigningMethodHS256.Verify(strings.Join(parts[0:2], "."), parts[2], key); jwtErr != nil {
		return nil, jwtErr
	}

	// parse Claims
	var claimBytes []byte
	if claimBytes, err = _decode_segment(parts[1]); err != nil {
		return nil, JWTErrDecodeCalim
	}

	if len(claimBytes) == 0 {
		return nil, JWTErrInvalidCalim
	}

	return claimBytes, nil
}
