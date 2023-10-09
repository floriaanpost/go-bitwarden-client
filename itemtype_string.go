// Code generated by "stringer -type=ItemType,Reprompt"; DO NOT EDIT.

package bitwarden

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[TypeLogin-1]
	_ = x[TypeSecureNote-2]
	_ = x[TypeCard-3]
	_ = x[TypeIdentity-4]
}

const _ItemType_name = "TypeLoginTypeSecureNoteTypeCardTypeIdentity"

var _ItemType_index = [...]uint8{0, 9, 23, 31, 43}

func (i ItemType) String() string {
	i -= 1
	if i < 0 || i >= ItemType(len(_ItemType_index)-1) {
		return "ItemType(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ItemType_name[_ItemType_index[i]:_ItemType_index[i+1]]
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[RepromptNo-0]
	_ = x[RepromptYes-1]
}

const _Reprompt_name = "RepromptNoRepromptYes"

var _Reprompt_index = [...]uint8{0, 10, 21}

func (i Reprompt) String() string {
	if i < 0 || i >= Reprompt(len(_Reprompt_index)-1) {
		return "Reprompt(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Reprompt_name[_Reprompt_index[i]:_Reprompt_index[i+1]]
}
