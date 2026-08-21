package apb

type FieldKind int

const (
	FieldUnknown FieldKind = iota
	FieldFixedWidth
	FieldRPC
)

type FieldDefinition struct {
	ID   uint32
	Name string
	Kind FieldKind

	// TotalBits includes the field index itself.
	// 0 means variable/decoded by a dedicated parser.
	TotalBits int
}

var ControllerFields = map[uint32]FieldDefinition{
	78: {
		ID:        78,
		Name:      "KnownField78",
		Kind:      FieldFixedWidth,
		TotalBits: 66,
	},

	90: {
		ID:   90,
		Name: "ServerUpdateLevelVisibility",
		Kind: FieldRPC,
	},

	371: {
		ID:   371,
		Name: "ServerSelectSpawnZone",
		Kind: FieldRPC,
	},

	372: {
		ID:   372,
		Name: "ServerNotifyClientLoaded",
		Kind: FieldRPC,
	},

	484: {
		ID:        484,
		Name:      "KnownField484",
		Kind:      FieldFixedWidth,
		TotalBits: 168,
	},

	489: {
		ID:   489,
		Name: "ServerRequestCharacterData",
		Kind: FieldRPC,
	},

	491: {
		ID:   491,
		Name: "ServerRequestCharacterStats",
		Kind: FieldRPC,
	},

	498: {
		ID:   498,
		Name: "ServerRequestCharacterRolesData",
		Kind: FieldRPC,
	},

	530: {
		ID:        530,
		Name:      "NotifyServerLfgStateChanged",
		Kind:      FieldFixedWidth,
		TotalBits: 21,
	},
}

func LookupField(id uint32) (FieldDefinition, bool) {
	field, ok := ControllerFields[id]
	return field, ok
}
