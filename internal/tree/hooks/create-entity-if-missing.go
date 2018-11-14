package hooks

import (
	"github.com/NetAuth/NetAuth/internal/db"
	"github.com/NetAuth/NetAuth/internal/tree"
	"github.com/golang/protobuf/proto"

	pb "github.com/NetAuth/Protocol"
)

// CreateEntityIfMissing is an EntityProcessor hook that will ensure
// that e exists and is populated before returning.  This hook is
// primarily used for bootstrap actions where an entity needs to
// either exist or be created and it isn't important which of these
// happens.
type CreateEntityIfMissing struct {
	tree.BaseHook
	db.DB
}

// Run will attempt to load the entity from an external source.  If
// the load returns that the failure is due to an unknown entity, then
// one will be created.  Any other load failure will result in an
// error being returned.  Returned errors will be of a db.* type.
func (c *CreateEntityIfMissing) Run(e, de *pb.Entity) error {
	le, err := c.LoadEntity(de.GetID())
	switch err {
	case nil:
		proto.Merge(e, le)
		return err
	case db.ErrUnknownEntity:
		break
	default:
		return err
	}

	ce := &pb.Entity{
		ID: de.ID,
	}
	proto.Merge(e, ce)
	return nil
}

func init() {
	tree.RegisterEntityHookConstructor("create-entity-if-missing", NewCreateEntityIfMissing)
}

// NewCreateEntityIfMissing returns an initalized hook for use during
// tree initialization.
func NewCreateEntityIfMissing(c tree.RefContext) (tree.EntityProcessorHook, error) {
	return &CreateEntityIfMissing{tree.NewBaseHook("create-entity-if-missing", 1), c.DB}, nil
}