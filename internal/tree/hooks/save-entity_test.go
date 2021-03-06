package hooks

import (
	"testing"

	"github.com/golang/protobuf/proto"

	"github.com/netauth/netauth/internal/db"
	_ "github.com/netauth/netauth/internal/db/memory"
	"github.com/netauth/netauth/internal/startup"
	"github.com/netauth/netauth/internal/tree"

	pb "github.com/netauth/protocol"
)

func TestSaveEntity(t *testing.T) {
	startup.DoCallbacks()

	mdb, err := db.New("memory")
	if err != nil {
		t.Fatal(err)
	}

	hook, err := NewSaveEntity(tree.RefContext{DB: mdb})
	if err != nil {
		t.Fatal(err)
	}

	e := &pb.Entity{ID: proto.String("foobar")}

	if err := hook.Run(e, &pb.Entity{}); err != nil {
		t.Fatal(err)
	}

	if _, err := mdb.LoadEntity("foobar"); err != nil {
		t.Fatal("Entity wasn't saved", err)
	}
}

func TestSaveEntityCB(t *testing.T) {
	saveEntityCB()
}
