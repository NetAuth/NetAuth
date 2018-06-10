package client

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/NetAuth/NetAuth/internal/token"
	_ "github.com/NetAuth/NetAuth/internal/token/impl"
	"github.com/NetAuth/NetAuth/internal/tree"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/NetAuth/Protocol"
)

type netAuthClient struct {
	c          pb.NetAuthClient
	serviceID  *string
	clientID   *string
	tokenStore TokenStore

	tokenService token.TokenService
}

// New takes in the values that set up a client and builds a
// client.netAuthClient struct on which all other methods are bound.
// This drastically simplifies the construction of other functions.
func New(server string, port int, serviceID string, clientID string) (*netAuthClient, error) {
	// Setup the connection.
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", server, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	// Get a tokenstore
	t, err := getTokenStore()
	if err != nil {
		// Log the error, but as there are many queries done
		// in read only mode, don't fail on it.
		log.Println(err)
	}

	// Get a token service, don't be a fatal error as most queries
	// don't require authentication anyway.
	ts, err := token.New()
	if err != nil {
		log.Println(err)
	}

	// Create a client to use later on.
	client := netAuthClient{
		c:            pb.NewNetAuthClient(conn),
		serviceID:    ensureServiceID(serviceID),
		clientID:     ensureClientID(clientID),
		tokenStore:   t,
		tokenService: ts,
	}

	return &client, nil
}

// Ping very simply pings the server.  The reply will contain the
// health status of the server as a server that replies and a server
// that can serve are two very different things (data might be
// reloading during the request).
func (n *netAuthClient) Ping() (*pb.PingResponse, error) {
	request := &pb.PingRequest{
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.Ping(context.Background(), request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// Authenticate takes in an entity and a secret and tries to validate
// that the identity is legitimate by verifying the secret provided.
func (n *netAuthClient) Authenticate(entity string, secret string) (*pb.SimpleResult, error) {
	request := pb.NetAuthRequest{
		Entity: &pb.Entity{
			ID:     &entity,
			Secret: &secret,
		},
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.AuthEntity(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// GetToken is identical to Authenticate except on success it will
// return a token which can be used to authorize additional later
// requests.
func (n *netAuthClient) GetToken(entity, secret string) (string, error) {
	// See if we have a local copy first.
	t, err := n.getTokenFromStore(entity)
	if err == nil {
		if _, err := n.InspectToken(t); err == nil {
			return t, nil
		}
	}

	request := pb.NetAuthRequest{
		Entity: &pb.Entity{
			ID:     &entity,
			Secret: &secret,
		},
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}
	tokenResult, err := n.c.GetToken(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return "", err
	}

	t = tokenResult.GetToken()
	if err := n.tokenStore.DestroyToken(entity); err != nil {
		return "", err
	}
	err = n.putTokenInStore(entity, t)
	return t, err
}

// ValidateToken sends the token to the server for validation.  This
// is effectively asking the server to authenticate the token and not
// do anything else.  Returns a comment from the server and an error.
func (n *netAuthClient) ValidateToken(entity string) (*pb.SimpleResult, error) {
	t, err := n.getTokenFromStore(entity)
	if err != nil {
		return nil, err
	}

	request := pb.NetAuthRequest{
		Entity: &pb.Entity{
			ID: &entity,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.ValidateToken(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// ChangeSecret crafts a modEntity request with the correct fields to
// change an entity secret either via self authentication or via token
// authentication which is held by an appropriate administrator.
func (n *netAuthClient) ChangeSecret(e, s, me, ms, t string) (*pb.SimpleResult, error) {
	request := pb.ModEntityRequest{
		Entity: &pb.Entity{
			ID:     &e,
			Secret: &s,
		},
		ModEntity: &pb.Entity{
			ID:     &me,
			Secret: &ms,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.ChangeSecret(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// NewEntity crafts a modEntity request with the correct fields to
// create a new entity.
func (n *netAuthClient) NewEntity(id string, uidn int32, secret, t string) (*pb.SimpleResult, error) {
	request := pb.ModEntityRequest{
		Entity: &pb.Entity{
			ID:     &id,
			Number: &uidn,
			Secret: &secret,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.NewEntity(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// RemoveEntity removes an entity by the given name.  Only the
// 'entity' field of the modEntityRequest is required.
func (n *netAuthClient) RemoveEntity(id, token string) (*pb.SimpleResult, error) {
	request := pb.ModEntityRequest{
		Entity: &pb.Entity{
			ID: &id,
		},
		AuthToken: &token,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.RemoveEntity(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// Obtain the entity object with the secure fields redacted.  This is
// primarily used for displaying the values of the metadata struct
// internally.
func (n *netAuthClient) EntityInfo(id string) (*pb.Entity, error) {
	request := pb.NetAuthRequest{
		Entity: &pb.Entity{
			ID: &id,
		},
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}
	result, err := n.c.EntityInfo(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// ModifyEntityMeta makes an authenticated request to the server to
// update the metadata of an entity.
func (n *netAuthClient) ModifyEntityMeta(id, t string, meta *pb.EntityMeta) (*pb.SimpleResult, error) {
	request := pb.ModEntityRequest{
		Entity: &pb.Entity{
			ID:   &id,
			Meta: meta,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.ModifyEntityMeta(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// ModifyEntityKeys modifies the keys on an entity, this action must
// be authorized.
func (n *netAuthClient) ModifyEntityKeys(t, e, m, kt, kv string) ([]string, error) {
	request := pb.ModEntityKeyRequest{
		Entity: &pb.Entity{
			ID: &e,
		},
		AuthToken: &t,
		Mode:      &m,
		Type:      &kt,
		Key:       &kv,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}
	result, err := n.c.ModifyEntityKeys(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result.GetKeys(), nil
}

// NewGroup creates a new group with the given name, display name, and
// group number.  This action must be authorized.
func (n *netAuthClient) NewGroup(name, displayname, managedby, t string, number int) (*pb.SimpleResult, error) {
	gid := int32(number)
	request := pb.ModGroupRequest{
		Group: &pb.Group{
			Name:        &name,
			DisplayName: &displayname,
			Number:      &gid,
			ManagedBy:   &managedby,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.NewGroup(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// DeleteGroup removes a group by name.  This action must be
// authorized.
func (n *netAuthClient) DeleteGroup(name, t string) (*pb.SimpleResult, error) {
	request := pb.ModGroupRequest{
		Group: &pb.Group{
			Name: &name,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.DeleteGroup(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// ListGroups returns a list of groups to the caller.  This action
// does not require authorization.
func (n *netAuthClient) ListGroups(entity string, indirects bool) ([]*pb.Group, error) {
	request := pb.GroupListRequest{
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
		IncludeIndirects: &indirects,
	}

	if entity != "" {
		request.Entity = &pb.Entity{ID: &entity}
	}

	result, err := n.c.ListGroups(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result.GetGroups(), nil
}

// GroupInfo provides information about a single group.
func (n *netAuthClient) GroupInfo(name string) (*pb.GroupInfoResult, error) {
	request := pb.ModGroupRequest{
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
		Group: &pb.Group{
			Name: &name,
		},
		AuthToken: proto.String(""),
	}

	result, err := n.c.GroupInfo(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// ModifyGroupMeta allows a group's metadata to be altered after the
// fact.  This action must be authorized.
func (n *netAuthClient) ModifyGroupMeta(group *pb.Group, token string) (*pb.SimpleResult, error) {
	request := pb.ModGroupRequest{
		Group:     group,
		AuthToken: &token,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.ModifyGroupMeta(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// AddEntityToGroup modifies direct membership of entities.  This
// action must be authorized.
func (n *netAuthClient) AddEntityToGroup(t, g, e string) (*pb.SimpleResult, error) {
	request := pb.ModEntityMembershipRequest{
		Entity: &pb.Entity{
			ID: &e,
		},
		Group: &pb.Group{
			Name: &g,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.AddEntityToGroup(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// RemoveEntityFromGroup modifies direct membership of entities.  This
// action must be authorized.
func (n *netAuthClient) RemoveEntityFromGroup(t, g, e string) (*pb.SimpleResult, error) {
	request := pb.ModEntityMembershipRequest{
		Entity: &pb.Entity{
			ID: &e,
		},
		Group: &pb.Group{
			Name: &g,
		},
		AuthToken: &t,
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.RemoveEntityFromGroup(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// ListGroupMembers returns a list of members for the requested group.
// This action does not require authorization.
func (n *netAuthClient) ListGroupMembers(g string) ([]*pb.Entity, error) {
	request := pb.GroupMemberRequest{
		Group: &pb.Group{
			Name: &g,
		},
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
	}

	result, err := n.c.ListGroupMembers(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result.GetMembers(), nil
}

// ModifyGroupExpansions modifies the parent/child status of the provided groups.
// This action must be authorized.
func (n *netAuthClient) ModifyGroupExpansions(t, p, c, m string) (*pb.SimpleResult, error) {
	mode := pb.ExpansionMode(pb.ExpansionMode_value[m])

	request := pb.ModGroupNestingRequest{
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
		AuthToken: &t,
		ParentGroup: &pb.Group{
			Name: &p,
		},
		ChildGroup: &pb.Group{
			Name: &c,
		},
		Mode: &mode,
	}

	result, err := n.c.ModifyGroupNesting(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

// ManageCapabilities modifies the capabilities present on an entity
// or group.  This action must be authorized.
func (n *netAuthClient) ManageCapabilities(t, e, g, c, m string) (*pb.SimpleResult, error) {
	capID, ok := pb.Capability_value[c]
	if !ok {
		return nil, tree.UnknownCapability
	}
	cap := pb.Capability(capID)

	request := pb.ModCapabilityRequest{
		Info: &pb.ClientInfo{
			ID:      n.clientID,
			Service: n.serviceID,
		},
		AuthToken:  &t,
		Mode:       &m,
		Capability: &cap,
	}

	if e != "" {
		request.Entity = &pb.Entity{ID: &e}
	} else if g != "" {
		request.Group = &pb.Group{Name: &g}
	}

	result, err := n.c.ManageCapabilities(context.Background(), &request)
	if status.Code(err) != codes.OK {
		return nil, err
	}
	return result, nil
}

func ensureClientID(clientID string) *string {
	if clientID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			clientID = "BOGUS_CLIENT"
			return &clientID
		}
		clientID = hostname
	}
	return &clientID
}

func ensureServiceID(serviceID string) *string {
	if serviceID == "" {
		serviceID = "BOGUS_SERVICE"
	}
	return &serviceID
}
