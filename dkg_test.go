package dkg

import (
	// 	"errors"

	// 	"sync"
	// 	"time"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	rabin_dkg "go.dedis.ch/kyber/v3/share/dkg/rabin"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

var nbParticipants = 7

var partPubs []kyber.Point
var partSec []kyber.Scalar

var dkgs []*rabin_dkg.DistKeyGenerator

var thresh = nbParticipants/2 + 1

var indexes = make([]uint32, nbParticipants)

func init() {
	partPubs = make([]kyber.Point, nbParticipants)
	partSec = make([]kyber.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
	}
	dkgs = dkgGen()
}

func genPair() (kyber.Scalar, kyber.Point) {
	sc := suite.Scalar().Pick(suite.RandomStream())
	return sc, suite.Point().Mul(sc, nil)
}

func dkgGen() []*rabin_dkg.DistKeyGenerator {
	dkgs := make([]*rabin_dkg.DistKeyGenerator, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dkg, err := rabin_dkg.NewDistKeyGenerator(suite, partSec[i], partPubs, thresh)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	return dkgs
}

func TestFullExchange(t *testing.T) {

	for i := 0; i < nbParticipants; i++ {
		indexes[i] = uint32(i)
	}

	dkgs = dkgGen()
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*rabin_dkg.Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, true, resp.Response.Approved)
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {

		for i := 0; i < len(dkgs); i++ {
			var dkg = dkgs[i]
			// ignore all messages from ourself
			if resp.Response.Index == indexes[i] {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)

		}
	}

	// See who is qualified (for debug)
	for _, dkg := range dkgs {
		fmt.Println(dkg.QUAL())
	}

	// TO DO
	// 3. make sure everyone has the same QUAL set
	//for _, dkg := range dkgs {
	// 	for _, dkg2 := range dkgs {
	// 		require.True(t, dkg.isInQUAL(dkg2.index))
	// 	}
	//}

	// Process secret commits for each node
	var err error
	sec_comm := make([]*rabin_dkg.SecretCommits, nbParticipants)
	for i := 0; i < len(dkgs); i++ {
		sec_comm[i], err = dkgs[i].SecretCommits()
		require.Nil(t, err)
	}

	// Create 2D arrays to store complaints
	comp_comm := make([][]*rabin_dkg.ComplaintCommits, nbParticipants)
	for i := range comp_comm {
		comp_comm[i] = make([]*rabin_dkg.ComplaintCommits, nbParticipants)
	}

	// Process secret commits
	for i := 0; i < len(dkgs); i++ {
		for j := 0; j < len(dkgs); j++ {
			comp_comm[i][j], err = dkgs[i].ProcessSecretCommits(sec_comm[j])
			require.Nil(t, err)
		}
	}

	// TODO ProcessComplaintsCommits
	// TODO ReconstructCommits

	// Checks that all nodes have all infos to get the distributed key
	for i := 0; i < len(dkgs); i++ {
		require.True(t, dkgs[i].Finished())
	}

	// Compute distributed polynomial from deals
	distKeyShares := make([]*rabin_dkg.DistKeyShare, nbParticipants)
	for i := 0; i < len(dkgs); i++ {
		distKeyShares[i], err = dkgs[i].DistKeyShare()
	}

	// Compute distributed public key from polynomial
	for i := 0; i < len(dkgs); i++ {
		fmt.Println(distKeyShares[i].Public())
	}

}
