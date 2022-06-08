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

	//"go.dedis.ch/kyber/v3/share"
	rabin_dkg "go.dedis.ch/kyber/v3/share/dkg/rabin"
	"go.dedis.ch/kyber/v3/sign/dss"
	"go.dedis.ch/kyber/v3/sign/eddsa"
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
	secComm := make([]*rabin_dkg.SecretCommits, nbParticipants)
	for i := 0; i < len(dkgs); i++ {
		secComm[i], err = dkgs[i].SecretCommits()
		require.Nil(t, err)
	}

	// Create 2D arrays to store complaints
	compComm := make([][]*rabin_dkg.ComplaintCommits, nbParticipants)
	for i := range compComm {
		compComm[i] = make([]*rabin_dkg.ComplaintCommits, nbParticipants)
	}

	// Process secret commits
	for i := 0; i < len(dkgs); i++ {
		for j := 0; j < len(dkgs); j++ {
			compComm[i][j], err = dkgs[i].ProcessSecretCommits(secComm[j])
			require.Nil(t, err)
		}
	}

	// TODO ProcessComplaintsCommits
	// TODO ADD OK to check if no complaints
	// TODO ReconstructCommits

	// Checks that all nodes have all infos to get the distributed key
	for i := 0; i < len(dkgs); i++ {
		require.True(t, dkgs[i].Finished())
	}

	// Compute distributed polynomial from deals
	distKeyShares := make([]*rabin_dkg.DistKeyShare, nbParticipants)
	for i := 0; i < len(dkgs); i++ {
		distKeyShares[i], err = dkgs[i].DistKeyShare()
		require.Nil(t, err)
	}

	// Compute distributed public key from polynomial
	var pubKey kyber.Point
	for i := 0; i < len(dkgs); i++ {
		pubKey = distKeyShares[i].Public()
		fmt.Println(pubKey)

	}

	// msg to sign
	msg := []byte("hello")

	// create dss struct
	dsses := make([]*dss.DSS, nbParticipants)
	for i := 0; i < len(dkgs); i++ {
		dsses[i], err = dss.NewDSS(suite, partSec[i], partPubs, distKeyShares[i], distKeyShares[i], msg, thresh)
		require.NotNil(t, dsses[i])
		require.Nil(t, err)
	}

	// partial sig
	partialSigs := make([]*dss.PartialSig, nbParticipants)
	for i := 0; i < len(dkgs); i++ {
		partialSigs[i], err = dsses[i].PartialSig()
		require.Nil(t, err)
	}

	// process partial sigs
	for i := 0; i < len(dkgs); i++ {
		for j := 0; j < len(dkgs); j++ {
			if i != j {
				err = dsses[i].ProcessPartialSig(partialSigs[j])
				require.Nil(t, err)
			}
		}
	}

	// make final signature
	finalSigs := make([][]byte, nbParticipants)
	for i := 0; i < len(dkgs); i++ {
		finalSigs[i], err = dsses[i].Signature()
		require.Nil(t, err)
	}

	// verify signature
	for i := 0; i < len(dkgs); i++ {
		err = eddsa.Verify(distKeyShares[i].Public(), msg, finalSigs[i])
		require.Nil(t, err)
	}

}
