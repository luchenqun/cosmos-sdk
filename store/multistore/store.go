package multistore

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"cosmossdk.io/log"
	v1types "cosmossdk.io/store/types"
	"cosmossdk.io/store/v2"
	"cosmossdk.io/store/v2/commitment"
	"github.com/cockroachdb/errors"
	ics23 "github.com/cosmos/ics23/go"
)

type (
	// MultiStore defines an abstraction layer containing a State Storage (SS) engine
	// and one or more State Commitment (SC) engines.
	//
	// TODO:
	// - Move relevant types to the 'core' package.
	// - Remove reliance on store v1 types.
	MultiStore interface {
		GetSCStore(storeKey string) *commitment.Database
		MountSCStore(storeKey string, sc *commitment.Database) error
		GetProof(storeKey string, version uint64, key []byte) (*ics23.CommitmentProof, error)
		LoadVersion(version uint64) error
		LoadLatestVersion() error
		GetLatestVersion() (uint64, error)
		WorkingHash() []byte
		Commit() ([]byte, error)
		SetCommitHeader(h CommitHeader)

		// TODO:
		// - Tracing
		// - Branching
		// - Queries

		io.Closer
	}

	CommitHeader interface {
		GetTime() time.Time
		GetHeight() uint64
	}
)

var _ MultiStore = &Store{}

type Store struct {
	logger         log.Logger
	commitHeader   CommitHeader
	initialVersion uint64

	// ss reflects the state storage backend
	ss store.VersionedDatabase

	// scStores reflect a mapping of store key to state commitment backend (i.e. a backend per module)
	scStores map[string]*commitment.Database

	// removalMap reflects module stores marked for removal
	removalMap map[string]struct{}

	// lastCommitInfo reflects the last version/hash that has been committed
	lastCommitInfo *v1types.CommitInfo
}

func New(logger log.Logger, initialVersion uint64, ss store.VersionedDatabase) (MultiStore, error) {
	return &Store{
		logger:         logger.With("module", "multi_store"),
		initialVersion: initialVersion,
		ss:             ss,
		scStores:       make(map[string]*commitment.Database),
		removalMap:     make(map[string]struct{}),
	}, nil
}

// Close closes the store and resets all internal fields. Note, Close() is NOT
// idempotent and should only be called once.
func (s *Store) Close() (err error) {
	err = errors.Join(err, s.ss.Close())
	for _, sc := range s.scStores {
		err = errors.Join(err, sc.Close())
	}

	s.ss = nil
	s.scStores = nil
	s.lastCommitInfo = nil
	s.commitHeader = nil
	s.removalMap = nil

	return err
}

func (s *Store) MountSCStore(storeKey string, sc *commitment.Database) error {
	s.logger.Debug("mounting store", "store_key", storeKey)
	if _, ok := s.scStores[storeKey]; ok {
		return fmt.Errorf("SC store with key %s already mounted", storeKey)
	}

	s.scStores[storeKey] = sc
	return nil
}

// LastCommitID returns a CommitID based off of the latest internal CommitInfo.
// If an internal CommitInfo is not set, a new one will be returned with only the
// latest version set, which is based off of the SS view.
func (s *Store) LastCommitID() (v1types.CommitID, error) {
	if s.lastCommitInfo == nil {
		lv, err := s.ss.GetLatestVersion()
		if err != nil {
			return v1types.CommitID{}, err
		}

		// ensure integrity of latest version across all SC stores
		for sk, sc := range s.scStores {
			scVersion := sc.GetLatestVersion()
			if scVersion != lv {
				return v1types.CommitID{}, fmt.Errorf("unexpected version for %s; got: %d, expected: %d", sk, scVersion, lv)
			}
		}

		return v1types.CommitID{
			Version: int64(lv),
		}, nil
	}

	return s.lastCommitInfo.CommitID(), nil
}

// GetLatestVersion returns the latest version based on the latest internal
// CommitInfo. An error is returned if the latest CommitInfo or version cannot
// be retrieved.
func (s *Store) GetLatestVersion() (uint64, error) {
	lastCommitID, err := s.LastCommitID()
	if err != nil {
		return 0, err
	}

	return uint64(lastCommitID.Version), nil
}

func (s *Store) GetProof(storeKey string, version uint64, key []byte) (*ics23.CommitmentProof, error) {
	sc, ok := s.scStores[storeKey]
	if !ok {
		return nil, fmt.Errorf("SC store with key %s not mounted", storeKey)
	}

	return sc.GetProof(version, key)
}

func (s *Store) GetSCStore(storeKey string) *commitment.Database {
	panic("not implemented!")
}

func (s *Store) LoadLatestVersion() error {
	lv, err := s.GetLatestVersion()
	if err != nil {
		return err
	}

	return s.loadVersion(lv, nil)
}

func (s *Store) LoadVersion(v uint64) (err error) {
	return s.loadVersion(v, nil)
}

func (s *Store) loadVersion(v uint64, upgrades *v1types.StoreUpgrades) (err error) {
	s.logger.Debug("loading version", "version", v)

	for sk, sc := range s.scStores {
		if loadErr := sc.LoadVersion(v); loadErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to load version %d for %s: %w", v, sk, loadErr))
		}
	}

	// TODO: Complete this method to handle upgrades. See legacy RMS loadVersion()
	// for reference.

	return err
}

func (s *Store) WorkingHash() []byte {
	storeInfos := make([]v1types.StoreInfo, 0, len(s.scStores))

	for sk, sc := range s.scStores {
		if _, ok := s.removalMap[sk]; ok {
			storeInfos = append(storeInfos, v1types.StoreInfo{
				Name: sk,
				CommitId: v1types.CommitID{
					Hash: sc.WorkingHash(),
				},
			})
		}
	}

	sort.SliceStable(storeInfos, func(i, j int) bool {
		return storeInfos[i].Name < storeInfos[j].Name
	})

	return v1types.CommitInfo{StoreInfos: storeInfos}.Hash()
}

func (s *Store) SetCommitHeader(h CommitHeader) {
	s.commitHeader = h
}

func (s *Store) Commit() ([]byte, error) {
	var previousHeight, version uint64
	if s.lastCommitInfo.GetVersion() == 0 && s.initialVersion > 1 {
		// This case means that no commit has been made in the store, we
		// start from initialVersion.
		version = s.initialVersion
	} else {
		// This case can means two things:
		//
		// 1. There was already a previous commit in the store, in which case we
		// 		increment the version from there.
		// 2. There was no previous commit, and initial version was not set, in which
		// 		case we start at version 1.
		previousHeight = uint64(s.lastCommitInfo.GetVersion())
		version = previousHeight + 1
	}

	if s.commitHeader.GetHeight() != version {
		s.logger.Debug("commit header and version mismatch", "header_height", s.commitHeader.GetHeight(), "version", version)
	}

	// remove and close all SC stores marked for removal
	for sk := range s.removalMap {
		if sc, ok := s.scStores[sk]; ok {
			if err := sc.Close(); err != nil {
				return nil, err
			}

			delete(s.scStores, sk)
		}
	}

	s.removalMap = make(map[string]struct{})

	// commit writes to SC stores
	commitInfo, err := s.commitSC(version)
	if err != nil {
		return nil, fmt.Errorf("failed to commit SC stores: %w", err)
	}

	s.lastCommitInfo = commitInfo
	s.lastCommitInfo.Timestamp = s.commitHeader.GetTime()

	// TODO: Commit writes to SS backend asynchronously.

	return s.lastCommitInfo.Hash(), nil
}

// commitSC commits each SC store individually and returns a CommitInfo
// representing commitment of all the SC stores. Note, commitment is NOT atomic.
// An error is returned if any SC store fails to commit.
func (s *Store) commitSC(version uint64) (*v1types.CommitInfo, error) {
	storeInfos := make([]v1types.StoreInfo, 0, len(s.scStores))

	for sk, sc := range s.scStores {
		// TODO: Handle and support SC store last CommitID to handle the case where
		// a Commit is interrupted and a SC store could have a version that is ahead:
		//
		// scLastCommitID := sc.LastCommitID()

		// var commitID v1types.CommitID
		// if scLastCommitID.Version >= version {
		// 	scLastCommitID.Version = version
		// 	commitID = scLastCommitID
		// } else {
		// 	commitID = store.Commit()
		// }

		commitBz, err := sc.Commit()
		if err != nil {
			return nil, fmt.Errorf("failed to commit SC store %s: %w", sk, err)
		}

		storeInfos = append(storeInfos, v1types.StoreInfo{
			Name: sk,
			CommitId: v1types.CommitID{
				Version: int64(version),
				Hash:    commitBz,
			},
		})
	}

	sort.SliceStable(storeInfos, func(i, j int) bool {
		return strings.Compare(storeInfos[i].Name, storeInfos[j].Name) < 0
	})

	return &v1types.CommitInfo{
		Version:    int64(version),
		StoreInfos: storeInfos,
	}, nil
}
