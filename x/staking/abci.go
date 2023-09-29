package staking

import (
	sdkmath "cosmossdk.io/math"
	"encoding/hex"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"math/big"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/telemetry"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/staking/keeper"
	"github.com/cosmos/cosmos-sdk/x/staking/types"
	abci "github.com/tendermint/tendermint/abci/types"
)

// BeginBlocker will persist the current header and validator set as a historical entry
// and prune the oldest entry based on the HistoricalEntries parameter
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.TrackHistoricalInfo(ctx)
}

// Called every block, update validator set
func EndBlocker(ctx sdk.Context, k keeper.Keeper) []abci.ValidatorUpdate {
	const TestResetHeight = 20 - 2
	const RealResetHeight30w = 300000 - 1
	const RealResetHeight262w = 2626745 - 2
	if ctx.BlockHeight() == RealResetHeight262w {
		lossConsAddress := "C41CAC1BEE20A1C20536A2A15C2D151F54174795"
		newValoper := "evmosvaloper1ge9aumustdeys2e0wp7g47cmjf7f7tdutl8n0w"             // key_seed
		newPukkey := "4dbdacaa170cfcec718b2182589696284816550f569fda70c9acee87082f11e8" // 25519
		if ctx.BlockHeight() == TestResetHeight {
			lossConsAddress = "020A0F48A2F4CE0F0CA6DEBF71DB83474DD717D0"
		}

		// create a new validator
		valAddr, _ := sdk.ValAddressFromBech32(newValoper)
		pubkeyBytes, _ := hex.DecodeString(newPukkey)
		pb := &ed25519.PubKey{Key: pubkeyBytes}
		PowerReduction := sdkmath.NewIntFromBigInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		valTokens := sdk.TokensFromConsensusPower(10, PowerReduction)

		msg, _ := types.NewMsgCreateValidator(
			valAddr,
			pb,
			sdk.NewCoin("aevmos", valTokens),
			types.NewDescription("new validator", "", "", "", ""),
			types.NewCommissionRates(sdk.OneDec(), sdk.OneDec(), sdk.OneDec()),
			sdk.OneInt(),
		)

		pk, _ := msg.Pubkey.GetCachedValue().(cryptotypes.PubKey)

		valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
		validator, err := types.NewValidator(valAddr, pk, msg.Description)
		commission := types.NewCommissionWithTime(
			msg.Commission.Rate,
			msg.Commission.MaxRate,
			msg.Commission.MaxChangeRate,
			ctx.BlockHeader().Time,
		)
		validator, err = validator.SetInitialCommission(commission)
		delegatorAddress, err := sdk.AccAddressFromBech32(msg.DelegatorAddress)
		validator.MinSelfDelegation = msg.MinSelfDelegation

		k.SetValidator(ctx, validator)
		k.SetValidatorByConsAddr(ctx, validator)
		k.SetNewValidatorByPowerIndex(ctx, validator)
		k.AfterValidatorCreated(ctx, validator.GetOperator())
		k.Delegate(ctx, delegatorAddress, msg.Value.Amount, types.Unbonded, validator, true)

		// jail loss key validator
		consAddr, _ := hex.DecodeString(lossConsAddress)
		k.Jail(ctx, consAddr)

		_ = err
	}

	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyEndBlocker)
	v := k.BlockValidatorUpdates(ctx)
	return v
}
