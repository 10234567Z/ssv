package duties

import (
	"context"
	"fmt"
	"time"

	eth2apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	spectypes "github.com/ssvlabs/ssv-spec/types"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv/observability"
	"github.com/ssvlabs/ssv/observability/log/fields"
	"github.com/ssvlabs/ssv/observability/traces"
	"github.com/ssvlabs/ssv/operator/duties/dutystore"
)

type ProposerHandler struct {
	baseHandler

	duties *dutystore.Duties[eth2apiv1.ProposerDuty]

	// fetchCurrentEpoch stores the intent to fetch duties for the current epoch, while
	// processFetching func uses this value to decide on whether the fetch is needed.
	fetchCurrentEpoch bool
	// fetchNextEpoch stores the intent to fetch duties for the next epoch, while
	// processFetching func uses this value to decide on whether the fetch is needed.
	fetchNextEpoch bool

	exporterMode bool
}

func NewProposerHandler(duties *dutystore.Duties[eth2apiv1.ProposerDuty], exporterMode bool) *ProposerHandler {
	return &ProposerHandler{
		duties:       duties,
		exporterMode: exporterMode,
	}
}

func (h *ProposerHandler) Name() string {
	return spectypes.BNRoleProposer.String()
}

// HandleDuties manages the duty lifecycle, handling different cases:
//
// On First Run:
//  1. Fetch duties for the current epoch.
//  2. If necessary, fetch duties for the next epoch.
//  3. Execute duties.
//
// On Re-org (current dependent root changed):
//  1. Fetch duties for the current epoch.
//  2. Execute duties.
//  3. If necessary, fetch duties for the next epoch.
//
// On Indices Change:
//  1. Execute duties.
//  2. ResetEpoch duties for the current epoch.
//  3. Fetch duties for the current epoch.
//  4. If necessary, fetch duties for the next epoch.
//
// On Ticker event:
//  1. Execute duties.
//  2. If necessary, fetch duties for the next epoch.
func (h *ProposerHandler) HandleDuties(ctx context.Context) {
	h.logger.Info("starting duty handler")
	defer h.logger.Info("duty handler exited")

	next := h.ticker.Next()
	for {
		select {
		case <-ctx.Done():
			return

		case <-next:
			slot := h.ticker.Slot()
			next = h.ticker.Next()
			currentEpoch := h.beaconConfig.EstimatedEpochAtSlot(slot)
			buildStr := fmt.Sprintf("e%v-s%v-#%v", currentEpoch, slot, slot%32+1)
			h.logger.Debug("🛠 ticker event", zap.String("epoch_slot_pos", buildStr))

			func() {
				tickCtx, cancel := h.ctxWithDeadlineOnNextSlot(ctx, slot)
				defer cancel()

				h.processExecution(tickCtx, currentEpoch, slot)

				slotsPerEpoch := h.beaconConfig.SlotsPerEpoch

				// If we have reached the mid-point of the epoch, fetch the duties for the next epoch in the next slot.
				// This allows us to set them up at a time when the beacon node should be less busy.
				if uint64(slot)%slotsPerEpoch == slotsPerEpoch/2-1 {
					h.fetchNextEpoch = true
				}

				h.processFetching(tickCtx, currentEpoch, slot)

				// last slot of epoch
				if uint64(slot)%slotsPerEpoch == slotsPerEpoch-1 {
					h.duties.ResetEpoch(currentEpoch - 1)
				}
			}()

		case reorgEvent := <-h.reorg:
			currentEpoch := h.beaconConfig.EstimatedEpochAtSlot(reorgEvent.Slot)
			buildStr := fmt.Sprintf("e%v-s%v-#%v", currentEpoch, reorgEvent.Slot, reorgEvent.Slot%32+1)
			h.logger.Info("🔀 reorg event received", zap.String("epoch_slot_pos", buildStr), zap.Any("event", reorgEvent))

			// reset current epoch duties
			if reorgEvent.Current {
				h.duties.ResetEpoch(currentEpoch)
				h.fetchCurrentEpoch = true
				if h.shouldFetchNexEpoch(reorgEvent.Slot) {
					h.duties.ResetEpoch(currentEpoch + 1)
					h.fetchNextEpoch = true
				}
			}

		case <-h.indicesChange:
			slot := h.beaconConfig.EstimatedCurrentSlot()
			currentEpoch := h.beaconConfig.EstimatedEpochAtSlot(slot)
			buildStr := fmt.Sprintf("e%v-s%v-#%v", currentEpoch, slot, slot%32+1)
			h.logger.Info("🔁 indices change received", zap.String("epoch_slot_pos", buildStr))

			h.fetchCurrentEpoch = true

			// reset next epoch duties if in appropriate slot range
			if h.shouldFetchNexEpoch(slot) {
				h.fetchNextEpoch = true
			}
		}
	}
}

// HandleInitialDuties fetches duties for the current and next epochs.
// Fetching duties for the next epoch is necessary if we are starting close to epoch-boundary because
// our ticker might "miss" that rollover otherwise.
func (h *ProposerHandler) HandleInitialDuties(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, h.beaconConfig.SlotDuration)
	defer cancel()

	h.fetchCurrentEpoch = true
	h.fetchNextEpoch = true

	slot := h.beaconConfig.EstimatedCurrentSlot()
	epoch := h.beaconConfig.EstimatedEpochAtSlot(slot)
	h.processFetching(ctx, epoch, slot)
}

func (h *ProposerHandler) processFetching(ctx context.Context, epoch phase0.Epoch, slot phase0.Slot) {
	ctx, span := tracer.Start(ctx,
		observability.InstrumentName(observabilityNamespace, "proposer.fetch"),
		trace.WithAttributes(
			observability.BeaconEpochAttribute(epoch),
			observability.BeaconSlotAttribute(slot),
			observability.BeaconRoleAttribute(spectypes.BNRoleProposer),
		))
	defer span.End()

	if h.fetchCurrentEpoch {
		span.AddEvent("fetching current epoch duties")
		if err := h.fetchAndProcessDuties(ctx, epoch); err != nil {
			h.logger.Error("failed to fetch duties for current epoch", zap.Error(err))
			span.SetStatus(codes.Error, err.Error())
			return
		}
		h.fetchCurrentEpoch = false
	}

	// This additional shouldFetchNexEpoch check here is an optimization that prevents
	// unnecessary(duplicate) fetches in some cases + also delays the fetch until we
	// cannot delay it much further.
	if h.fetchNextEpoch && h.shouldFetchNexEpoch(slot) {
		span.AddEvent("fetching next epoch duties")
		if err := h.fetchAndProcessDuties(ctx, epoch+1); err != nil {
			h.logger.Error("failed to fetch duties for next epoch", zap.Error(err))
			span.SetStatus(codes.Error, err.Error())
			return
		}
		h.fetchNextEpoch = false
	}

	span.SetStatus(codes.Ok, "")
}

func (h *ProposerHandler) processExecution(ctx context.Context, epoch phase0.Epoch, slot phase0.Slot) {
	if h.exporterMode {
		return
	}

	ctx, span := tracer.Start(ctx,
		observability.InstrumentName(observabilityNamespace, "proposer.execute"),
		trace.WithAttributes(
			observability.BeaconEpochAttribute(epoch),
			observability.BeaconSlotAttribute(slot),
			observability.BeaconRoleAttribute(spectypes.BNRoleProposer),
		))
	defer span.End()

	duties := h.duties.CommitteeSlotDuties(epoch, slot)
	if duties == nil {
		span.AddEvent("no duties available")
		span.SetStatus(codes.Ok, "")
		return
	}

	// range over duties and execute
	span.AddEvent("duties fetched", trace.WithAttributes(observability.DutyCountAttribute(len(duties))))
	toExecute := make([]*spectypes.ValidatorDuty, 0, len(duties))
	for _, d := range duties {
		if h.shouldExecute(d) {
			toExecute = append(toExecute, h.toSpecDuty(d, spectypes.BNRoleProposer))
		}
	}
	span.AddEvent("executing duties", trace.WithAttributes(observability.DutyCountAttribute(len(toExecute))))

	h.dutiesExecutor.ExecuteDuties(ctx, toExecute)

	span.SetStatus(codes.Ok, "")
}

func (h *ProposerHandler) fetchAndProcessDuties(ctx context.Context, epoch phase0.Epoch) error {
	start := time.Now()
	ctx, span := tracer.Start(ctx,
		observability.InstrumentName(observabilityNamespace, "proposer.fetch_and_store"),
		trace.WithAttributes(
			observability.BeaconEpochAttribute(epoch),
			observability.BeaconRoleAttribute(spectypes.BNRoleProposer),
		))
	defer span.End()

	var allEligibleIndices []phase0.ValidatorIndex
	for _, share := range h.validatorProvider.Validators() {
		if share.IsAttesting(epoch) {
			allEligibleIndices = append(allEligibleIndices, share.ValidatorIndex)
		}
	}
	if len(allEligibleIndices) == 0 {
		const eventMsg = "no eligible validators for epoch"
		h.logger.Debug(eventMsg, fields.Epoch(epoch))
		span.AddEvent(eventMsg)
		span.SetStatus(codes.Ok, "")
		return nil
	}

	selfEligibleIndices := map[phase0.ValidatorIndex]struct{}{}
	for _, share := range h.validatorProvider.SelfValidators() {
		if share.IsAttesting(epoch) {
			selfEligibleIndices[share.ValidatorIndex] = struct{}{}
		}
	}

	span.AddEvent("fetching duties from beacon node", trace.WithAttributes(observability.ValidatorCountAttribute(len(allEligibleIndices))))
	duties, err := h.beaconNode.ProposerDuties(ctx, epoch, allEligibleIndices)
	if err != nil {
		return traces.Errorf(span, "failed to fetch proposer duties: %w", err)
	}

	specDuties := make([]*spectypes.ValidatorDuty, 0, len(duties))
	storeDuties := make([]dutystore.StoreDuty[eth2apiv1.ProposerDuty], 0, len(duties))
	for _, d := range duties {
		_, inCommitteeDuty := selfEligibleIndices[d.ValidatorIndex]
		storeDuties = append(storeDuties, dutystore.StoreDuty[eth2apiv1.ProposerDuty]{
			Slot:           d.Slot,
			ValidatorIndex: d.ValidatorIndex,
			Duty:           d,
			InCommittee:    inCommitteeDuty,
		})
		span.AddEvent("will store duty", trace.WithAttributes(observability.ValidatorIndexAttribute(d.ValidatorIndex)))
		specDuties = append(specDuties, h.toSpecDuty(d, spectypes.BNRoleProposer))
	}

	span.AddEvent("storing duties", trace.WithAttributes(observability.DutyCountAttribute(len(storeDuties))))
	h.duties.Set(epoch, storeDuties)

	truncate := -1
	if h.exporterMode {
		truncate = 10
	}
	h.logger.Debug("📚 got duties",
		fields.Count(len(duties)),
		fields.Epoch(epoch),
		fields.Duties(epoch, specDuties, truncate),
		fields.Took(time.Since(start)),
	)

	span.SetStatus(codes.Ok, "")
	return nil
}

func (h *ProposerHandler) toSpecDuty(duty *eth2apiv1.ProposerDuty, role spectypes.BeaconRole) *spectypes.ValidatorDuty {
	return &spectypes.ValidatorDuty{
		Type:           role,
		PubKey:         duty.PubKey,
		Slot:           duty.Slot,
		ValidatorIndex: duty.ValidatorIndex,
	}
}

func (h *ProposerHandler) shouldExecute(duty *eth2apiv1.ProposerDuty) bool {
	currentSlot := h.beaconConfig.EstimatedCurrentSlot()
	// execute task if slot already began and not pass 1 slot
	if currentSlot == duty.Slot {
		return true
	}
	if currentSlot+1 == duty.Slot {
		h.warnMisalignedSlotAndDuty(duty.String())
		return true
	}
	return false
}

func (h *ProposerHandler) shouldFetchNexEpoch(slot phase0.Slot) bool {
	slotsPerEpoch := h.beaconConfig.SlotsPerEpoch
	return uint64(slot)%slotsPerEpoch > slotsPerEpoch/2-2
}
