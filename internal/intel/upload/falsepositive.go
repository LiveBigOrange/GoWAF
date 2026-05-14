package upload

import (
	"gowaf/internal/intel/store"
)

type FalsePositiveHandler struct {
	store *store.Store
}

func NewFalsePositiveHandler(store *store.Store) *FalsePositiveHandler {
	return &FalsePositiveHandler{store: store}
}

func (h *FalsePositiveHandler) MarkFalsePositive(eventID int64, ruleID, intelRuleID, reason string) error {
	return h.store.AddFalsePositive(&store.FalsePositiveRecord{
		EventID:     eventID,
		RuleID:      ruleID,
		IntelRuleID: intelRuleID,
		Reason:      reason,
		Status:      "pending",
	})
}

func (h *FalsePositiveHandler) SubmitFalsePositive(id int64, result string) error {
	return h.store.UpdateFalsePositiveStatus(id, "submitted")
}
