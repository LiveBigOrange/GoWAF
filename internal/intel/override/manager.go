package override

import (
	"gowaf/internal/intel/store"
)

type OverrideManager struct {
	store *store.Store
}

func NewOverrideManager(store *store.Store) *OverrideManager {
	return &OverrideManager{store: store}
}

func (m *OverrideManager) AddOverride(intelID, dataType, action, reason, createdBy string) error {
	return m.store.AddOverride(&store.RuleOverride{
		IntelID:   intelID,
		DataType:  dataType,
		Action:    action,
		Reason:    reason,
		CreatedBy: createdBy,
	})
}

func (m *OverrideManager) RemoveOverride(id int) error {
	return m.store.DeleteOverride(id)
}

func (m *OverrideManager) ListOverrides() ([]store.RuleOverride, error) {
	return m.store.GetOverrides()
}

func (m *OverrideManager) GetOverride(intelID, dataType string) (*store.RuleOverride, error) {
	return m.store.GetOverride(intelID, dataType)
}
