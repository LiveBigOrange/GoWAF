package backend

import (
	crand "crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"
)

type groupRouteEntry struct {
	lbPolicy        LBPolicy
	allAvailable    []*Backend
	tlsBackends     []*Backend
	nonTLSBackends  []*Backend
	openAttempts    uint64
	lastOpenAttempt time.Time
}

const (
	circuitClosedRetryInterval = 10 * time.Second
	circuitHalfOpenMaxAttempts = 1
)

type groupRouteCache struct {
	entries map[string]*groupRouteEntry
}

type BackendGroup struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	LbPolicy  string `json:"lb_policy"`
	Enabled   bool   `json:"enabled"`
	MemberCnt int    `json:"member_cnt"`
	CreatedAt int64  `json:"created_at"`
}

type GroupMember struct {
	BackendID   string `json:"backend_id"`
	Address     string `json:"address"`
	Name        string `json:"name"`
	Scheme      string `json:"scheme"`
	Weight      int    `json:"weight"`
	Healthy     bool   `json:"healthy"`
	Enabled     bool   `json:"enabled"`
	HealthCheck bool   `json:"health_check"`
}

type BackendGroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SelectionInfo struct {
	ClientIP string
	URLPath  string
	IsWS     bool
	IsTLS    bool
}

func (m *Manager) ensureGroupTables() error {
	_, err := m.db.Exec(`
		CREATE TABLE IF NOT EXISTS backend_groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			lb_policy TEXT DEFAULT 'round_robin',
			enabled INTEGER DEFAULT 1,
			created_at INTEGER
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS backend_group_members (
			group_id TEXT NOT NULL,
			backend_id TEXT NOT NULL,
			weight INTEGER DEFAULT 1,
			enabled INTEGER DEFAULT 1,
			PRIMARY KEY (group_id, backend_id)
		)
	`)
	return err
}

func (m *Manager) loadGroups() {
	rows, err := m.db.Query(`SELECT id, name, lb_policy, enabled, created_at FROM backend_groups ORDER BY created_at`)
	if err != nil {
		log.Printf("[Backend] 加载后端组失败: %v", err)
		return
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.groups = make(map[string]*BackendGroup)
	m.groupMembers = make(map[string][]*GroupMemberItem)

	for rows.Next() {
		var g BackendGroup
		var enabled int
		if err := rows.Scan(&g.ID, &g.Name, &g.LbPolicy, &enabled, &g.CreatedAt); err != nil {
			log.Printf("[Backend] 扫描后端组行失败: %v", err)
			continue
		}
		g.Enabled = enabled == 1
		m.groups[g.ID] = &g
	}

	memberRows, err := m.db.Query(`SELECT group_id, backend_id, weight, enabled FROM backend_group_members`)
	if err != nil {
		log.Printf("[Backend] 加载组成员失败: %v", err)
		return
	}
	defer memberRows.Close()

	for memberRows.Next() {
		var mi GroupMemberItem
		var enabled int
		if err := memberRows.Scan(&mi.GroupID, &mi.BackendID, &mi.Weight, &enabled); err != nil {
			log.Printf("[Backend] 扫描组成员行失败: %v", err)
			continue
		}
		mi.Enabled = enabled == 1
		m.groupMembers[mi.GroupID] = append(m.groupMembers[mi.GroupID], &mi)
	}

	for gid, g := range m.groups {
		g.MemberCnt = len(m.groupMembers[gid])
	}
}

type GroupMemberItem struct {
	GroupID   string
	BackendID string
	Weight    int
	Enabled   bool
}

func (m *Manager) GetGroups() []BackendGroup {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]BackendGroup, 0, len(m.groups))
	for _, g := range m.groups {
		gc := *g
		gc.MemberCnt = len(m.groupMembers[g.ID])
		result = append(result, gc)
	}
	return result
}

func (m *Manager) GetGroup(id string) (*BackendGroup, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.groups[id]
	if !ok {
		return nil, false
	}
	gc := *g
	gc.MemberCnt = len(m.groupMembers[id])
	return &gc, true
}

func (m *Manager) AddGroup(name, lbPolicy string) (*BackendGroup, error) {
	id := fmt.Sprintf("grp_%d%08x", time.Now().UnixMicro(), randomUint32())

	if !isValidLBPolicy(LBPolicy(lbPolicy)) {
		lbPolicy = string(LBRoundRobin)
	}

	now := time.Now().Unix()
	_, err := m.db.Exec(`INSERT INTO backend_groups (id, name, lb_policy, enabled, created_at) VALUES (?,?,?,1,?)`,
		id, name, lbPolicy, now)
	if err != nil {
		return nil, err
	}

	g := &BackendGroup{ID: id, Name: name, LbPolicy: lbPolicy, Enabled: true, CreatedAt: now}

	m.mu.Lock()
	m.groups[id] = g
	m.mu.Unlock()
	m.rebuildGroupCache()

	return g, nil
}

func (m *Manager) UpdateGroup(id, name, lbPolicy string) error {
	if !isValidLBPolicy(LBPolicy(lbPolicy)) {
		lbPolicy = string(LBRoundRobin)
	}

	var result sql.Result
	var err error
	if name != "" {
		result, err = m.db.Exec(`UPDATE backend_groups SET name=?, lb_policy=? WHERE id=?`, name, lbPolicy, id)
	} else {
		result, err = m.db.Exec(`UPDATE backend_groups SET lb_policy=? WHERE id=?`, lbPolicy, id)
	}
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group not found: %s", id)
	}

	m.mu.Lock()
	if g, ok := m.groups[id]; ok {
		if name != "" {
			g.Name = name
		}
		g.LbPolicy = lbPolicy
	}
	m.mu.Unlock()
	m.rebuildGroupCache()
	return nil
}

func (m *Manager) SetGroupEnabled(id string, enabled bool) error {
	var enabledInt int
	if enabled {
		enabledInt = 1
	}
	result, err := m.db.Exec(`UPDATE backend_groups SET enabled=? WHERE id=?`, enabledInt, id)
	if err != nil {
		return fmt.Errorf("更新组启用状态失败: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group not found: %s", id)
	}

	m.mu.Lock()
	if g, ok := m.groups[id]; ok {
		g.Enabled = enabled
	}
	m.mu.Unlock()
	m.rebuildGroupCache()
	return nil
}

func (m *Manager) DeleteGroup(id string) error {
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("启动事务失败: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM backend_group_members WHERE group_id=?`, id); err != nil {
		tx.Rollback()
		return fmt.Errorf("删除组成员失败: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM backend_groups WHERE id=?`, id); err != nil {
		tx.Rollback()
		return fmt.Errorf("删除后端组失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	m.mu.Lock()
	delete(m.groups, id)
	delete(m.groupMembers, id)
	m.mu.Unlock()
	m.rebuildGroupCache()
	return nil
}

func (m *Manager) GetGroupMembersFull(groupID string) []GroupMember {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []GroupMember
	for _, mi := range m.groupMembers[groupID] {
		var addr, name, scheme string
		var healthy, healthCheck bool
		found := false
		for _, b := range m.backends {
			if b.ID == mi.BackendID {
				addr = b.Address
				name = b.Name
				scheme = b.Scheme
				healthy = b.Healthy
				healthCheck = b.HealthCheck
				found = true
				break
			}
		}
		if !found {
			log.Printf("[Backend] 孤立组成员: groupID=%s, backendID=%s (后端已删除)", groupID, mi.BackendID)
			continue
		}
		w := mi.Weight
		if w <= 0 {
			w = 1
		}
		result = append(result, GroupMember{
			BackendID:   mi.BackendID,
			Address:     addr,
			Name:        name,
			Scheme:      scheme,
			Weight:      w,
			Healthy:     healthy,
			Enabled:     mi.Enabled,
			HealthCheck: healthCheck,
		})
	}
	return result
}

func (m *Manager) AddGroupMember(groupID, backendID string, weight int) error {
	if weight <= 0 {
		weight = 1
	}

	m.mu.RLock()
	_, groupOK := m.groups[groupID]
	backendExists := false
	for _, b := range m.backends {
		if b.ID == backendID {
			backendExists = true
			break
		}
	}
	m.mu.RUnlock()

	if !groupOK {
		return fmt.Errorf("后端组不存在: %s", groupID)
	}
	if !backendExists {
		return fmt.Errorf("后端不存在: %s", backendID)
	}

	_, err := m.db.Exec(`INSERT OR REPLACE INTO backend_group_members (group_id, backend_id, weight, enabled) VALUES (?,?,?,1)`,
		groupID, backendID, weight)
	if err != nil {
		return err
	}

	m.mu.Lock()
	found := false
	for _, mi := range m.groupMembers[groupID] {
		if mi.BackendID == backendID {
			mi.Weight = weight
			mi.Enabled = true
			found = true
			break
		}
	}
	if !found {
		m.groupMembers[groupID] = append(m.groupMembers[groupID], &GroupMemberItem{
			GroupID: groupID, BackendID: backendID, Weight: weight, Enabled: true,
		})
	}
	m.mu.Unlock()
	m.rebuildGroupCache()
	return nil
}

func (m *Manager) RemoveGroupMember(groupID, backendID string) error {
	_, err := m.db.Exec(`DELETE FROM backend_group_members WHERE group_id=? AND backend_id=?`, groupID, backendID)
	if err != nil {
		return err
	}

	m.mu.Lock()
	members := m.groupMembers[groupID]
	for i, mi := range members {
		if mi.BackendID == backendID {
			m.groupMembers[groupID] = append(members[:i], members[i+1:]...)
			break
		}
	}
	m.mu.Unlock()
	m.wrrMu.Lock()
	delete(m.wrrState, backendID)
	m.wrrMu.Unlock()
	m.rebuildGroupCache()
	return nil
}

func (m *Manager) GetGroupedBackendIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make(map[string]bool)
	for _, members := range m.groupMembers {
		for _, mi := range members {
			if mi.Enabled {
				ids[mi.BackendID] = true
			}
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	return result
}

func (m *Manager) GetBackendGroupsMap() map[string][]BackendGroupRef {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]BackendGroupRef)
	for gid, members := range m.groupMembers {
		g, ok := m.groups[gid]
		if !ok {
			continue
		}
		ref := BackendGroupRef{ID: g.ID, Name: g.Name}
		for _, mi := range members {
			result[mi.BackendID] = append(result[mi.BackendID], ref)
		}
	}
	return result
}

func (m *Manager) SelectBackendForGroup(groupID string, info SelectionInfo) *Backend {
	cache := m.groupCache.Load()
	if cache != nil {
		if entry, ok := cache.entries[groupID]; ok {
			if len(entry.allAvailable) == 0 {
				now := time.Now()
				if now.Sub(entry.lastOpenAttempt) < circuitClosedRetryInterval {
					return nil
				}
				return m.selectBackendForGroupSlow(groupID, info)
			}

			available := entry.nonTLSBackends
			if info.IsTLS {
				available = entry.tlsBackends
			}
			if len(available) == 0 {
				log.Printf("[Backend] 协议筛选无匹配后端(缓存): groupID=%s, IsTLS=%v, 回退到全量列表", groupID, info.IsTLS)
				available = entry.allAvailable
			}
			return m.selectBackendFromList(available, entry.lbPolicy, info)
		}
	}

	return m.selectBackendForGroupSlow(groupID, info)
}

func (m *Manager) selectBackendForGroupSlow(groupID string, info SelectionInfo) *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()

	g, ok := m.groups[groupID]
	if !ok || !g.Enabled {
		return nil
	}
	lbPolicy := g.LbPolicy

	var allAvailable []*Backend
	for _, mi := range m.groupMembers[groupID] {
		if !mi.Enabled {
			continue
		}
		for _, b := range m.backends {
			if b.ID == mi.BackendID && b.Enabled && b.Healthy {
				bc := *b
				if mi.Weight > 0 {
					bc.Weight = mi.Weight
				}
				allAvailable = append(allAvailable, &bc)
				break
			}
		}
	}
	if len(allAvailable) == 0 {
		return nil
	}

	var available []*Backend
	for _, b := range allAvailable {
		schemes := b.GetSchemes()
		if info.IsTLS {
			for _, s := range schemes {
				if s == "https" || s == "wss" {
					available = append(available, b)
					break
				}
			}
		} else {
			for _, s := range schemes {
				if s == "http" || s == "ws" {
					available = append(available, b)
					break
				}
			}
		}
	}

	if len(available) == 0 {
		log.Printf("[Backend] 协议筛选无匹配后端: groupID=%s, IsTLS=%v, 回退到全量列表(可能降级)", groupID, info.IsTLS)
		available = allAvailable
	}

	policy := LBPolicy(lbPolicy)
	if !isValidLBPolicy(policy) {
		policy = LBRoundRobin
	}

	return m.selectBackendFromList(available, policy, info)
}

func (m *Manager) rebuildGroupCache() {
	m.mu.RLock()
	m.doRebuildGroupCache()
	m.mu.RUnlock()
	m.groupCache.Store(m.rebuildGroupCacheResult)
}

func (m *Manager) doRebuildGroupCache() {
	oldCache := m.groupCache.Load()
	cache := &groupRouteCache{entries: make(map[string]*groupRouteEntry, len(m.groups))}

	for gid, g := range m.groups {
		if !g.Enabled {
			continue
		}
		entry := &groupRouteEntry{
			lbPolicy: LBPolicy(g.LbPolicy),
		}
		if !isValidLBPolicy(entry.lbPolicy) {
			entry.lbPolicy = LBRoundRobin
		}

		var oldEntry *groupRouteEntry
		if oldCache != nil {
			oldEntry = oldCache.entries[gid]
		}

		for _, mi := range m.groupMembers[gid] {
			if !mi.Enabled {
				continue
			}
			for _, b := range m.backends {
				if b.ID == mi.BackendID && b.Enabled && b.Healthy {
					bc := *b
					if mi.Weight > 0 {
						bc.Weight = mi.Weight
					}
					entry.allAvailable = append(entry.allAvailable, &bc)

					schemes := bc.GetSchemes()
					hasTLS := false
					hasNonTLS := false
					for _, s := range schemes {
						if s == "https" || s == "wss" {
							hasTLS = true
						}
						if s == "http" || s == "ws" {
							hasNonTLS = true
						}
					}
					if hasTLS {
						entry.tlsBackends = append(entry.tlsBackends, &bc)
					}
					if hasNonTLS {
						entry.nonTLSBackends = append(entry.nonTLSBackends, &bc)
					}
					break
				}
			}
		}

		if len(entry.allAvailable) == 0 && oldEntry != nil {
			entry.lastOpenAttempt = oldEntry.lastOpenAttempt
			entry.openAttempts = oldEntry.openAttempts + 1
		}

		if len(entry.allAvailable) > 0 && oldEntry != nil && len(oldEntry.allAvailable) == 0 {
			log.Printf("[Backend] 断路器恢复: groupID=%s, 可用后端=%d", gid, len(entry.allAvailable))
		}

		cache.entries[gid] = entry
	}

	m.rebuildGroupCacheResult = cache
}

func (m *Manager) rebuildGroupCacheLocked() {
	m.doRebuildGroupCache()
	m.groupCache.Store(m.rebuildGroupCacheResult)
}

func (m *Manager) selectBackendFromList(available []*Backend, policy LBPolicy, info SelectionInfo) *Backend {
	switch policy {
	case LBLeastConns:
		return m.selectLeastConns(available)
	case LBWeightedRR:
		return m.selectWeightedRR(available)
	case LBIPHash:
		return m.selectByIPHash(available, info.ClientIP)
	case LBURLHash:
		return m.selectByURLHash(available, info.URLPath)
	case LBRandom:
		return m.selectByRandom(available)
	default:
		idx := atomic.AddUint64(&m.roundIdx, 1) - 1
		return available[idx%uint64(len(available))]
	}
}

func (m *Manager) selectByIPHash(members []*Backend, clientIP string) *Backend {
	host, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		host = clientIP
	}
	idx := fnv1aHash32(host) % uint32(len(members))
	return members[idx]
}

func (m *Manager) selectByURLHash(members []*Backend, urlPath string) *Backend {
	idx := fnv1aHash32(urlPath) % uint32(len(members))
	return members[idx]
}

func (m *Manager) selectByRandom(members []*Backend) *Backend {
	totalWeight := 0
	for _, b := range members {
		if b.Weight > 0 {
			totalWeight += b.Weight
		} else {
			totalWeight++
		}
	}
	if totalWeight == 0 {
		return members[0]
	}

	r := rand.IntN(totalWeight)

	for _, b := range members {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		r -= w
		if r < 0 {
			return b
		}
	}
	return members[len(members)-1]
}

func fnv1aHash32(s string) uint32 {
	const prime = 16777619
	var hash uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime
	}
	return hash
}

func isValidLBPolicy(p LBPolicy) bool {
	switch p {
	case LBRoundRobin, LBWeightedRR, LBLeastConns, LBIPHash, LBURLHash, LBRandom:
		return true
	}
	return false
}

func randomUint32() uint32 {
	b := make([]byte, 4)
	if _, err := crand.Read(b); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint32(b)
}
