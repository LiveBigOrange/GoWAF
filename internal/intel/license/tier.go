package license

var tierFeatures = map[string][]string{
	"free":       {},
	"community":  {"ip_blacklist", "threat_signatures"},
	"basic":      {"ip_blacklist", "threat_signatures", "ua_rules", "path_rules", "bot_ips"},
	"pro":        {"ip_blacklist", "threat_signatures", "ua_rules", "path_rules", "bot_ips", "geoip", "realtime_push"},
	"enterprise": {"ip_blacklist", "threat_signatures", "ua_rules", "path_rules", "bot_ips", "geoip", "realtime_push", "multi_instance", "custom_rule_upload"},
}

var tierSyncIntervals = map[string]int{
	"free":       7200,
	"community":  3600,
	"basic":      1800,
	"pro":        900,
	"enterprise": 300,
}

var tierAllowedDataTypes = map[string][]string{
	"free":       {},
	"community":  {"ip_blacklist", "threat_signatures"},
	"basic":      {"ip_blacklist", "threat_signatures", "ua_rules", "path_rules", "bot_ips"},
	"pro":        {"ip_blacklist", "threat_signatures", "ua_rules", "path_rules", "bot_ips", "geoip"},
	"enterprise": {"ip_blacklist", "threat_signatures", "ua_rules", "path_rules", "bot_ips", "geoip"},
}

func GetTierFeatures(tier string) []string {
	if f, ok := tierFeatures[tier]; ok {
		return f
	}
	return tierFeatures["free"]
}

func GetTierSyncInterval(tier string) int {
	if i, ok := tierSyncIntervals[tier]; ok {
		return i
	}
	return tierSyncIntervals["free"]
}

func GetTierAllowedDataTypes(tier string) []string {
	if d, ok := tierAllowedDataTypes[tier]; ok {
		return d
	}
	return tierAllowedDataTypes["free"]
}

func IsValidTier(tier string) bool {
	_, ok := tierFeatures[tier]
	return ok
}

func AllTiers() []string {
	return []string{"free", "community", "basic", "pro", "enterprise"}
}
