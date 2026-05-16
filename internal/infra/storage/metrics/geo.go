package metrics

import (
	"net"
	"time"

	"github.com/oschwald/geoip2-golang"
	"gowaf/internal/infra/logger"
)

// GetGeoInfo 获取IP地理信息
func (m *Manager) GetGeoInfo(ip string) *GeoIPInfo {
	geo := m.getGeoLocation(ip)
	if geo.CountryISO == "" && geo.Country == "局域网" {
		return nil
	}
	return &GeoIPInfo{
		CountryISO: geo.CountryISO,
		Country:    geo.Country,
	}
}

// GetGeoLocation 获取IP地理位置（公开方法，供外部调用）
func (m *Manager) GetGeoLocation(ip string) GeoLocation {
	return m.getGeoLocation(ip)
}

// getGeoLocation 获取IP地理位置（优先使用GeoIP2数据库，回退到简化版）
func (m *Manager) getGeoLocation(ip string) GeoLocation {
	if isPrivateIP(ip) {
		return GeoLocation{
			Country: "局域网",
			City:    "",
			Flag:    "🌐",
		}
	}

	m.geoCacheMu.RLock()
	if entry, ok := m.geoCache[ip]; ok && time.Now().Before(entry.expiresAt) {
		m.geoCacheMu.RUnlock()
		return entry.loc
	}
	m.geoCacheMu.RUnlock()

	var loc GeoLocation
	if m.geoipDB != nil {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			record, err := m.geoipDB.City(parsedIP)
			if err == nil && record.Country.IsoCode != "" {
				country := record.Country.Names["zh-CN"]
				if country == "" {
					country = record.Country.Names["en"]
				}
				city := record.City.Names["zh-CN"]
				if city == "" {
					city = record.City.Names["en"]
				}
				flag := countryToFlag(record.Country.IsoCode)
				loc = GeoLocation{
					Country:    country,
					CountryISO: record.Country.IsoCode,
					City:       city,
					Flag:       flag,
				}
			}
		}
	}

	if loc.Country == "" {
		loc = getGeoLocationSimple(ip)
	}

	m.geoCacheMu.Lock()
	if m.geoCache == nil {
		m.geoCache = make(map[string]*geoCacheEntry, geoCacheMaxSize)
	}
	if len(m.geoCache) >= geoCacheMaxSize {
		now := time.Now()
		for k, v := range m.geoCache {
			if now.After(v.expiresAt) || len(m.geoCache) > geoCacheMaxSize/2 {
				delete(m.geoCache, k)
			}
			if len(m.geoCache) <= geoCacheMaxSize/2 {
				break
			}
		}
	}
	m.geoCache[ip] = &geoCacheEntry{loc: loc, expiresAt: time.Now().Add(geoCacheTTL)}
	m.geoCacheMu.Unlock()

	return loc
}

// getGeoLocationSimple 简化版IP地理位置判断（基于IP段）
func getGeoLocationSimple(ip string) GeoLocation {
	if isPrivateIP(ip) {
		return GeoLocation{
			Country: "局域网",
			City:    "",
			Flag:    "🌐",
		}
	}

	parts := splitIP(ip)
	if len(parts) == 0 {
		return GeoLocation{Country: "未知", City: "", Flag: "❓"}
	}

	firstOctet := parts[0]

	if firstOctet >= 1 && firstOctet <= 126 {
		if firstOctet == 10 {
			return GeoLocation{Country: "局域网", City: "", Flag: "🌐"}
		}
		if firstOctet >= 1 && firstOctet <= 9 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 14 && firstOctet <= 15 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 16 && firstOctet <= 31 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 32 && firstOctet <= 61 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 58 && firstOctet <= 60 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 61 && firstOctet <= 62 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 80 && firstOctet <= 95 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
		if firstOctet >= 100 && firstOctet <= 126 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
	}

	if firstOctet >= 128 && firstOctet <= 191 {
		if firstOctet >= 128 && firstOctet <= 135 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 139 && firstOctet <= 143 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 144 && firstOctet <= 159 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
		if firstOctet >= 160 && firstOctet <= 171 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 172 && firstOctet <= 172 {
			if len(parts) > 1 && parts[1] >= 16 && parts[1] <= 31 {
				return GeoLocation{Country: "局域网", City: "", Flag: "🌐"}
			}
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 175 && firstOctet <= 191 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
	}

	if firstOctet >= 192 && firstOctet <= 223 {
		if firstOctet == 192 {
			if len(parts) > 1 && parts[1] == 168 {
				return GeoLocation{Country: "局域网", City: "", Flag: "🌐"}
			}
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 193 && firstOctet <= 195 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
		if firstOctet >= 200 && firstOctet <= 201 {
			return GeoLocation{Country: "美洲", City: "", Flag: "🌎"}
		}
		if firstOctet >= 202 && firstOctet <= 203 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 210 && firstOctet <= 223 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
	}

	return GeoLocation{Country: "未知", City: "", Flag: "❓"}
}

// isPrivateIP 判断是否为私有IP
func isPrivateIP(ip string) bool {
	parts := splitIP(ip)
	if len(parts) < 2 {
		return false
	}

	if parts[0] == 10 {
		return true
	}

	if parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31 {
		return true
	}

	if parts[0] == 192 && parts[1] == 168 {
		return true
	}

	if parts[0] == 127 {
		return true
	}

	return false
}

// splitIP 分割IP地址
func splitIP(ip string) []int {
	parts := make([]int, 0, 4)
	start := 0
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			if i > start {
				num := 0
				for j := start; j < i; j++ {
					if ip[j] >= '0' && ip[j] <= '9' {
						num = num*10 + int(ip[j]-'0')
					}
				}
				parts = append(parts, num)
			}
			start = i + 1
		}
	}
	return parts
}

// countryToFlag 根据ISO国家代码返回国旗emoji
func countryToFlag(code string) string {
	if len(code) != 2 {
		return "❓"
	}
	return string(rune(0x1F1E6+rune(code[0])-'A')) + string(rune(0x1F1E6+rune(code[1])-'A'))
}

// ReloadGeoIP 热重载GeoIP数据库
func (m *Manager) ReloadGeoIP(dbPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.geoipDB != nil {
		m.geoipDB.Close()
		m.geoipDB = nil
	}
	if dbPath == "" {
		return nil
	}
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return err
	}
	m.geoipDB = reader
	logger.Info("GeoIP2 数据库热重载成功: %s", dbPath)
	return nil
}
