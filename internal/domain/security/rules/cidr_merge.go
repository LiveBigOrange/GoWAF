package rules

import (
	"encoding/binary"
	"net"
	"sort"
)

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func rangeToCIDRs(start, end uint32) []string {
	var result []string
	for start <= end {
		maxBits := uint32(0)
		for i := uint32(0); i < 32; i++ {
			size := uint32(1) << i
			if (start & (size - 1)) != 0 {
				break
			}
			if size-1 > end-start {
				break
			}
			maxBits = i
		}
		cidrSize := 32 - int(maxBits)
		ip := uint32ToIP(start)
		result = append(result, (&net.IPNet{IP: ip, Mask: net.CIDRMask(cidrSize, 32)}).String())
		next := start + (uint32(1) << maxBits)
		if next <= start {
			break
		}
		start = next
	}
	return result
}

type ipRange struct {
	start uint32
	end   uint32
}

func mergeIPsToCIDRs(ips []string) []string {
	if len(ips) <= 1 {
		return ips
	}

	var ranges []ipRange
	for _, ipStr := range ips {
		if _, cidr, err := net.ParseCIDR(ipStr); err == nil {
			ones, _ := cidr.Mask.Size()
			start := ipToUint32(cidr.IP)
			if ones == 32 {
				ranges = append(ranges, ipRange{start: start, end: start})
			} else {
				var size uint32
				if ones == 0 {
					size = 0
				} else {
					size = uint32(1) << (32 - uint(ones))
				}
				if size > 0 {
					ranges = append(ranges, ipRange{start: start, end: start + size - 1})
				}
			}
		} else if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
			n := ipToUint32(ip)
			ranges = append(ranges, ipRange{start: n, end: n})
		}
	}

	if len(ranges) <= 1 {
		return ips
	}

	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	merged := []ipRange{ranges[0]}
	for i := 1; i < len(ranges); i++ {
		last := &merged[len(merged)-1]
		if ranges[i].start <= last.end+1 {
			if ranges[i].end > last.end {
				last.end = ranges[i].end
			}
		} else {
			merged = append(merged, ranges[i])
		}
	}

	var result []string
	for _, r := range merged {
		if r.start == r.end {
			result = append(result, uint32ToIP(r.start).String())
		} else {
			cidrs := rangeToCIDRs(r.start, r.end)
			result = append(result, cidrs...)
		}
	}
	return result
}
