package ebpf

import (
	"testing"
	"unsafe"
)

func TestSubnetStructSizes(t *testing.T) {
	if sz := unsafe.Sizeof(SubnetV4Key{}); sz != 8 {
		t.Errorf("SubnetV4Key size = %d; want 8", sz)
	}
	if sz := unsafe.Sizeof(SubnetV6Key{}); sz != 20 {
		t.Errorf("SubnetV6Key size = %d; want 20", sz)
	}
	if sz := unsafe.Sizeof(SubnetVal{}); sz != 24 {
		t.Errorf("SubnetVal size = %d; want 24", sz)
	}
}

func TestLSMStructSizes(t *testing.T) {
	if sz := unsafe.Sizeof(LSMRule{}); sz != 24 {
		t.Errorf("LSMRule size = %d; want 24", sz)
	}
	if sz := unsafe.Sizeof(LSMConfig{}); sz != 16 {
		t.Errorf("LSMConfig size = %d; want 16", sz)
	}
	if sz := unsafe.Sizeof(WafioLSMEvent{}); sz != 344 {
		t.Errorf("WafioLSMEvent size = %d; want 344", sz)
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		isV6      bool
		prefixLen uint32
		addrV4    [4]byte
		addrV6    [16]byte
		wantErr   bool
	}{
		{
			name:      "IPv4 /24 subnet",
			input:     "192.168.1.0/24",
			isV6:      false,
			prefixLen: 24,
			addrV4:    [4]byte{192, 168, 1, 0},
		},
		{
			name:      "IPv4 with host bits (should be masked to network)",
			input:     "192.168.1.155/24",
			isV6:      false,
			prefixLen: 24,
			addrV4:    [4]byte{192, 168, 1, 0},
		},
		{
			name:      "IPv4 /16 subnet",
			input:     "10.50.0.0/16",
			isV6:      false,
			prefixLen: 16,
			addrV4:    [4]byte{10, 50, 0, 0},
		},
		{
			name:      "IPv4 bare IP (defaults to /32)",
			input:     "1.2.3.4",
			isV6:      false,
			prefixLen: 32,
			addrV4:    [4]byte{1, 2, 3, 4},
		},
		{
			name:      "IPv6 /64 subnet",
			input:     "2001:db8:abcd:0012::/64",
			isV6:      true,
			prefixLen: 64,
			addrV6: [16]byte{
				0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x00, 0x12,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:      "IPv6 bare IP (defaults to /128)",
			input:     "::1",
			isV6:      true,
			prefixLen: 128,
			addrV6: [16]byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 1,
			},
		},
		{
			name:    "Invalid input",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "Invalid CIDR mask",
			input:   "10.0.0.1/40",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isV6, k4, k6, err := ParseCIDR(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if isV6 != tt.isV6 {
				t.Errorf("isV6 = %v; want %v", isV6, tt.isV6)
			}
			if !isV6 {
				if k4.PrefixLen != tt.prefixLen {
					t.Errorf("PrefixLen = %d; want %d", k4.PrefixLen, tt.prefixLen)
				}
				if k4.Addr != tt.addrV4 {
					t.Errorf("Addr = %v; want %v", k4.Addr, tt.addrV4)
				}
			} else {
				if k6.PrefixLen != tt.prefixLen {
					t.Errorf("PrefixLen = %d; want %d", k6.PrefixLen, tt.prefixLen)
				}
				if k6.Addr != tt.addrV6 {
					t.Errorf("Addr = %v; want %v", k6.Addr, tt.addrV6)
				}
			}
		})
	}
}
